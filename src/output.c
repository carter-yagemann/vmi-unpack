/*
 * Copyright (c) 2017 Carter Yagemann
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

//strcasestr() is a GNU extension
#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <limits.h> //PATH_MAX
#include <unistd.h> //sysconf(_SC_PAGESIZE)
#include <sys/stat.h> //mkdir()
#include <string.h> //strcasestr()

#include <libvmi/libvmi.h>
#include <json-glib/json-glib.h>

#include <monitor.h>
#include <dump.h>
#include <output.h>
#include <paging/intel_64.h>
#include <vmi/process.h>

/* defined in main.c */
extern char *domain_name;
extern char *vol_profile;
extern char *output_dir;

int dump_count = 0;

void process_layer(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, page_cat_t page_cat)
{
    size_t dump_size;

    mem_seg_t vma = vmi_current_find_segment(vmi, event, event->mem_event.gla);
    if (!vma.size)
    {
        fprintf(stderr, "WARNING: Unpack - Could not find memory segment for virtual address 0x%lx\n", event->mem_event.gla);
        return;
    }

    char *buffer = (char *) malloc(vma.size);
    if (!buffer)
    {
        fprintf(stderr, "ERROR: Unpack - Failed to malloc buffer to dump W2X event\n");
        return;
    }

    vmi_read_va(vmi, vma.base_va, pid, vma.size, buffer, &dump_size);
    printf("Dumping section: base_va: %p, size: %zu\n", (void *)(vma.base_va), vma.size);
    add_to_dump_queue(buffer, dump_size, pid, event->x86_regs->rip, vma.base_va);
    printf("Done queueing dump: base_va: %p, size: %zu\n", (void *)(vma.base_va), vma.size);
}

int capture_cmd(const char *cmd, const char *fn)
{
    FILE *pipe = NULL;
    FILE *out_f = NULL;
    char *out_buf = NULL;
    size_t out_size;
    const size_t PAGE_SIZE = sysconf(_SC_PAGESIZE);

    // fork&exec cmd
    // NOTE: popen does not capture stderr. cmd should have "2>&1" if you want stderr
    pipe = popen(cmd, "r");
    if (pipe == NULL)
    {
        fprintf(stderr, "%s: failed to run cmd {%s}\n", __func__, cmd);
        return -1;
    }

    if (fn)
    {
        // capture cmd output and write to fn
        out_f = fopen(fn, "w");
        if (!out_f)
        {
            fprintf(stderr, "%s: error: failed to open {%s} for writing\n", __func__, fn);
            pclose(pipe);
            return -1;
        }
        out_buf = malloc(PAGE_SIZE);
        if (!out_buf)
        {
            fprintf(stderr, "%s: error: failed to allocate buffer\n", __func__);
            fclose(out_f);
            pclose(pipe);
            return -1;
        }

        while (1)
        {
            out_size = fread(out_buf, 1, PAGE_SIZE, pipe);
            if (!out_size)
                break;
            if (fwrite(out_buf, 1, out_size, out_f) != out_size)
                fprintf(stderr, "%s: warning: short write to {%s}\n", __func__, fn);
        }

        free(out_buf);
        fclose(out_f);
    }
    else
    {
        char ch;
        while( (ch=fgetc(pipe)) != EOF) {} //discard all output from pipe
    }
    pclose(pipe);
    return 0;
}

static inline JsonParser* read_json_file(const char* fn)
{
    JsonParser *parser = NULL;
    GError *error = NULL;

    parser = json_parser_new();
    if (!json_parser_load_from_file(parser, fn, &error))
    {
        fprintf(stderr, "%s: error: cannot parse vadinfo json file {%s} %s\n",
            __func__, fn, error->message);
        g_error_free(error);
        g_object_unref(parser);
        return NULL;
    }
    return parser;
}

static inline gchar* json_node_to_data(JsonNode *node, gsize *len)
{
    gchar *data = NULL;
    JsonGenerator *gen = json_generator_new();
    json_generator_set_root(gen, node);
    data = json_generator_to_data(gen, len);
    g_object_unref(gen);
    return data;
}

/*
 * return -1 if fopen() fails
 * return -2 if fwrite fails and ferror() is true
 * return the negative of (written + 10) to indicate a short write
 *   the value returned is padded by 10 to allow for other error codes to be returned
 * return written if fwrite() succeeds and written == len
 */
static inline int write_file(const char *fn, const char *data, const size_t len)
{
    size_t written;
    int rc = -9;
    FILE *out_f = fopen(fn, "w");

    if (!out_f)
    {
      perror(__func__);
      rc = -1;
      goto out;
    }

    written = fwrite(data, 1, len, out_f);
    if (written != len)
    {
        if (!ferror(out_f))
        {
            fprintf(stderr, "%s: warning: short write to {%s}\n", __func__, fn);
            rc = -(written + 10);
            goto _close;
        }
        fprintf(stderr, "%s: %s\n", __func__, strerror(errno));
        clearerr(out_f);
        rc = -2;
        goto _close;
    }
    rc = written;

_close:
    fclose(out_f);
out:
    return rc;
}

//#define DEBUG_ADD_RIP_TO_JSON 1

char* make_vadinfo_json_fn(vmi_pid_t pid, int count)
{
    char *filepath = malloc(PATH_MAX);
    snprintf(filepath, PATH_MAX - 1, "%s/vadinfo.%04d.%ld.json", output_dir, count, (long)pid);
    return filepath;
}

int add_rip_to_json(vmi_pid_t pid, int count, reg_t rip)
{
    char rip_buf[32] = {0};
    // "0x1122334455667788"
    char *filepath = NULL;
    JsonParser *parser = NULL;
    JsonNode *root = NULL;
    gchar *data = NULL;
    gsize len;
    int rc = 0;
#ifdef DEBUG_ADD_RIP_TO_JSON
    gchar *str_val = NULL;
    JsonObject *obj = NULL;
#endif

    filepath = make_vadinfo_json_fn(pid, count);
 
    parser = read_json_file(filepath);
    if (!parser)
    {
        rc = -1;
        goto out;
    }

    root = json_parser_get_root(parser);
    snprintf(rip_buf, sizeof(rip_buf), "%p", (void*)rip);
    json_object_set_string_member(json_node_get_object(root), "rip", rip_buf);

    data = json_node_to_data(root, &len);
    g_object_unref(parser);

    rc = write_file(filepath, data, len);
    if (rc < 0)
        goto out;

#ifdef DEBUG_ADD_RIP_TO_JSON
    // read the new json and test to see if we set the RIP key/val correctly
    parser = read_json_file(filepath);
    root = json_parser_get_root(parser);
    obj = json_node_get_object(root);
    if (!json_object_has_member(obj, "rip"))
    {
        fprintf(stderr, "%s: error: new vadinfo json file does not have member 'rip'\n", __func__);
        rc = -2;
        g_object_unref(parser);
        goto out;
    }
    str_val = (gchar*)json_object_get_string_member(obj, "rip");
    if (!str_val || strcmp(str_val, rip_buf) != 0)
    {
        fprintf(stderr, "%s: error: new vadinfo json file: expected '%s', got '%s'\n",
            __func__, rip_buf, str_val);
        rc = -3;
        g_object_unref(parser);
        goto out;
    }
#endif

out:
    free(filepath);
    if (data) g_free(data);
    return rc;
}

void volatility_callback_vaddump(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, page_cat_t page_cat)
{
    char *cmd_prefix = "";

    volatility_vaddump(pid, cmd_prefix, dump_count);
    volatility_vadinfo(pid, cmd_prefix, dump_count);
    add_rip_to_json(pid, dump_count, event->x86_regs->rip);

    dump_count++;
}

int volatility_vaddump(vmi_pid_t pid, const char *cmd_prefix, int dump_count)
{
    //  volatility -l vmi://win7-borg --profile=Win7SP0x64 vaddump -D ~/borg-out/ -p 2448

    // vmi_pid_t is int32_t which can be int or long
    // so, for pid, we use %ld and cast to long
    const char *vaddump_cmd = "%svolatility -l vmi://%s --profile=%s vaddump -D %s 2>&1 -p %ld";
    const size_t PAGE_SIZE = sysconf(_SC_PAGESIZE);
    char *cmd = NULL;
    const size_t cmd_max = PAGE_SIZE;
    char *filepath = NULL;

    cmd = malloc(cmd_max);
    filepath = malloc(PATH_MAX);

    // vaddump
    snprintf(filepath, PATH_MAX - 1, "%s/%04d", output_dir, dump_count);
    mkdir(filepath, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH); // mode = 775
    snprintf(cmd, cmd_max - 1, vaddump_cmd, cmd_prefix, domain_name, vol_profile, filepath, (long)pid);
    snprintf(filepath, PATH_MAX - 1, "%s/vaddump_output.%04d.%ld", output_dir, dump_count, (long)pid);
    queue_and_wait_for_shell_cmd(cmd, filepath);

    free(cmd);
    free(filepath);

    return 0;
}

int volatility_vadinfo(vmi_pid_t pid, const char *cmd_prefix, int dump_count)
{
    //  volatility -l vmi://win7-borg --profile=Win7SP0x64 vadinfo --output=json -p 2448 --output-file=calc_upx.exe.vadinfo.json

    // vmi_pid_t is int32_t which can be int or long
    // so, for pid, we use %ld and cast to long
    const char *vadinfo_cmd = "%svolatility -l vmi://%s --profile=%s  vadinfo --output=json --output-file=%s 2>&1 -p %ld";
    const size_t PAGE_SIZE = sysconf(_SC_PAGESIZE);
    char *cmd = NULL;
    const size_t cmd_max = PAGE_SIZE;
    char *filepath = NULL;

    cmd = malloc(cmd_max);
    filepath = malloc(PATH_MAX);

    // vadinfo
    snprintf(filepath, PATH_MAX - 1, "%s/vadinfo.%04d.%ld.json", output_dir, dump_count, (long)pid);
    snprintf(cmd, cmd_max - 1, vadinfo_cmd, cmd_prefix, domain_name, vol_profile, filepath, (long)pid);
    snprintf(filepath, PATH_MAX - 1, "%s/vadinfo_output.%04d.%ld", output_dir, dump_count, (long)pid);
    queue_and_wait_for_shell_cmd(cmd, filepath);

    free(cmd);
    free(filepath);

    return 0;
}

gboolean find_process_in_vad(gconstpointer vad, gconstpointer name)
{
  JsonNode *fnwd_node = g_hash_table_lookup((gpointer)vad, "FileNameWithDevice");
  const char *fnwd_str = json_node_get_string(fnwd_node);
  if (!strlen(fnwd_str))
    return false;
  if (strcasestr(fnwd_str, name))
    return true; //found
  return false;
}

void free_pe(parsed_pe_t *pe)
{
  if (pe->proc_first_page)
  {
    free(pe->proc_first_page);
  }
  if (pe->section_table)
  {
    free(pe->section_table);
  }
  g_slice_free(parsed_pe_t, pe);
}

void free_bundle(gpointer data)
{
  vadinfo_bundle_t *bundle = (vadinfo_bundle_t*)data;
  if (bundle->parsed_pe)
    free_pe(bundle->parsed_pe);
  g_ptr_array_unref(bundle->vadinfo_maps);
  g_slice_free(vadinfo_bundle_t, bundle);
}

GPtrArray* map_process_vads(vmi_pid_t pid, int count)
{
  GPtrArray *column_names;
  GPtrArray *maps = NULL;
  GHashTable *map;
  char *filepath = NULL;
  JsonParser *parser = NULL;
  JsonNode *root = NULL, *node;
  JsonObject *root_obj;
  JsonArray *columns_arr, *rows_arr, *row_arr;
  guint len;
  int i, j;

  filepath = make_vadinfo_json_fn(pid, count);
  parser = read_json_file(filepath);
  if (!parser)
  {
      goto out;
  }

  root = json_parser_get_root(parser);
  root_obj = json_node_get_object(root);
  columns_arr = json_object_get_array_member(root_obj, "columns");
  rows_arr = json_object_get_array_member(root_obj, "rows");

  column_names = g_ptr_array_new();
  len = json_array_get_length(columns_arr);
  for (i = 0; i < len; i++)
  {
    node = json_array_get_element(columns_arr, i);
    const char *val_str = json_node_get_string(node);
    g_ptr_array_add(column_names, (char*)val_str);
  }

  maps = g_ptr_array_new_with_free_func((GDestroyNotify)g_hash_table_unref);
  len = json_array_get_length(rows_arr);
  for (i = 0; i < len; i++)
  {
    row_arr = json_array_get_array_element(rows_arr, i);
    map = g_hash_table_new_full(g_str_hash, g_str_equal, free, (GDestroyNotify)json_node_unref);
    g_ptr_array_add(maps, map);
    for (j = 0; j < column_names->len; j++)
    {
      char *new_str, *tmp_str;
      node = json_array_dup_element(row_arr, j);
      tmp_str = g_ptr_array_index(column_names, j);
      new_str = malloc(strlen(tmp_str)+1);
      strcpy(new_str, tmp_str);
      g_hash_table_insert(map, new_str, node);
    }
  }

out:
  g_ptr_array_unref(column_names);
  g_object_unref(parser);
  free(filepath);
  return maps;
}

gboolean find_process_in_vads(vmi_instance_t vmi, pid_events_t *pid_evts, int count)
{
  guint process_idx;
  gboolean found = false;
  GPtrArray *maps = NULL;
  vadinfo_bundle_t *vad_bundle;

  if (count < 0) goto out;

  if (!pid_evts->vadinfo_bundles)
  {
    pid_evts->vadinfo_bundles = g_ptr_array_new_with_free_func(free_bundle);
  }

  if (count < pid_evts->vadinfo_bundles->len)
  {
    vad_bundle = g_ptr_array_index(pid_evts->vadinfo_bundles, count);
    if (!vad_bundle->vadinfo_maps)
    {
      maps = map_process_vads(pid_evts->pid, count);
      vad_bundle->vadinfo_maps = maps;
    }
    else
      maps = vad_bundle->vadinfo_maps;
  }
  else if (count != (pid_evts->vadinfo_bundles->len))
    goto out;
  else {
    maps = map_process_vads(pid_evts->pid, count);
    vad_bundle = g_slice_new(vadinfo_bundle_t);
    vad_bundle->sequence = count;
    vad_bundle->vadinfo_maps = maps;
    g_ptr_array_add(pid_evts->vadinfo_bundles, vad_bundle);
    vad_bundle->pe_index = -1;
    vad_bundle->parsed_pe = NULL;
  }

  if (!pid_evts->process_name) goto out;
  found = g_ptr_array_find_with_equal_func(maps, pid_evts->process_name, find_process_in_vad, &process_idx);
  if (found)
  {
    addr_t start;
    addr_t end;
    size_t size;
    size_t actual_size;
    bounded_buffer_t orig_exe;
    GHashTable *pe_map;

    vad_bundle->pe_index = process_idx;
    pe_map = g_ptr_array_index(maps, process_idx);
    start = (addr_t)json_node_get_int(g_hash_table_lookup(pe_map, "Start"));
    end = (addr_t)json_node_get_int(g_hash_table_lookup(pe_map, "End"));
    size = end - start;
    orig_exe = malloc_bounded_buffer(size);
    //buf is the first member of bounded_buffer. so, cheat, and just use the pointer as-is.
    vmi_read_va(vmi, start, pid_evts->pid, size, orig_exe /*orig_exe->buf*/, &actual_size);
    //TODO check actual_size
    vad_bundle->parsed_pe = parse_pe_buffer(orig_exe);
  }
out:
  return found;
}
