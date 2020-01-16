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
#include <libvmi/peparse.h>
#include <json-glib/json-glib.h>

#include <monitor.h>
#include <dump.h>
#include <output.h>
#include <paging/intel_64.h>
#include <vmi/process.h>

/* defined in main.c */
extern char *domain_name;
extern char *vol_bin;
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
    addr_t oep;
    addr_t base_va;
    pid_events_t *pid_event = g_hash_table_lookup(vmi_events_by_pid, GINT_TO_POINTER(pid));

    volatility_vaddump(pid, vol_bin, dump_count);
    volatility_vadinfo(pid, vol_bin, dump_count);
    volatility_ldrmodules(pid, vol_bin, dump_count);

    base_va = pid_event->peb_imagebase_va ? pid_event->peb_imagebase_va : pid_event->vad_pe_start;
    volatility_impscan(vmi, pid_event, base_va, vol_bin, dump_count);

    oep = event->x86_regs->rip - base_va;
    fprintf(stderr, "%s: rip=%p base_va=%p oep=%p\n", __func__,
        (void*)event->x86_regs->rip, (void*)base_va, (void*)oep);
    add_rip_to_json(pid, dump_count, oep);

    dump_count++;
}

int volatility_vaddump(vmi_pid_t pid, const char *cmd_prefix, int dump_count)
{
    //  volatility -l vmi://win7-borg --profile=Win7SP0x64 vaddump -D ~/borg-out/ -p 2448

    // vmi_pid_t is int32_t which can be int or long
    // so, for pid, we use %ld and cast to long
    const char *vaddump_cmd = "%s -l vmi://%s --profile=%s vaddump -D %s 2>&1 -p %ld";
    const size_t PAGE_SIZE = sysconf(_SC_PAGESIZE);
    char *cmd = NULL;
    const size_t cmd_max = PAGE_SIZE;
    char *filepath = NULL;
    char *stdout_path = "/dev/null";

    cmd = malloc(cmd_max);
    filepath = malloc(PATH_MAX);

    // vaddump
    snprintf(filepath, PATH_MAX - 1, "%s/%04d", output_dir, dump_count);
    mkdir(filepath, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH); // mode = 775
    snprintf(cmd, cmd_max - 1, vaddump_cmd, cmd_prefix, domain_name, vol_profile, filepath, (long)pid);
    queue_and_wait_for_shell_cmd(cmd, stdout_path);

    free(cmd);
    free(filepath);

    return 0;
}

int volatility_vadinfo(vmi_pid_t pid, const char *cmd_prefix, int dump_count)
{
    //  volatility -l vmi://win7-borg --profile=Win7SP0x64 vadinfo --output=json -p 2448 --output-file=calc_upx.exe.vadinfo.json

    // vmi_pid_t is int32_t which can be int or long
    // so, for pid, we use %ld and cast to long
    const char *vadinfo_cmd = "%s -l vmi://%s --profile=%s  vadinfo --output=json --output-file=%s 2>&1 -p %ld";
    const size_t PAGE_SIZE = sysconf(_SC_PAGESIZE);
    char *cmd = NULL;
    const size_t cmd_max = PAGE_SIZE;
    char *filepath = NULL;
    char *stdout_path = "/dev/null";

    cmd = malloc(cmd_max);
    filepath = malloc(PATH_MAX);

    // vadinfo
    snprintf(filepath, PATH_MAX - 1, "%s/vadinfo.%04d.%ld.json", output_dir, dump_count, (long)pid);
    snprintf(cmd, cmd_max - 1, vadinfo_cmd, cmd_prefix, domain_name, vol_profile, filepath, (long)pid);
    fprintf(stderr, "%s: cmd=%s\n", __func__, cmd);
    queue_and_wait_for_shell_cmd(cmd, stdout_path);

    free(cmd);
    free(filepath);

    return 0;
}

int volatility_ldrmodules(vmi_pid_t pid, const char *cmd_prefix, int dump_count)
{
    //  volatility -l vmi://win7-borg --profile=Win7SP0x64 ldrmodules --output=json -p 2448 --output-file=calc_upx.exe.ldrmodules.json

    // vmi_pid_t is int32_t which can be int or long
    // so, for pid, we use %ld and cast to long
    const char *ldrmodules_cmd = "%s -l vmi://%s --profile=%s"
        " ldrmodules --output=json --output-file=%s 2>&1 -p %ld";
    const size_t PAGE_SIZE = sysconf(_SC_PAGESIZE);
    char *cmd = NULL;
    const size_t cmd_max = PAGE_SIZE;
    char *filepath = NULL;
    char *stdout_path = "/dev/null";

    cmd = malloc(cmd_max);
    filepath = malloc(PATH_MAX);

    // vadinfo
    snprintf(filepath, PATH_MAX - 1, "%s/ldrmodules.%04d.%ld.json", output_dir, dump_count, (long)pid);
    snprintf(cmd, cmd_max - 1, ldrmodules_cmd, cmd_prefix, domain_name, vol_profile, filepath, (long)pid);
    fprintf(stderr, "%s: cmd=%s\n", __func__, cmd);
    queue_and_wait_for_shell_cmd(cmd, stdout_path);

    free(cmd);
    free(filepath);

    return 0;
}

int volatility_impscan(vmi_instance_t vmi, pid_events_t *pid_event, addr_t base_va, const char *cmd_prefix, int count)
{
    /*
     *  volatility -l vmi://win7-borg --profile=Win7SP0x64 \
     *  impscan --base 0x407000 --size 8192 \
     *  -p 2448 --output=json --output-file=calc_upx.exe.impscan.section0000.json

     *    # The base address in kernel or process memory where
     *    # we begin scanning. This is an executable region with
     *    # assembly instructions like a .text or .code PE section.
     *    config.add_option('BASE', short_option = 'b', default = None,
     *                      help = 'Base address in process memory if --pid ' +
     *                      'is supplied, otherwise an address in kernel space',
     *                      action = 'store', type = 'int')
     *    # The size in bytes of data to scan from the base address.
     *    config.add_option('SIZE', short_option = 's', default = None,
     *                      help = 'Size of memory to scan',
     *                      action = 'store', type = 'int')
     */

    // vmi_pid_t is int32_t which can be int or long
    // so, for pid, we use %ld and cast to long
    const char *impscan_cmd = "%s -l vmi://%s --profile=%s"
      " impscan --base 0x%lx --size %zu"
      " --output=json --output-file=%s 2>&1 --pid %ld";

    const size_t PAGE_SIZE = sysconf(_SC_PAGESIZE);
    char *cmd = NULL;
    const size_t cmd_max = PAGE_SIZE;
    char *filepath = NULL;
    char *devnull_path = "/dev/null";
    vadinfo_bundle_t *vad_bundle;
    parsed_pe_t *pe;
    struct section_header *section_table;
    size_t num_sections;
    int s;

    cmd = malloc(cmd_max);
    filepath = malloc(PATH_MAX);

    fprintf(stderr, "%s: base_va=%p, pid=%ld, count=%d\n",
        __func__, (void*)base_va, (long)pid_event->pid, count);
    //re-parse pe, call find_process_in_vads()
    find_process_in_vads(vmi, pid_event, count);
    vad_bundle = g_ptr_array_index(pid_event->vadinfo_bundles, count);
    pe = vad_bundle->parsed_pe;
    show_parsed_pe(pe, stderr);
    section_table = pe->section_table;
    num_sections = pe->pe_header->number_of_sections;
    fprintf(stderr, "%s: num_sections=%zu\n", __func__, num_sections);
    //for each section with exec
    //  call impscan(eprocess, imagebase + section_rva, size)
    for (s=0; s < num_sections; s++) {
      fprintf(stderr, "%s: section=%d\n", __func__, s);
      if (section_table[s].characteristics & IMAGE_SCN_MEM_EXECUTE) {
        addr_t section_rva = section_table[s].virtual_address;
        size_t section_size = section_table[s].a.virtual_size;
        if (section_size == 0) {
          addr_t next_sec_rva;
          if (s == num_sections - 1)
            next_sec_rva = pid_event->vad_pe_size;
          else
            next_sec_rva = section_table[s+1].virtual_address;
          section_size = next_sec_rva - section_rva;
        }
        snprintf(filepath, PATH_MAX - 1, "%s/impscan.section%04d.%04d.%ld.json",
            output_dir, s, count, (long)pid_event->pid);
        snprintf(cmd, cmd_max - 1, impscan_cmd,
          cmd_prefix, domain_name, vol_profile,
          base_va + section_rva, section_size,
          filepath, (long)pid_event->pid);
        fprintf(stderr, "%s: cmd=%s\n", __func__, cmd);
        queue_and_wait_for_shell_cmd(cmd, devnull_path);
      }
      else
        fprintf(stderr, "%s: section=%d is not EXECUTE\n", __func__, s);
    }

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
  GPtrArray *column_names = NULL;
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
  if (column_names) g_ptr_array_unref(column_names);
  if (parser) g_object_unref(parser);
  free(filepath);
  return maps;
}

void show_parsed_pe(parsed_pe_t *pe, FILE* out_fd)
{
    uint32_t c;
    addr_t pe_imagebase;

    if (!out_fd)
      out_fd = stderr;

    fprintf(out_fd, "\tSignature: %u.\n", pe->pe_header->signature);
    fprintf(out_fd, "\tMachine: %u.\n", pe->pe_header->machine);
    fprintf(out_fd, "\t# of sections: %u.\n", pe->pe_header->number_of_sections);
    fprintf(out_fd, "\t# of symbols: %u.\n", pe->pe_header->number_of_symbols);
    fprintf(out_fd, "\tTimestamp: %u.\n", pe->pe_header->time_date_stamp);
    fprintf(out_fd, "\tCharacteristics: %u.\n", pe->pe_header->characteristics);
    fprintf(out_fd, "\tOptional header size: %u.\n", pe->pe_header->size_of_optional_header);
    fprintf(out_fd, "\tOptional header type: 0x%x\n", pe->oh_magic);

    if (pe->oh_magic == IMAGE_PE32_MAGIC) {
        pe_imagebase = ((struct optional_header_pe32 *)pe->opt_header)->image_base;
    } else {
        pe_imagebase = ((struct optional_header_pe32plus *)pe->opt_header)->image_base;
    }
    fprintf(out_fd, "\tPE ImageBase: %p\n", (void*)pe_imagebase);

    for (c=0; c < pe->pe_header->number_of_sections; c++) {
        // The character array is not null terminated, so only print the first 8 characters!
        fprintf(out_fd, "\tSection %u: %.8s flags=0x%x\n",
            c+1, pe->section_table[c].short_name, pe->section_table[c].characteristics);
    }
}

gboolean parse_pe(vmi_instance_t vmi, pid_events_t *pid_event, parsed_pe_t *pe)
{
  status_t status;
  addr_t imagebase;
  addr_t section_addr;
  size_t sec_tbl_sz;
  access_context_t ctx = {
    .translate_mechanism = VMI_TM_PROCESS_DTB,
    .dtb = pid_event->cr3,
  };
  if (pid_event->peb_imagebase_va)
    imagebase = pid_event->peb_imagebase_va;
  else
    imagebase = pid_event->vad_pe_start;
  ctx.addr = imagebase;

  pe->proc_first_page = malloc(MAX_PE_HEADER_SIZE);
  status = peparse_get_image(vmi, &ctx, MAX_PE_HEADER_SIZE, pe->proc_first_page);
  if (status != VMI_SUCCESS)
  {
    fprintf(stderr, "%s: error: cannot read PE header from imagebase=%p\n",
        __func__, (void*)imagebase);
    free(pe->proc_first_page);
    pe->proc_first_page = NULL;
    return false;
  }

  peparse_assign_headers(pe->proc_first_page, &pe->dos_header, &pe->pe_header,
      &pe->oh_magic, &pe->opt_header, NULL, NULL);

  section_addr = imagebase
    + pe->dos_header->offset_to_pe
    + sizeof(struct pe_header)
    + pe->pe_header->size_of_optional_header;
  sec_tbl_sz = pe->pe_header->number_of_sections * sizeof(struct section_header);
  pe->section_table = malloc(sec_tbl_sz);
  ctx.addr = section_addr;
  status = vmi_read(vmi, &ctx, sec_tbl_sz, pe->section_table, NULL);
  if (status != VMI_SUCCESS)
  {
    fprintf(stderr, "%s: error: cannot read PE section table from imagebase=%p\n",
        __func__, (void*)pid_event->peb_imagebase_va);
    free(pe->proc_first_page);
    pe->proc_first_page = NULL;
    free(pe->section_table);
    pe->section_table = NULL;
    return false;
  }

  return true;
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
    GHashTable *pe_map;
    parsed_pe_t *pe;

    vad_bundle->pe_index = count;
    pe_map = g_ptr_array_index(maps, process_idx);
    start = (addr_t)json_node_get_int(g_hash_table_lookup(pe_map, "Start"));
    pid_evts->vad_pe_start = start;
    end = (addr_t)json_node_get_int(g_hash_table_lookup(pe_map, "End"));
    size = end - start;
    pid_evts->vad_pe_size = size;
    fprintf(stderr, "%s: imagebase=%p pe_index=%d vad_pe_index=%d\n",
      __func__, (void*)pid_evts->vad_pe_start, vad_bundle->pe_index, pid_evts->vad_pe_index);

    pe = g_slice_new(parsed_pe_t);
    pe->proc_first_page = NULL;
    pe->section_table = NULL;
    if (parse_pe(vmi, pid_evts, pe)) {
      vad_bundle->parsed_pe = pe;
      //update vad_pe_index to the latest scan
      pid_evts->vad_pe_index = process_idx;
    }
    else
      g_slice_free(parsed_pe_t, pe);
  }
out:
  return found;
}
