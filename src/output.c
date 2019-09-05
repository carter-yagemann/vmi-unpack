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

#include <stdlib.h>
#include <stdio.h>
#include <limits.h> //PATH_MAX
#include <unistd.h> //sysconf(_SC_PAGESIZE)
#include <sys/stat.h> //mkdir()

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

uint64_t extract_field_value(uint64_t packed, uint64_t start, uint64_t end)
{
    packed >>= start;
    gint64 mask = (1ULL << (end - start + 1)) - 1;
    packed &= mask;
    return packed;
}

void get_node_vadtype(vmi_instance_t vmi, addr_t node, vadtype_t *vadtype)
{
    uint64_t flags = 0;
    uint64_t start = process_vmi_windows_rekall.flags_vadtype_start;
    uint64_t end = process_vmi_windows_rekall.flags_vadtype_end;
    vmi_read_64_va(vmi,
                   node + process_vmi_windows_rekall.mmvad_flags,
                   0, &flags);
    *vadtype = (vadtype_t)extract_field_value(flags, start, end);
}

void get_node_isprivate(vmi_instance_t vmi, addr_t node, uint8_t *isprivate)
{
    uint64_t flags = 0;
    uint64_t start = process_vmi_windows_rekall.flags_isprivate_start;
    uint64_t end = process_vmi_windows_rekall.flags_isprivate_end;
    vmi_read_64_va(vmi,
                   node + process_vmi_windows_rekall.mmvad_flags,
                   0, &flags);
    *isprivate = (uint8_t)extract_field_value(flags, start, end);
}

void get_node_protection(vmi_instance_t vmi, addr_t node, uint8_t *protection)
{
    uint64_t flags = 0;
    uint64_t start = process_vmi_windows_rekall.flags_protection_start;
    uint64_t end = process_vmi_windows_rekall.flags_protection_end;
    vmi_read_64_va(vmi,
                   node + process_vmi_windows_rekall.mmvad_flags,
                   0, &flags);
    *protection = (uint8_t)extract_field_value(flags, start, end);
}

// you must free the returned string:
//   free(fn_utf8.contents);
void get_node_filename(vmi_instance_t vmi, addr_t node, unicode_string_t *fn_utf8)
{
    unicode_string_t *fn_ustr = NULL;
    addr_t control_area = 0, file_object = 0, filename_ptr = 0;
    vmi_read_addr_va(vmi,
                     node + process_vmi_windows_rekall.mmvad_controlarea,
                     0, &control_area);
    if (control_area == 0) return;
    vmi_read_addr_va(vmi,
                     control_area + process_vmi_windows_rekall.controlarea_fileobject,
                     0, &file_object);
    if (file_object == 0) return;
    file_object &= 0xFFFFFFFFFFFFFFF8; //because its an EX_FAST_REF
    vmi_read_addr_va(vmi,
                     file_object + process_vmi_windows_rekall.fileobject_filename,
                     0, &filename_ptr);
    if (filename_ptr == 0) return;
    fn_ustr = vmi_read_unicode_str_va(vmi, filename_ptr, 0 /* pid=0 for kernel struct */);
    if (fn_ustr == NULL) return;
    vmi_convert_str_encoding(fn_ustr, fn_utf8, "UTF-8");
    vmi_free_unicode_str(fn_ustr);
}

void handle_node(vmi_instance_t vmi, addr_t node, void *data)
{
    dump_layer_t *dump = (dump_layer_t *)data;
    if (dump->segment_count >= SEG_COUNT_MAX)
    {
        fprintf(stderr, "handle_node: skipping VAD, SEG_COUNT_MAX reached.\n");
        return;
    }
    addr_t start = 0, end = 0, base_va = 0, size = 0;
    if (vmi_read_addr_va(
            vmi,
            node + process_vmi_windows_rekall.mmvad_startingvpn,
            0,
            &start) != VMI_SUCCESS)
        return;
    start <<= 12;
    if (vmi_read_addr_va(
            vmi,
            node + process_vmi_windows_rekall.mmvad_endingvpn,
            0,
            &end) != VMI_SUCCESS)
        return;
    end <<= 12;
    if (!start || !end) return;
    base_va = start;
    size = end - start;
    // this is some weird address padding that results in huge sections of memory
    // that probably dont contain anything useful.
    if (end > 0x7ff00000000)
    {
        //printf("%s: start:%#016lx end:%#016lx\n", __func__, start, end);
        return;
    }
    dump->segments[dump->segment_count] = malloc(sizeof(vad_seg_t));
    dump->segments[dump->segment_count]->base_va = base_va;
    dump->segments[dump->segment_count]->size = size;
    dump->segments[dump->segment_count]->va_size = size;
    dump->segments[dump->segment_count]->buf = calloc(1, size);
    size_t read_size = 0;
    vmi_read_va(
        vmi,
        base_va,
        dump->pid,
        size,
        dump->segments[dump->segment_count]->buf, &read_size);
    if (read_size < size)
    {
        dump->segments[dump->segment_count]->buf =
            realloc(dump->segments[dump->segment_count]->buf, read_size);
        dump->segments[dump->segment_count]->size = read_size;
    }
    // filename
    dump->segments[dump->segment_count]->filename = (const unicode_string_t) {0};
    get_node_filename(vmi, node, &(dump->segments[dump->segment_count]->filename));
    // vadtype
    get_node_vadtype(vmi, node, &(dump->segments[dump->segment_count]->vadtype));
    // isprivate
    get_node_isprivate(vmi, node, &(dump->segments[dump->segment_count]->isprivate));
    // protection
    get_node_protection(vmi, node, &(dump->segments[dump->segment_count]->protection));

    dump->segment_count += 1;
}

void vad_dump_process(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, page_cat_t page_cat)
{
    addr_t eprocess = windows_find_eprocess_pgd(vmi, event->x86_regs->cr3);
    addr_t vadroot = vmi_get_eprocess_vadroot(vmi, eprocess);
    dump_layer_t *dump;
    dump = malloc(sizeof(dump_layer_t));
    dump->pid = pid;
    dump->rip = event->x86_regs->rip;
    dump->segment_count = 0;
    dump->segments = malloc(sizeof(vad_seg_t *) * SEG_COUNT_MAX);
    vad_iterator(vmi, vadroot, handle_node, dump);
    queue_vads_to_dump(dump);
}

void vad_iterator(vmi_instance_t vmi, addr_t node, traverse_func func, void *data)
{
    addr_t left = 0, right = 0;
    if (vmi_read_addr_va(
            vmi,
            node + process_vmi_windows_rekall.mmvad_leftchild,
            0,
            &left) != VMI_SUCCESS)
        fprintf(stderr, "vad_iterator: Left node could not be read\n");
    if (left)
        vad_iterator(vmi, left, func, data);
    func(vmi, node, data);
    if (vmi_read_addr_va(
            vmi,
            node + process_vmi_windows_rekall.mmvad_rightchild,
            0,
            &right) != VMI_SUCCESS)
        fprintf(stderr, "vad_iterator: Right node could not be read\n");
    if (right)
        vad_iterator(vmi, right, func, data);
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

int add_rip_to_json(vmi_pid_t pid, int dump_count, reg_t rip)
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

    filepath = malloc(PATH_MAX);
    snprintf(filepath, PATH_MAX - 1, "%s/vadinfo.%04d.%ld.json", output_dir, dump_count, (long)pid);
 
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
