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
#include <stdbool.h>
#include <glib-object.h>
#include <json-glib/json-glib.h>

#include <rekall_parser.h>

JsonParser *parse_json(char *json_file)
{

    JsonParser *parser;
    GError *error;

    parser = json_parser_new();

    error = NULL;
    json_parser_load_from_file(parser, json_file, &error);
    if (error)
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to parse file %s\n", json_file);
        return NULL;
    }

    return parser;
}

gint64 get_int_from_jsonpath(const char *expr, JsonNode *root)
{
    gint64 val = G_MININT64;
    JsonNode *result_n = json_path_query(expr, root, NULL);
    JsonArray *result_a = json_node_get_array(result_n);
    if (json_array_get_length(result_a) == 1)
    {
        val = json_array_get_int_element(result_a, 0);
    }
    else
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate JsonPath %s\n", expr);
    }
    json_node_unref(result_n);
    return val;
}

void set_rekall_val(const char *expr, JsonNode *root, gint64 *dest)
{
    gint64 val = G_MININT64;
    val = get_int_from_jsonpath(expr, root);
    if (val == G_MININT64)
        *dest = 0;
    else
        *dest = val;
}

bool parse_rekall_linux(linux_rekall_t *rekall, char *json_file)
{

    JsonParser *parser = parse_json(json_file);

    if (parser == NULL)
    {
        fprintf(stderr, "ERROR: Rekall Parser - JSON parser is NULL\n");
        return 0;
    }

    JsonNode *root = json_parser_get_root(parser);

    set_rekall_val("$['$CONSTANTS']['current_task']", root, &rekall->current_task);
    set_rekall_val("$['$STRUCTS']['task_struct'][1]['comm'][0]", root, &rekall->task_struct_comm);
    set_rekall_val("$['$STRUCTS']['task_struct'][1]['pid'][0]", root, &rekall->task_struct_pid);
    set_rekall_val("$['$STRUCTS']['task_struct'][1]['real_parent'][0]", root, &rekall->task_struct_parent);
    set_rekall_val("$['$STRUCTS']['task_struct'][1]['mm'][0]", root, &rekall->task_struct_mm);
    set_rekall_val("$['$STRUCTS']['task_struct'][1]['tasks'][0]", root, &rekall->task_struct_tasks);
    set_rekall_val("$['$STRUCTS']['mm_struct'][1]['mmap'][0]", root, &rekall->mm_struct_mmap);
    set_rekall_val("$['$STRUCTS']['mm_struct'][1]['pgd'][0]", root, &rekall->mm_struct_pgd);
    set_rekall_val("$['$STRUCTS']['vm_area_struct'][1]['vm_start'][0]", root, &rekall->vm_area_struct_vm_start);
    set_rekall_val("$['$STRUCTS']['vm_area_struct'][1]['vm_end'][0]", root, &rekall->vm_area_struct_vm_end);
    set_rekall_val("$['$STRUCTS']['vm_area_struct'][1]['vm_next'][0]", root, &rekall->vm_area_struct_vm_next);

    g_object_unref(parser);
    return 1;
}

bool parse_rekall_windows(windows_rekall_t *rekall, char *json_file)
{
    JsonParser *parser = parse_json(json_file);

    if (parser == NULL)
    {
        fprintf(stderr, "ERROR: Rekall Parser - JSON parser is NULL\n");
        return 0;
    }

    JsonNode *root = json_parser_get_root(parser);

    set_rekall_val("$['$STRUCTS']['_KPCR'][1]['Prcb'][0]", root, &rekall->kpcr_prcb);
    set_rekall_val("$['$STRUCTS']['_KPRCB'][1]['CurrentThread'][0]", root, &rekall->kprcb_currentthread);
    set_rekall_val("$['$STRUCTS']['_KTHREAD'][1]['Process'][0]", root, &rekall->kthread_process);
    set_rekall_val("$['$STRUCTS']['_KPROCESS'][1]['DirectoryTableBase'][0]", root, &rekall->kprocess_pdbase);
    set_rekall_val("$['$STRUCTS']['_EPROCESS'][1]['ImageFileName'][0]", root, &rekall->eprocess_pname);
    set_rekall_val("$['$STRUCTS']['_EPROCESS'][1]['UniqueProcessId'][0]", root, &rekall->eprocess_pid);
    set_rekall_val("$['$STRUCTS']['_EPROCESS'][1]['InheritedFromUniqueProcessId'][0]", root, &rekall->eprocess_parent_pid);
    set_rekall_val("$['$STRUCTS']['_EPROCESS'][1]['Peb'][0]", root, &rekall->eprocess_peb);
    set_rekall_val("$['$STRUCTS']['_EPROCESS'][1]['ActiveProcessLinks'][0]", root, &rekall->eprocess_tasks);
    set_rekall_val("$['$STRUCTS']['_EPROCESS'][1]['ObjectTable'][0]", root, &rekall->eprocess_objecttable);
    set_rekall_val("$['$STRUCTS']['_EPROCESS'][1]['VadRoot'][0]", root, &rekall->eprocess_vadroot);
    set_rekall_val("$['$STRUCTS']['_MMVAD'][1]['LeftChild'][0]", root, &rekall->mmvad_leftchild);
    set_rekall_val("$['$STRUCTS']['_MMVAD'][1]['RightChild'][0]", root, &rekall->mmvad_rightchild);
    set_rekall_val("$['$STRUCTS']['_MMVAD'][1]['StartingVpn'][0]", root, &rekall->mmvad_startingvpn);
    set_rekall_val("$['$STRUCTS']['_MMVAD'][1]['EndingVpn'][0]", root, &rekall->mmvad_endingvpn);
    set_rekall_val("$['$STRUCTS']['_MMVAD'][1]['Subsection'][0]", root, &rekall->mmvad_controlarea);
    set_rekall_val("$['$STRUCTS']['_CONTROL_AREA'][1]['FilePointer'][0]", root, &rekall->controlarea_fileobject);
    set_rekall_val("$['$STRUCTS']['_FILE_OBJECT'][1]['FileName'][0]", root, &rekall->fileobject_filename);
    set_rekall_val("$['$STRUCTS']['_MMVAD'][1]['u'][0]", root, &rekall->mmvad_flags);
    set_rekall_val("$['$STRUCTS']['_MMVAD_FLAGS'][0]", root, &rekall->mmvad_flags_sizeof);
    set_rekall_val("$['$STRUCTS']['_MMVAD_FLAGS'][1]['VadType'][1][1]['start_bit']", root, &rekall->flags_vadtype_start);
    set_rekall_val("$['$STRUCTS']['_MMVAD_FLAGS'][1]['VadType'][1][1]['end_bit']", root, &rekall->flags_vadtype_end);
    set_rekall_val("$['$STRUCTS']['_MMVAD_FLAGS'][1]['PrivateMemory'][1][1]['start_bit']", root, &rekall->flags_isprivate_start);
    set_rekall_val("$['$STRUCTS']['_MMVAD_FLAGS'][1]['PrivateMemory'][1][1]['end_bit']", root, &rekall->flags_isprivate_end);
    set_rekall_val("$['$STRUCTS']['_MMVAD_FLAGS'][1]['Protection'][1][1]['start_bit']", root, &rekall->flags_protection_start);
    set_rekall_val("$['$STRUCTS']['_MMVAD_FLAGS'][1]['Protection'][1][1]['end_bit']", root, &rekall->flags_protection_end);
    set_rekall_val("$['$STRUCTS']['_PEB'][1]['ImageBaseAddress'][0]", root, &rekall->peb_imagebaseaddress);

    g_object_unref(parser);
    return 1;
}
