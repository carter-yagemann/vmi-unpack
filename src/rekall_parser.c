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

#define CHECK_VAL(VAL) ({ if (VAL == G_MININT64) return 0; VAL; })

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

gint64 get_int_from_jsonpath(const char *expr, JsonNode *root) {
  gint64 val = G_MININT64;
  JsonNode* result_n = json_path_query(expr, root, NULL);
  JsonArray* result_a = json_node_get_array(result_n);
  if (json_array_get_length(result_a) == 1) {
    val = json_array_get_int_element(result_a, 0);
  } else {
    fprintf(stderr, "ERROR: Rekall Parser - Failed to locate JsonPath %s\n", expr);
  }
  g_object_unref(result_n);
  return val;
}

bool parse_rekall_linux(linux_rekall_t *rekall, char *json_file)
{

    JsonParser *parser = parse_json(json_file);

    if (parser == NULL)
    {
        fprintf(stderr, "ERROR: Rekall Parser - JSON parser is NULL\n");
        return 0;
    }

    JsonReader *reader = json_reader_new(json_parser_get_root(parser));

    // current_task offset
    if (!json_reader_read_member(reader, "$CONSTANTS"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate $CONSTANTS\n");
        return 0;
    }
    if (!json_reader_read_member(reader, "current_task"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate current_task\n");
        return 0;
    }
    rekall->current_task = json_reader_get_int_value(reader);
    g_object_unref(reader);
    reader = json_reader_new(json_parser_get_root(parser));

    // task_struct->comm offset
    if (!json_reader_read_member(reader, "$STRUCTS"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate $STRUCTS \n");
        return 0;
    }
    if (!json_reader_read_member(reader, "task_struct"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate task_struct\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 1))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate task_struct[1]\n");
        return 0;
    }
    if (!json_reader_read_member(reader, "comm"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate task_struct[1]['comm']\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 0))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate task_struct[1]['comm'][0]\n");
        return 0;
    }
    rekall->task_struct_comm = json_reader_get_int_value(reader);
    g_object_unref(reader);
    reader = json_reader_new(json_parser_get_root(parser));

    // task_struct->pid offset
    json_reader_read_member(reader, "$STRUCTS");
    json_reader_read_member(reader, "task_struct");
    json_reader_read_element(reader, 1);
    if (!json_reader_read_member(reader, "pid"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate task_struct[1]['pid']\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 0))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate task_struct[1]['pid'][0]\n");
        return 0;
    }
    rekall->task_struct_pid = json_reader_get_int_value(reader);
    g_object_unref(reader);
    reader = json_reader_new(json_parser_get_root(parser));

    // task_struct->real_parent offset
    json_reader_read_member(reader, "$STRUCTS");
    json_reader_read_member(reader, "task_struct");
    json_reader_read_element(reader, 1);
    if (!json_reader_read_member(reader, "real_parent"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate task_struct[1]['real_parent']\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 0))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate task_struct[1]['real_parent'][0]\n");
        return 0;
    }
    rekall->task_struct_parent = json_reader_get_int_value(reader);
    g_object_unref(reader);
    reader = json_reader_new(json_parser_get_root(parser));

    // task_struct->mm
    json_reader_read_member(reader, "$STRUCTS");
    json_reader_read_member(reader, "task_struct");
    json_reader_read_element(reader, 1);
    if (!json_reader_read_member(reader, "mm"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate task_struct[1]['mm']\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 0))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate task_struct[1]['mm'][0]\n");
        return 0;
    }
    rekall->task_struct_mm = json_reader_get_int_value(reader);
    g_object_unref(reader);
    reader = json_reader_new(json_parser_get_root(parser));

    // task_struct->tasks
    json_reader_read_member(reader, "$STRUCTS");
    json_reader_read_member(reader, "task_struct");
    json_reader_read_element(reader, 1);
    if (!json_reader_read_member(reader, "tasks"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate task_struct[1]['tasks']\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 0))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate task_struct[1]['tasks'][0]\n");
        return 0;
    }
    rekall->task_struct_tasks = json_reader_get_int_value(reader);
    g_object_unref(reader);
    reader = json_reader_new(json_parser_get_root(parser));

    // mm_struct->mmap
    json_reader_read_member(reader, "$STRUCTS");
    if (!json_reader_read_member(reader, "mm_struct"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate mm_struct\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 1))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate mm_struct[1]\n");
        return 0;
    }
    if (!json_reader_read_member(reader, "mmap"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate mm_struct[1]['mmap']\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 0))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate mm_struct[1]['mmap'][0]\n");
        return 0;
    }
    rekall->mm_struct_mmap = json_reader_get_int_value(reader);
    g_object_unref(reader);
    reader = json_reader_new(json_parser_get_root(parser));

    // mm_struct->pgd
    json_reader_read_member(reader, "$STRUCTS");
    json_reader_read_member(reader, "mm_struct");
    json_reader_read_element(reader, 1);
    if (!json_reader_read_member(reader, "pgd"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate mm_struct[1]['pgd']\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 0))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate mm_struct[1]['pgd'][0]\n");
        return 0;
    }
    rekall->mm_struct_pgd = json_reader_get_int_value(reader);
    g_object_unref(reader);
    reader = json_reader_new(json_parser_get_root(parser));

    // vm_area_struct->vm_start
    json_reader_read_member(reader, "$STRUCTS");
    if (!json_reader_read_member(reader, "vm_area_struct"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate vm_area_struct\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 1))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate vm_area_struct[1]\n");
        return 0;
    }
    if (!json_reader_read_member(reader, "vm_start"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate vm_area_struct[1]['vm_start']\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 0))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate vm_area_struct[1]['vm_start'][0]\n");
        return 0;
    }
    rekall->vm_area_struct_vm_start = json_reader_get_int_value(reader);
    g_object_unref(reader);
    reader = json_reader_new(json_parser_get_root(parser));

    // vm_area_struct->vm_end
    json_reader_read_member(reader, "$STRUCTS");
    json_reader_read_member(reader, "vm_area_struct");
    json_reader_read_element(reader, 1);
    if (!json_reader_read_member(reader, "vm_end"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate vm_area_struct[1]['vm_end']\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 0))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate vm_area_struct[1]['vm_end'][0]\n");
        return 0;
    }
    rekall->vm_area_struct_vm_end = json_reader_get_int_value(reader);
    g_object_unref(reader);
    reader = json_reader_new(json_parser_get_root(parser));

    // vm_area_struct->vm_next
    json_reader_read_member(reader, "$STRUCTS");
    json_reader_read_member(reader, "vm_area_struct");
    json_reader_read_element(reader, 1);
    if (!json_reader_read_member(reader, "vm_next"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate vm_area_struct[1]['vm_next']\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 0))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate vm_area_struct[1]['vm_next'][0]\n");
        return 0;
    }
    rekall->vm_area_struct_vm_next = json_reader_get_int_value(reader);

    g_object_unref(reader);
    g_object_unref(parser);

    return 1;
}

bool parse_rekall_windows(windows_rekall_t *rekall, char *json_file)
{

    gint64 val;
    JsonParser *parser = parse_json(json_file);

    if (parser == NULL)
    {
        fprintf(stderr, "ERROR: Rekall Parser - JSON parser is NULL\n");
        return 0;
    }

    JsonNode* root = json_parser_get_root(parser);
    JsonReader *reader = json_reader_new(root);

    // kpcr->prcb
    if (!json_reader_read_member(reader, "$STRUCTS"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate $STRUCTS\n");
        return 0;
    }
    if (!json_reader_read_member(reader, "_KPCR"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _KPCR\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 1))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _KPCR[1]\n");
        return 0;
    }
    if (!json_reader_read_member(reader, "Prcb"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _KPCR[1]['Prcb']\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 0))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _KPCR[1]['Prcb'][0]\n");
        return 0;
    }
    rekall->kpcr_prcb = json_reader_get_int_value(reader);
    g_object_unref(reader);
    reader = json_reader_new(root);

    // kpcr_currentthread
    json_reader_read_member(reader, "$STRUCTS");
    if (!json_reader_read_member(reader, "_KPRCB"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _KPRCB\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 1))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _KPRCB[1]\n");
        return 0;
    }
    if (!json_reader_read_member(reader, "CurrentThread"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _KPCR[1]['CurrentThread']\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 0))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _KPCR[1]['CurrentThread'][0]\n");
        return 0;
    }
    rekall->kprcb_currentthread = json_reader_get_int_value(reader);
    g_object_unref(reader);
    reader = json_reader_new(root);

    // kthread_process
    json_reader_read_member(reader, "$STRUCTS");
    if (!json_reader_read_member(reader, "_KTHREAD"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _KTHREAD\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 1))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _KTHREAD[1]\n");
        return 0;
    }
    if (!json_reader_read_member(reader, "Process"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _KTHREAD[1]['Process']\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 0))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _KTHREAD[1]['Process'][0]\n");
        return 0;
    }
    rekall->kthread_process = json_reader_get_int_value(reader);
    g_object_unref(reader);
    reader = json_reader_new(root);

    // kprocess_pdbase
    json_reader_read_member(reader, "$STRUCTS");
    if (!json_reader_read_member(reader, "_KPROCESS"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _KPROCESS\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 1))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _KPROCESS[1]\n");
        return 0;
    }
    if (!json_reader_read_member(reader, "DirectoryTableBase"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _KPROCESS[1]['DirectoryTableBase']\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 0))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _KPROCESS[1]['DirectoryTableBase'][0]\n");
        return 0;
    }
    rekall->kprocess_pdbase = json_reader_get_int_value(reader);
    g_object_unref(reader);
    reader = json_reader_new(root);

    // eprocess_pname
    json_reader_read_member(reader, "$STRUCTS");
    if (!json_reader_read_member(reader, "_EPROCESS"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _EPROCESS\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 1))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _EPROCESS[1]\n");
        return 0;
    }
    if (!json_reader_read_member(reader, "ImageFileName"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _EPROCESS[1]['ImageFileName']\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 0))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _EPROCESS[1]['ImageFileName'][0]\n");
        return 0;
    }
    rekall->eprocess_pname = json_reader_get_int_value(reader);
    g_object_unref(reader);
    reader = json_reader_new(root);

    // eprocess_pid
    json_reader_read_member(reader, "$STRUCTS");
    json_reader_read_member(reader, "_EPROCESS");
    json_reader_read_element(reader, 1);
    if (!json_reader_read_member(reader, "UniqueProcessId"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _EPROCESS[1]['UniqueProcessId']\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 0))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _EPROCESS[1]['UniqueProcessId'][0]\n");
        return 0;
    }
    rekall->eprocess_pid = json_reader_get_int_value(reader);
    g_object_unref(reader);
    reader = json_reader_new(root);

    // eprocess_parent_pid
    json_reader_read_member(reader, "$STRUCTS");
    json_reader_read_member(reader, "_EPROCESS");
    json_reader_read_element(reader, 1);
    if (!json_reader_read_member(reader, "InheritedFromUniqueProcessId"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _EPROCESS[1]['InheritedFromUniqueProcessId']\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 0))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _EPROCESS[1]['InheritedFromUniqueProcessId'][0]\n");
        return 0;
    }
    rekall->eprocess_parent_pid = json_reader_get_int_value(reader);
    g_object_unref(reader);
    reader = json_reader_new(root);

    // eprocess_tasks
    json_reader_read_member(reader, "$STRUCTS");
    json_reader_read_member(reader, "_EPROCESS");
    json_reader_read_element(reader, 1);
    if (!json_reader_read_member(reader, "ActiveProcessLinks"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _EPROCESS[1]['ActiveProcessLinks']\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 0))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _EPROCESS[1]['ActiveProcessLinks'][0]\n");
        return 0;
    }
    rekall->eprocess_tasks = json_reader_get_int_value(reader);
    g_object_unref(reader);
    reader = json_reader_new(root);

    // eprocess_vadroot
    json_reader_read_member(reader, "$STRUCTS");
    json_reader_read_member(reader, "_EPROCESS");
    json_reader_read_element(reader, 1);
    if (!json_reader_read_member(reader, "VadRoot"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _EPROCESS[1]['VadRoot']\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 0))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _EPROCESS[1]['VadRoot'][0]\n");
        return 0;
    }
    rekall->eprocess_vadroot = json_reader_get_int_value(reader);
    g_object_unref(reader);
    reader = json_reader_new(root);

    // mmvad_leftchild
    json_reader_read_member(reader, "$STRUCTS");
    if (!json_reader_read_member(reader, "_MMVAD"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _MMVAD\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 1))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _MMVAD[1]\n");
        return 0;
    }
    if (!json_reader_read_member(reader, "LeftChild"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _MMVAD[1]['LeftChild']\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 0))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _MMVAD[1]['LeftChild'][0]\n");
        return 0;
    }
    rekall->mmvad_leftchild = json_reader_get_int_value(reader);
    g_object_unref(reader);
    reader = json_reader_new(root);

    // mmvad_rightchild
    json_reader_read_member(reader, "$STRUCTS");
    json_reader_read_member(reader, "_MMVAD");
    json_reader_read_element(reader, 1);
    if (!json_reader_read_member(reader, "RightChild"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _MMVAD[1]['RightChild']\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 0))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _MMVAD[1]['RightChild'][0]\n");
        return 0;
    }
    rekall->mmvad_rightchild = json_reader_get_int_value(reader);
    g_object_unref(reader);
    reader = json_reader_new(root);

    // mmvad_startingvpn
    json_reader_read_member(reader, "$STRUCTS");
    json_reader_read_member(reader, "_MMVAD");
    json_reader_read_element(reader, 1);
    if (!json_reader_read_member(reader, "StartingVpn"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _MMVAD[1]['StartingVpn']\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 0))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _MMVAD[1]['StartingVpn'][0]\n");
        return 0;
    }
    rekall->mmvad_startingvpn = json_reader_get_int_value(reader);
    g_object_unref(reader);
    reader = json_reader_new(root);

    // mmvad_endingvpn
    json_reader_read_member(reader, "$STRUCTS");
    json_reader_read_member(reader, "_MMVAD");
    json_reader_read_element(reader, 1);
    if (!json_reader_read_member(reader, "EndingVpn"))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _MMVAD[1]['EndingVpn']\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 0))
    {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _MMVAD[1]['EndingVpn'][0]\n");
        return 0;
    }
    rekall->mmvad_endingvpn = json_reader_get_int_value(reader);

    g_object_unref(reader);

    // mmvad_controlarea
    const char *controlarea_expr = "$['$STRUCTS']['_MMVAD'][1]['Subsection'][0]";
    val = get_int_from_jsonpath(controlarea_expr, root);
    rekall->mmvad_controlarea = CHECK_VAL(val);

    // controlarea_fileobject
    const char *fileobject_expr = "$['$STRUCTS']['_CONTROL_AREA'][1]['FilePointer'][0]";
    val = get_int_from_jsonpath(fileobject_expr, root);
    rekall->controlarea_fileobject = CHECK_VAL(val);

    // fileobject_filename
    const char *filename_expr = "$['$STRUCTS']['_FILE_OBJECT'][1]['FileName'][0]";
    val = get_int_from_jsonpath(filename_expr, root);
    rekall->fileobject_filename = CHECK_VAL(val);

    // mmvad_flags
    const char *flags_expr = "$['$STRUCTS']['_MMVAD'][1]['u'][0]";
    val = get_int_from_jsonpath(flags_expr, root);
    rekall->mmvad_flags = CHECK_VAL(val);

    // mmvad_flags_sizeof
    const char *flags_sizeof_expr = "$['$STRUCTS']['_MMVAD_FLAGS'][0]";
    val = get_int_from_jsonpath(flags_sizeof_expr, root);
    rekall->mmvad_flags_sizeof = CHECK_VAL(val);

    // flags_vadtype_start
    const char *vadtype_start_expr = "$['$STRUCTS']['_MMVAD_FLAGS'][1]['VadType'][1][1]['start_bit']";
    val = get_int_from_jsonpath(vadtype_start_expr, root);
    rekall->flags_vadtype_start = CHECK_VAL(val);

    // flags_vadtype_end
    const char *vadtype_end_expr = "$['$STRUCTS']['_MMVAD_FLAGS'][1]['VadType'][1][1]['end_bit']";
    val = get_int_from_jsonpath(vadtype_end_expr, root);
    rekall->flags_vadtype_end = CHECK_VAL(val);

    // flags_isprivate_start
    const char *isprivate_start_expr = "$['$STRUCTS']['_MMVAD_FLAGS'][1]['PrivateMemory'][1][1]['start_bit']";
    val = get_int_from_jsonpath(isprivate_start_expr, root);
    rekall->flags_isprivate_start = CHECK_VAL(val);

    // flags_isprivate_end
    const char *isprivate_end_expr = "$['$STRUCTS']['_MMVAD_FLAGS'][1]['PrivateMemory'][1][1]['end_bit']";
    val = get_int_from_jsonpath(isprivate_end_expr, root);
    rekall->flags_isprivate_end = CHECK_VAL(val);

    // flags_protection_start
    const char *protection_start_expr = "$['$STRUCTS']['_MMVAD_FLAGS'][1]['Protection'][1][1]['start_bit']";
    val = get_int_from_jsonpath(protection_start_expr, root);
    rekall->flags_protection_start = CHECK_VAL(val);

    // flags_protection_end
    const char *protection_end_expr = "$['$STRUCTS']['_MMVAD_FLAGS'][1]['Protection'][1][1]['end_bit']";
    val = get_int_from_jsonpath(protection_end_expr, root);
    rekall->flags_protection_end = CHECK_VAL(val);

    g_object_unref(parser);
    return 1;
}
