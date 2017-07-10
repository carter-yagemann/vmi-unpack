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

JsonParser *parse_json(char *json_file) {

    JsonParser *parser;
    GError *error;

    parser = json_parser_new();

    error = NULL;
    json_parser_load_from_file(parser, json_file, &error);
    if (error) {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to parse file %s\n", json_file);
        return NULL;
    }

    return parser;
}

bool parse_rekall_linux(linux_rekall_t *rekall, char *json_file) {

    JsonParser *parser = parse_json(json_file);

    if (parser == NULL) {
        fprintf(stderr, "ERROR: Rekall Parser - JSON parser is NULL\n");
        return 0;
    }

    JsonReader *reader = json_reader_new(json_parser_get_root(parser));

    // current_task offset
    if (!json_reader_read_member(reader, "$CONSTANTS")) {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate $CONSTANTS\n");
        return 0;
    }
    if (!json_reader_read_member(reader, "current_task")) {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate current_task\n");
        return 0;
    }
    rekall->current_task = json_reader_get_int_value(reader);
    json_reader_end_member(reader);
    json_reader_end_member(reader);

    // task_struct->comm offset
    if (!json_reader_read_member(reader, "$STRUCTS")) {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate $STRUCTS \n");
        return 0;
    }
    if (!json_reader_read_member(reader, "task_struct")) {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate task_struct\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 1)) {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate task_struct[1]\n");
        return 0;
    }
    if (!json_reader_read_member(reader, "comm")) {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate task_struct[1]['comm']\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 0)) {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate task_struct[1]['comm'][0]\n");
        return 0;
    }
    rekall->task_struct_comm = json_reader_get_int_value(reader);
    json_reader_end_member(reader);
    json_reader_end_member(reader);

    // task_struct->pid offset
    if (!json_reader_read_member(reader, "pid")) {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate task_struct[1]['pid']\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 0)) {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate task_struct[1]['pid'][0]\n");
        return 0;
    }
    rekall->task_struct_pid = json_reader_get_int_value(reader);
    json_reader_end_member(reader);
    json_reader_end_member(reader);

    // task_struct->real_parent offset
    if (!json_reader_read_member(reader, "real_parent")) {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate task_struct[1]['real_parent']\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 0)) {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate task_struct[1]['real_parent'][0]\n");
        return 0;
    }
    rekall->task_struct_parent = json_reader_get_int_value(reader);

    g_object_unref(reader);
    g_object_unref(parser);

    return 1;
}

bool parse_rekall_windows(windows_rekall_t *rekall, char *json_file) {

    JsonParser *parser = parse_json(json_file);

    if (parser == NULL) {
        fprintf(stderr, "ERROR: Rekall Parser - JSON parser is NULL\n");
        return 0;
    }

    JsonReader *reader = json_reader_new(json_parser_get_root(parser));

    // kpcr->prcb
    if (!json_reader_read_member(reader, "$STRUCTS")) {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate $STRUCTS\n");
        return 0;
    }
    if (!json_reader_read_member(reader, "_KPCR")) {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _KPCR\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 1)) {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _KPCR[1]\n");
        return 0;
    }
    if (!json_reader_read_member(reader, "Prcb")) {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _KPCR[1]['Prcb']\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 0)) {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _KPCR[1]['Prcb'][0]\n");
        return 0;
    }
    rekall->kpcr_prcb = json_reader_get_int_value(reader);
    json_reader_end_member(reader);
    json_reader_end_member(reader);
    json_reader_end_member(reader);
    json_reader_end_member(reader);

    // kpcr_currentthread
    if (!json_reader_read_member(reader, "_KPRCB")) {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _KPRCB\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 1)) {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _KPRCB[1]\n");
        return 0;
    }
    if (!json_reader_read_member(reader, "CurrentThread")) {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _KPCR[1]['CurrentThread']\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 0)) {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _KPCR[1]['CurrentThread'][0]\n");
        return 0;
    }
    rekall->kprcb_currentthread = json_reader_get_int_value(reader);
    json_reader_end_member(reader);
    json_reader_end_member(reader);
    json_reader_end_member(reader);
    json_reader_end_member(reader);

    // kthread_process
    if (!json_reader_read_member(reader, "_KTHREAD")) {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _KTHREAD\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 1)) {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _KTHREAD[1]\n");
        return 0;
    }
    if (!json_reader_read_member(reader, "Process")) {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _KTHREAD[1]['Process']\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 0)) {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _KTHREAD[1]['Process'][0]\n");
        return 0;
    }
    rekall->kthread_process = json_reader_get_int_value(reader);
    json_reader_end_member(reader);
    json_reader_end_member(reader);
    json_reader_end_member(reader);
    json_reader_end_member(reader);

    // eprocess_pname
    if (!json_reader_read_member(reader, "_EPROCESS")) {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _EPROCESS\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 1)) {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _EPROCESS[1]\n");
        return 0;
    }
    if (!json_reader_read_member(reader, "ImageFileName")) {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _EPROCESS[1]['ImageFileName']\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 0)) {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _EPROCESS[1]['ImageFileName'][0]\n");
        return 0;
    }
    rekall->eprocess_pname = json_reader_get_int_value(reader);
    json_reader_end_member(reader);
    json_reader_end_member(reader);

    // eprocess_pid
    if (!json_reader_read_member(reader, "UniqueProcessId")) {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _EPROCESS[1]['UniqueProcessId']\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 0)) {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _EPROCESS[1]['UniqueProcessId'][0]\n");
        return 0;
    }
    rekall->eprocess_pid = json_reader_get_int_value(reader);
    json_reader_end_member(reader);
    json_reader_end_member(reader);

    // eprocess_parent_pid
    if (!json_reader_read_member(reader, "InheritedFromUniqueProcessId")) {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _EPROCESS[1]['InheritedFromUniqueProcessId']\n");
        return 0;
    }
    if (!json_reader_read_element(reader, 0)) {
        fprintf(stderr, "ERROR: Rekall Parser - Failed to locate _EPROCESS[1]['InheritedFromUniqueProcessId'][0]\n");
        return 0;
    }
    rekall->eprocess_parent_pid = json_reader_get_int_value(reader);

    g_object_unref(reader);
    g_object_unref(parser);

    return 1;
}
