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

#ifndef REKALL_PARSER_H
#define REKALL_PARSER_H

#include <stdbool.h>

#include <glib-object.h>
#include <json-glib/json-glib.h>

typedef struct {
    gint64 kpcr_prcb;
    gint64 kprcb_currentthread;
    gint64 kthread_process;
    gint64 eprocess_pname;
    gint64 eprocess_pid;
    gint64 eprocess_parent_pid;
} windows_rekall_t;

typedef struct {
    gint64 current_task;
    gint64 task_struct_comm;
    gint64 task_struct_pid;
    gint64 task_struct_parent;
} linux_rekall_t;

/**
 * Reads a linux rekall JSON file and creates a struct with the offsets needed by vmi/process.h.
 *
 * @param rekall A linux_rekall_t struct to fill.
 * @param json_file The filepath to a linux rekall JSON file.
 *
 * @return 1 on success, otherwise 0.
 */
bool parse_rekall_linux(linux_rekall_t *rekall, char *json_file);

/**
 * Reads a windows rekall JSON file and creates a struct with the offsets needed by vmi/process.h.
 *
 * @param rekall A windows rekall_t struct to fill.
 * @param json_file The filepath to a windows rekall JSON file.
 *
 * @return 1 on success, otherwise 0.
 */
bool parse_rekall_windows(windows_rekall_t *rekall, char *json_file);

#endif
