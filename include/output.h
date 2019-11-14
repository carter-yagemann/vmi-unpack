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

#ifndef UNPACK_OUTPUT_H
#define UNPACK_OUTPUT_H

#include <libvmi/libvmi.h>

#define MAX_PE_HEADER_SIZE 1024
//section header permissions
#define IMAGE_SCN_CNT_CODE (1<<5)
#define IMAGE_SCN_MEM_EXECUTE (1<<29)
#define IMAGE_SCN_MEM_READ (1<<30)
#define IMAGE_SCN_MEM_WRITE (1<<31)


extern int dump_count;

/**
 * Callback for when a layer is detected via write-then-execute (W2X).
 * Processes the event, prepares an output file and passes it to the dumper thread.
 *
 * @param vmi A libVMI instance.
 * @param event The VMI event triggered by W2X.
 * @param pid The PID of the process that triggered the event.
 * @param cat The type of page that the event triggered on.
 */
void process_layer(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, page_cat_t page_cat);

/**
 * Callback for when a layer is detected via write-then-execute (W2X).
 * Use external Volatility suite to dump the process VADs. Windows only.
 *
 * @param vmi A libVMI instance.
 * @param event The VMI event triggered by W2X.
 * @param pid The PID of the process that triggered the event.
 * @param cat The type of page that the event triggered on.
 */
void volatility_callback_vaddump(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, page_cat_t page_cat);

int volatility_vaddump(vmi_pid_t pid, const char *cmd_prefix, int dump_count);
int volatility_vadinfo(vmi_pid_t pid, const char *cmd_prefix, int dump_count);
int volatility_impscan(vmi_instance_t vmi, pid_events_t *pid_event, addr_t base_va, const char *cmd_prefix, int dump_count);
char* make_vadinfo_json_fn(vmi_pid_t pid, int count);
gboolean find_process_in_vads(vmi_instance_t vmi, pid_events_t *pid_evts, int count);
void show_parsed_pe(parsed_pe_t *pe);

#endif
