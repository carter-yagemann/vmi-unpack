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

typedef struct
{
    char *buf;
    size_t size;
    vmi_pid_t pid;
} pe_dump_t;

typedef void (*traverse_func)(vmi_instance_t, addr_t, void *);

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
void vad_dump_process(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, page_cat_t page_cat);
void volatility_vaddump(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, page_cat_t page_cat);

/**
 * Iterates over a VAD tree
 *
 * @param vmi A libVMI instance.
 * @param node The current node
 * @param func The function to call on each iteration
 * @param data User-specified data
 */
void vad_iterator(vmi_instance_t vmi, addr_t node, traverse_func func, void *data);

#endif
