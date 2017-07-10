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

#include <stdio.h>

#include <libvmi/libvmi.h>
#include <libvmi/events.h>

#include <vmi/process.h>

#define STACK_SIZE_8K  0x1fff
#define STACK_SIZE_16K 0x3fff
#define MIN_KERNEL_BOUNDARY 0x80000000

addr_t vmi_current_task_struct_linux(vmi_instance_t vmi, vmi_event_t *event) {

    addr_t current_task = 0;

    access_context_t ctx = {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = event->x86_regs->cr3,
        .addr = event->x86_regs->gs_base + process_vmi_linux_rekall.current_task,
    };

    // First try reading the current_task pointer
    if (vmi_read_addr(vmi, &ctx, &current_task) == VMI_FAILURE || current_task < MIN_KERNEL_BOUNDARY) {
        // If that fails or returns nonsense, try reading kernel stack assuming it's size is 16KB
        ctx.addr = event->x86_regs->gs_base & ~STACK_SIZE_16K;
        if (vmi_read_addr(vmi, &ctx, &current_task) == VMI_FAILURE || current_task < MIN_KERNEL_BOUNDARY) {
            // If we still fail, try assuming the kernel stack size is 8KB
            ctx.addr = event->x86_regs->gs_base & ~STACK_SIZE_8K;
            if (vmi_read_addr(vmi, &ctx, &current_task) == VMI_FAILURE || current_task < MIN_KERNEL_BOUNDARY)
                return 0; // Give up
        }
    }

    return current_task;
}

vmi_pid_t vmi_current_pid_linux(vmi_instance_t vmi, vmi_event_t *event) {

    if (!process_vmi_ready) {
        fprintf(stderr, "ERROR: Linux Process VMI - Not initialized\n");
        return 0;
    }

    addr_t task_struct = vmi_current_task_struct_linux(vmi, event);

    if (!task_struct)
        return 0;

    vmi_pid_t pid;
    addr_t task_struct_pid = task_struct + process_vmi_linux_rekall.task_struct_pid;
    if (vmi_read_32_va(vmi, task_struct_pid, 0, (uint32_t *) &pid) != VMI_SUCCESS)
        return 0;

    return pid;
}

char *vmi_current_name_linux(vmi_instance_t vmi, vmi_event_t *event) {

    if (!process_vmi_ready) {
        fprintf(stderr, "ERROR: Linux Process VMI - Not initialized\n");
        return NULL;
    }

    addr_t task_struct = vmi_current_task_struct_linux(vmi, event);

    if (!task_struct)
        return NULL;

    return vmi_read_str_va(vmi, task_struct + process_vmi_linux_rekall.task_struct_comm, 0);
}

vmi_pid_t vmi_current_parent_pid_linux(vmi_instance_t vmi, vmi_event_t *event) {

    if (!process_vmi_ready) {
        fprintf(stderr, "ERROR: Linux Process VMI - Not initialized\n");
        return 0;
    }

    addr_t task_struct = vmi_current_task_struct_linux(vmi, event);

    if (!task_struct)
        return 0;

    addr_t parent_task_struct;
    addr_t task_struct_parent = task_struct + process_vmi_linux_rekall.task_struct_parent;
    if (vmi_read_addr_va(vmi, task_struct_parent, 0, &parent_task_struct) != VMI_SUCCESS)
        return 0;

    vmi_pid_t parent_pid;
    addr_t task_struct_pid = parent_task_struct + process_vmi_linux_rekall.task_struct_pid;
    if (vmi_read_32_va(vmi, task_struct_pid, 0, (uint32_t *) &parent_pid) != VMI_SUCCESS)
        return 0;

    return parent_pid;
}
