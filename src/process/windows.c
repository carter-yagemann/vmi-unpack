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

addr_t vmi_current_thread_windows(vmi_instance_t vmi, vmi_event_t *event) {

    addr_t thread;
    addr_t prcb;
    addr_t currentthread;

    if (vmi_get_page_mode(vmi, event->vcpu_id) != VMI_PM_IA32E) {
        fprintf(stderr, "ERROR: Windows Process VMI - Only IA-32E is currently supported\n");
        return 0;
    }

    reg_t gs_base = event->x86_regs->gs_base;
    prcb = process_vmi_windows_rekall.kpcr_prcb;
    currentthread = gs_base + prcb + process_vmi_windows_rekall.kprcb_currentthread;
    if (vmi_read_addr_va(vmi, currentthread, 0, &thread) != VMI_SUCCESS)
        return 0;

    return thread;
}

addr_t vmi_current_process_windows(vmi_instance_t vmi, vmi_event_t *event) {

    addr_t process;
    addr_t thread = vmi_current_thread_windows(vmi, event);

    if (!thread)
        return 0;

    addr_t kthread = thread + process_vmi_windows_rekall.kthread_process;
    if (vmi_read_addr_va(vmi, kthread, 0, &process) != VMI_SUCCESS)
        return 0;

    return process;
}

vmi_pid_t vmi_current_pid_windows(vmi_instance_t vmi, vmi_event_t *event) {

    if (!process_vmi_ready) {
        fprintf(stderr, "ERROR: Windows Process VMI - Not initialized\n");
        return 0;
    }

    addr_t process = vmi_current_process_windows(vmi, event);

    if (!process)
        return 0;

    vmi_pid_t pid;
    addr_t eprocess_pid = process + process_vmi_windows_rekall.eprocess_pid;
    if (vmi_read_32_va(vmi, eprocess_pid, 0, (uint32_t *) &pid) != VMI_SUCCESS)
        return 0;

    return pid;
}

char *vmi_current_name_windows(vmi_instance_t vmi, vmi_event_t *event) {

    if (!process_vmi_ready) {
        fprintf(stderr, "ERROR: Windows Process VMI - Not initialized\n");
        return NULL;
    }

    addr_t process = vmi_current_process_windows(vmi, event);

    if (!process)
        return NULL;

    addr_t eprocess_pname = process + process_vmi_windows_rekall.eprocess_pname;

    return vmi_read_str_va(vmi, eprocess_pname, 0);
}

vmi_pid_t vmi_current_parent_pid_windows(vmi_instance_t vmi, vmi_event_t *event) {

    if (!process_vmi_ready) {
        fprintf(stderr, "ERROR: Windows Process VMI - Not initialized\n");
        return 0;
    }

    addr_t process = vmi_current_process_windows(vmi, event);

    if (!process)
        return 0;

    vmi_pid_t parent_pid;
    addr_t eprocess_parent_pid = process + process_vmi_windows_rekall.eprocess_parent_pid;
    if (vmi_read_32_va(vmi, eprocess_parent_pid, 0, (uint32_t *) &parent_pid) != VMI_SUCCESS)
        return 0;

    return parent_pid;
}
