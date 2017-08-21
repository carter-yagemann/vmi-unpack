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

#include <libvmi/libvmi.h>

#include <monitor.h>
#include <paging/intel_64.h>
#include <vmi/process.h>

/* Signal handler */
static int interrupted = 0;
static struct sigaction action;
static void close_handler(int sig)
{
    interrupted = sig;
}

/**
 * Callback that's invoked when a process tries to write then execute.
 */
void w2x_cb(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, page_cat_t cat)
{
    mem_seg_t mem_seg = vmi_current_find_segment(vmi, event, event->x86_regs->rip);

    printf("Caught write then execute! [PID=%d,EIP=0x%lx,base=0x%lx,size=%ld]\n",
           pid, event->x86_regs->rip, mem_seg.base_va, mem_seg.size);
}

/**
 * Monitors a process' page table.
 */
int main(int argc, char *argv[])
{
    if (argc < 4)
    {
        printf("%s <domain_name> <pid> <rekall_json>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Register signal handler.
    action.sa_handler = close_handler;
    action.sa_flags = 0;
    sigemptyset(&action.sa_mask);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGHUP,  &action, NULL);
    sigaction(SIGINT,  &action, NULL);
    sigaction(SIGALRM, &action, NULL);

    // Initialize libVMI
    vmi_instance_t vmi;
    if (vmi_init_complete(&vmi, argv[1], VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, NULL,
                          VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL) == VMI_FAILURE)
    {
        printf("ERROR: Failed to initialize libVMI.\n");
        if (vmi != NULL)
        {
            vmi_destroy(vmi);
        }
        return EXIT_FAILURE;
    }

    process_vmi_init(vmi, argv[3]);
    monitor_init(vmi);
    monitor_add_page_table(vmi, atoi(argv[2]), w2x_cb, MONITOR_FOLLOW_REMAPPING);

    // Main loop
    status_t status;
    while (!interrupted)
    {
        status = vmi_events_listen(vmi, 500);
        if (status != VMI_SUCCESS)
        {
            printf("ERROR: Unexpected error while waiting for VMI events, quitting.\n");
            interrupted = 1;
        }
    }

    // Cleanup
    monitor_destroy(vmi);
    process_vmi_destroy(vmi);

    vmi_destroy(vmi);
    return EXIT_SUCCESS;
}
