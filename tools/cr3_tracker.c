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
#include <getopt.h>

#include <libvmi/libvmi.h>

#include <vmi/process.h>

/* Global variables */
vmi_event_t cr3_monitoring;
char *domain_name;

/* Signal handler */
static int interrupted = 0;
static struct sigaction action;
static void close_handler(int sig)
{
    interrupted = sig;
}

event_response_t monitor_cr3(vmi_instance_t vmi, vmi_event_t *event)
{
    vmi_pid_t pid = vmi_current_pid(vmi, event);
    vmi_pid_t parent_pid = vmi_current_parent_pid(vmi, event);
    char *name = vmi_current_name(vmi, event);

    printf("VCPU: %d PID: %d NAME: %s PARENT: %d\n", event->vcpu_id, pid, name, parent_pid);

    free(name);
    return VMI_EVENT_RESPONSE_NONE;
}

/**
 * Monitors the CR3 register in each VCPU and prints the current process'
 * PID and name.
 */
int main(int argc, char *argv[])
{
    domain_name = NULL;
    char *rekall = NULL;

    if (argc < 3)
    {
        printf("Usage: %s <domain_name> <rekall_profile>\n", argv[0]);
        return EXIT_FAILURE;
    }

    domain_name = argv[1];
    rekall = argv[2];

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
    if (vmi_init_complete(&vmi, domain_name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, NULL,
                          VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL) == VMI_FAILURE)
    {
        fprintf(stderr, "ERROR: libVMI - Failed to initialize libVMI.\n");
        if (vmi != NULL)
        {
            vmi_destroy(vmi);
        }
        return EXIT_FAILURE;
    }

    SETUP_REG_EVENT(&cr3_monitoring, CR3, VMI_REGACCESS_W, 0, monitor_cr3);

    // Initialize various helper methods
    vmi_pause_vm(vmi);
    if (!process_vmi_init(vmi, rekall))
    {
        fprintf(stderr, "ERROR: CR3 Tracker - Failed to initialize process VMI\n");
        vmi_destroy(vmi);
        return EXIT_FAILURE;
    }
    vmi_register_event(vmi, &cr3_monitoring);
    vmi_resume_vm(vmi);

    // Main loop
    status_t status;
    while (!interrupted)
    {
        status = vmi_events_listen(vmi, 500);
        if (status != VMI_SUCCESS)
        {
            fprintf(stderr, "ERROR: libVMI - Unexpected error while waiting for VMI events, quitting.\n");
            interrupted = 1;
        }
    }

    // Cleanup
    vmi_pause_vm(vmi);
    process_vmi_destroy(vmi);
    vmi_resume_vm(vmi);

    vmi_destroy(vmi);
    return EXIT_SUCCESS;
}
