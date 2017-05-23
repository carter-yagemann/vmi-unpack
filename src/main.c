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

#include <monitor.h>
#include <dump.h>
#include <paging/intel_64.h>
#include <vmi/process.h>

/* Global variables */
vmi_event_t cr3_monitoring;
char *domain_name;
char *process_name;
char *output_dir;
vmi_pid_t process_pid;

/* Signal handler */
static int interrupted = 0;
static struct sigaction action;
static void close_handler(int sig) {
    interrupted = sig;
}

/**
 * Callback that's invoked when a process tries to write then execute.
 */
void w2x_cb(vmi_instance_t vmi, vmi_event_t *event, page_cat_t page_cat) {

    uint64_t page_size;

    switch(page_cat) {
        case PAGE_CAT_4KB_FRAME:
            page_size = 0x1000;
            break;
        case PAGE_CAT_2MB_FRAME:
            page_size = 0x200000;
            break;
        case PAGE_CAT_1GB_FRAME:
            page_size = 0x40000000;
            break;
        default:
            page_size = 0;
            break;
    }

    if (!page_size) {
        fprintf(stderr, "ERROR: Unpack - Unknown page size\n");
        return;
    }

    addr_t paddr = (event->mem_event.gfn << 12) + event->mem_event.offset;
    uint64_t dump_size = page_size - event->mem_event.offset;
    char * buffer = (char *) malloc(dump_size);
    vmi_read_pa(vmi, paddr, (void *) buffer, dump_size);

    add_to_dump_queue(buffer, dump_size, event->x86_regs->rip);
}

void usage(char *name) {

    printf("%s [options]\n", name);
    printf("\n");
    printf("Required arguments:\n");
    printf("    -d <domain_name>         name of VM to unpack from\n");
    printf("    -r <rekall_file>         path to rekall file\n");
    printf("    -o <output_dir>          directory to dump layers into\n");
    printf("\n");
    printf("One of the following must be provided:\n");
    printf("    -p <pid>                 unpack process with provided PID\n");
    printf("    -n <process_name>        unpack process with provided name\n");
}

event_response_t monitor_pid(vmi_instance_t vmi, vmi_event_t *event) {

    vmi_pid_t pid = vmi_current_pid(vmi, event);
    if (pid == process_pid) {
        monitor_add_page_table(vmi, pid, w2x_cb);
        vmi_clear_event(vmi, &cr3_monitoring, NULL);
    }

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t monitor_name(vmi_instance_t vmi, vmi_event_t *event) {

    char *name = vmi_current_name(vmi, event);
    if (!strncmp(name, process_name, strlen(name))) {
        vmi_pid_t pid = vmi_current_pid(vmi, event);
        monitor_add_page_table(vmi, pid, w2x_cb);
        vmi_clear_event(vmi, &cr3_monitoring, NULL);
    }
    return VMI_EVENT_RESPONSE_NONE;
}

/**
 * Monitors a process' page table.
 */
int main(int argc, char *argv[]) {

    domain_name = NULL;
    char *rekall = NULL;
    process_name = NULL;
    output_dir = NULL;
    process_pid = 0;
    int c;

    // Parse arguments
    while ((c = getopt(argc, argv, "d:r:o:p:n:")) != -1) {
        switch (c) {
            case 'd':
                domain_name = optarg;
                break;
            case 'r':
                rekall = optarg;
                break;
            case 'o':
                output_dir = optarg;
                break;
            case 'p':
                process_pid = atoi(optarg);
                break;
            case 'n':
                process_name = optarg;
                break;
            default:
                usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (domain_name == NULL || rekall == NULL || output_dir == NULL ||
            (process_pid == 0 && process_name == NULL)) {
        usage(argv[0]);
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
    if (vmi_init_complete(&vmi, domain_name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, NULL,
            VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL) == VMI_FAILURE) {
        fprintf(stderr, "ERROR: libVMI - Failed to initialize libVMI.\n");
        if (vmi != NULL) {
            vmi_destroy(vmi);
        }
        return EXIT_FAILURE;
    }

    SETUP_REG_EVENT(&cr3_monitoring, CR3, VMI_REGACCESS_W, 0, NULL);
    if (process_name != NULL) {
        cr3_monitoring.callback = monitor_name;
    } else if (process_pid > 0) {
        cr3_monitoring.callback = monitor_pid;
    }

    // Initialize various helper methods
    start_dump_thread(output_dir);
    vmi_pause_vm(vmi);
    monitor_init(vmi);
    if (!process_vmi_init(vmi, rekall)) {
        fprintf(stderr, "ERROR: Unpack - Failed to initialize process VMI\n");
        monitor_destroy(vmi);
        vmi_destroy(vmi);
        return EXIT_FAILURE;
    }
    vmi_register_event(vmi, &cr3_monitoring);
    vmi_resume_vm(vmi);

    // Main loop
    status_t status;
    while (!interrupted) {
        status = vmi_events_listen(vmi, 500);
        if (status != VMI_SUCCESS) {
            fprintf(stderr, "ERROR: libVMI - Unexpected error while waiting for VMI events, quitting.\n");
            interrupted = 1;
        }
    }

    // Cleanup
    vmi_pause_vm(vmi);
    monitor_destroy(vmi);
    process_vmi_destroy(vmi);
    vmi_resume_vm(vmi);
    stop_dump_thread();

    vmi_destroy(vmi);
    return EXIT_SUCCESS;
}
