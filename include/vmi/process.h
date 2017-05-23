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

#ifndef VMI_PROCESS_H
#define VMI_PROCESS_H

#include <stdbool.h>

#include <libvmi/libvmi.h>
#include <libvmi/events.h>

#include <rekall_parser.h>

bool process_vmi_ready;

/**
 * Initializes the functions in this header file.
 *
 * @param vmi A vmi_instance_t.
 * @param rekall_filepath The path to a rekall JSON file.
 *
 * @return 1 if successful, otherwise 0.
 */
bool process_vmi_init(vmi_instance_t vmi, char *rekall_filepath);

/**
 * Destroys the current state of these functions.
 */
void process_vmi_destroy();

/**
 * Gets the PID of the current process. This method is faster than
 * vmi_dtb_to_pid because it doesn't walk the entire process list.
 *
 * @param vmi A vmi_instance_t for the guest VM to introspect.
 *
 * @return The PID of the current process.
 */
vmi_pid_t (*vmi_current_pid)(vmi_instance_t vmi, vmi_event_t *event);

/**
 * Gets the current process' name.
 *
 * @param vmi A vmi_instance_t for the guest VM to introspect.
 *
 * @return The current process' name or NULL if it could not be determined.
 */
char *(*vmi_current_name)(vmi_instance_t vmi, vmi_event_t *event);

/* LINUX */

linux_rekall_t process_vmi_linux_rekall;
vmi_pid_t vmi_current_pid_linux(vmi_instance_t vmi, vmi_event_t *event);
char *vmi_current_name_linux(vmi_instance_t vmi, vmi_event_t *event);

/* WINDOWS */

windows_rekall_t process_vmi_windows_rekall;
vmi_pid_t vmi_current_pid_windows(vmi_instance_t vmi, vmi_event_t *event);
char *vmi_current_name_windows(vmi_instance_t vmi, vmi_event_t *event);

#endif
