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

#include <stdbool.h>

#include <libvmi/libvmi.h>

#include <rekall_parser.h>
#include <vmi/process.h>

bool process_vmi_init_linux(char *rekall_filepath)
{

    if (!parse_rekall_linux(&process_vmi_linux_rekall, rekall_filepath))
    {
        fprintf(stderr, "ERROR: Process VMI - Failed to initialize Linux\n");
        return 0;
    }

    vmi_current_pid = vmi_current_pid_linux;
    vmi_current_name = vmi_current_name_linux;
    vmi_current_parent_pid = vmi_current_parent_pid_linux;
    vmi_current_find_segment = vmi_current_find_segment_linux;
    vmi_get_all_pids = NULL;

    process_vmi_ready = 1;
    return 1;
}

bool process_vmi_init_windows(char *rekall_filepath)
{

    if (!parse_rekall_windows(&process_vmi_windows_rekall, rekall_filepath))
    {
        fprintf(stderr, "ERROR: Process VMI - Failed to initialize Linux\n");
        return 0;
    }

    vmi_current_pid = vmi_current_pid_windows;
    vmi_current_name = vmi_current_name_windows;
    vmi_current_parent_pid = vmi_current_parent_pid_windows;
    vmi_current_find_segment = vmi_current_find_segment_windows;
    vmi_get_all_pids = vmi_get_all_pids_windows;

    process_vmi_ready = 1;
    return 1;
}

bool process_vmi_init(vmi_instance_t vmi, char *rekall_filepath)
{

    process_vmi_ready = 0;

    const os_t os = vmi_get_ostype(vmi);
    switch (os)
    {
        case VMI_OS_WINDOWS:
            return process_vmi_init_windows(rekall_filepath);
        case VMI_OS_LINUX:
            return process_vmi_init_linux(rekall_filepath);
        case VMI_OS_UNKNOWN:
        default:
            fprintf(stderr, "ERROR: Process VMI - Unknown OS type\n");
            return 0;
    }
}

void process_vmi_destroy()
{

    process_vmi_ready = 0;
}
