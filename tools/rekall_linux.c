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

#include <rekall_parser.h>

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("%s <json_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    linux_rekall_t rekall;
    if (!parse_rekall_linux(&rekall, argv[1]))
    {
        printf("Failed to parse rekall file\n");
    }
    else
    {
        printf("current_thread = %ld, comm = %ld, pid = %ld parent = %ld, mm = %ld tasks = %ld\n",
               rekall.current_task, rekall.task_struct_comm, rekall.task_struct_pid,
               rekall.task_struct_parent, rekall.task_struct_mm, rekall.task_struct_tasks);
        printf("mmap = %ld, vm_start = %ld, vm_end = %ld, vm_next = %ld pgd = %ld\n",
               rekall.mm_struct_mmap, rekall.vm_area_struct_vm_start,
               rekall.vm_area_struct_vm_end, rekall.vm_area_struct_vm_next, rekall.mm_struct_pgd);
    }

    return EXIT_SUCCESS;
}
