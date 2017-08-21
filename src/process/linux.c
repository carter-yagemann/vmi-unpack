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

addr_t linux_get_taskstruct_addr_from_pgd(vmi_instance_t vmi, addr_t pgd)
{
    addr_t list_head = 0, next_process = 0;
    addr_t task_pgd = 0;
    uint8_t width = 0;

    /*
     * First we need a pointer to the initial entry in the tasks list.
     * Note that this is task_struct->tasks, not the base addr
     * of task_struct: task_struct base = $entry - tasks_offset.
     */
    vmi_translate_ksym2v(vmi, "init_task", &next_process);
    list_head = next_process;

    width = vmi_get_address_width(vmi);

    do
    {
        addr_t ptr = 0;
        vmi_read_addr_va(vmi, next_process + process_vmi_linux_rekall.task_struct_mm, 0, &ptr);

        /*
         * task_struct->mm is NULL when Linux is executing on the behalf
         * of a task, or if the task represents a kthread. In this context,
         * task_struct->active_mm is non-NULL and we can use it as
         * a fallback. task_struct->active_mm can be found very reliably
         * at task_struct->mm + 1 pointer width
         */
        if (!ptr && width)
            vmi_read_addr_va(vmi, next_process + process_vmi_linux_rekall.task_struct_mm + width, 0, &ptr);
        vmi_read_addr_va(vmi, ptr + process_vmi_linux_rekall.mm_struct_pgd, 0, &task_pgd);

        if (VMI_SUCCESS == vmi_translate_kv2p(vmi, task_pgd, &task_pgd) &&
            task_pgd == pgd)
            return next_process;

        vmi_read_addr_va(vmi, next_process + process_vmi_linux_rekall.task_struct_tasks, 0, &next_process);
        next_process -= process_vmi_linux_rekall.task_struct_tasks;

        // If we are back at the list head, we are done.
    }
    while (list_head != next_process);

    return 0;
}

addr_t vmi_current_task_struct_linux(vmi_instance_t vmi, vmi_event_t *event)
{
    addr_t current_task = 0;

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = event->x86_regs->cr3,
        .addr = event->x86_regs->gs_base + process_vmi_linux_rekall.current_task,
    };

    // First try reading the current_task pointer
    if (vmi_read_addr(vmi, &ctx, &current_task) == VMI_FAILURE || current_task < MIN_KERNEL_BOUNDARY)
    {
        // If that fails or returns nonsense, try reading kernel stack assuming it's size is 16KB
        ctx.addr = event->x86_regs->gs_base & ~STACK_SIZE_16K;
        if (vmi_read_addr(vmi, &ctx, &current_task) == VMI_FAILURE || current_task < MIN_KERNEL_BOUNDARY)
        {
            // If we still fail, try assuming the kernel stack size is 8KB
            ctx.addr = event->x86_regs->gs_base & ~STACK_SIZE_8K;
            if (vmi_read_addr(vmi, &ctx, &current_task) == VMI_FAILURE || current_task < MIN_KERNEL_BOUNDARY)
                // As a last resort, try traversing the entire process table (VERY SLOW!)
                return linux_get_taskstruct_addr_from_pgd(vmi, event->x86_regs->cr3);
        }
    }

    return current_task;
}

vmi_pid_t vmi_current_pid_linux(vmi_instance_t vmi, vmi_event_t *event)
{
    if (!process_vmi_ready)
    {
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

char *vmi_current_name_linux(vmi_instance_t vmi, vmi_event_t *event)
{
    if (!process_vmi_ready)
    {
        fprintf(stderr, "ERROR: Linux Process VMI - Not initialized\n");
        return NULL;
    }

    addr_t task_struct = vmi_current_task_struct_linux(vmi, event);

    if (!task_struct)
        return NULL;

    return vmi_read_str_va(vmi, task_struct + process_vmi_linux_rekall.task_struct_comm, 0);
}

vmi_pid_t vmi_current_parent_pid_linux(vmi_instance_t vmi, vmi_event_t *event)
{
    if (!process_vmi_ready)
    {
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

mem_seg_t vmi_current_find_segment_linux(vmi_instance_t vmi, vmi_event_t *event, addr_t addr)
{
    mem_seg_t mem_seg =
    {
        mem_seg.base_va = 0,
        mem_seg.size = 0,
    };

    if (!process_vmi_ready)
    {
        fprintf(stderr, "ERROR: Linux Process VMI - Not initialized\n");
        return mem_seg;
    }

    addr_t task_struct = vmi_current_task_struct_linux(vmi, event);

    if (!task_struct)
    {
        fprintf(stderr, "WARNING: Linux Process VMI - Could not find current task struct\n");
        return mem_seg;
    }

    addr_t mm;
    addr_t task_struct_mm = task_struct + process_vmi_linux_rekall.task_struct_mm;
    if (vmi_read_addr_va(vmi, task_struct_mm, 0, &mm) != VMI_SUCCESS)
    {
        fprintf(stderr, "WARNING: Linux Process VMI - Could not find current memory mapping\n");
        return mem_seg;
    }

    // task_struct->mm can sometimes be NULL (e.g. some kernel worker threads).
    if (!mm)
    {
        fprintf(stderr, "WARNING: Linux Process VMI - Current memory mapping is NULL\n");
        return mem_seg;
    }

    addr_t vma;
    addr_t mm_struct_mmap = mm + process_vmi_linux_rekall.mm_struct_mmap;
    if (vmi_read_addr_va(vmi, mm_struct_mmap, 0, &vma) != VMI_SUCCESS)
    {
        fprintf(stderr, "WARNING: Linux Process VMI - Could not find root VMA\n");
        return mem_seg;
    }

    // vma is now a pointer to the current process' first virtual memory area.
    // Iterate through the VMAs looking for the one the provided addr belongs to.
    while (vma)
    {
        addr_t start, end;
        addr_t vma_start = vma + process_vmi_linux_rekall.vm_area_struct_vm_start;
        addr_t vma_end = vma + process_vmi_linux_rekall.vm_area_struct_vm_end;

        if (vmi_read_addr_va(vmi, vma_start, 0, &start) != VMI_SUCCESS)
            return mem_seg;

        if (vmi_read_addr_va(vmi, vma_end, 0, &end) != VMI_SUCCESS)
            return mem_seg;

        if (addr >= start && addr <= end)
        {
            mem_seg.base_va = start;
            mem_seg.size = end - start;
            return mem_seg;
        }

        addr_t vma_next = vma + process_vmi_linux_rekall.vm_area_struct_vm_next;
        if (vmi_read_addr_va(vmi, vma_next, 0, &vma) != VMI_SUCCESS)
            return mem_seg;
    }

    return mem_seg; // no match found
}
