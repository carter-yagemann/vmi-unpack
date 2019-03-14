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

// these are private to this source file
static addr_t PsInitialSystemProcess = 0;
static addr_t get_initial_system_process(vmi_instance_t vmi) {
  if (PsInitialSystemProcess == 0)
    vmi_read_addr_ksym(vmi, "PsInitialSystemProcess", &PsInitialSystemProcess);
  return PsInitialSystemProcess;
}

addr_t vmi_current_thread_windows(vmi_instance_t vmi, vmi_event_t *event)
{
    addr_t thread;
    addr_t prcb;
    addr_t currentthread;

    if (vmi_get_page_mode(vmi, event->vcpu_id) != VMI_PM_IA32E)
    {
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

addr_t windows_find_eprocess_pgd(vmi_instance_t vmi, addr_t pgd)
{
    addr_t list_head, next_process, pdbase;
    addr_t pdbase_offset = process_vmi_windows_rekall.kprocess_pdbase;
    addr_t tasks_offset = process_vmi_windows_rekall.eprocess_tasks;

    list_head = get_initial_system_process(vmi);
    if (!list_head)
        return 0;

    if (vmi_read_addr_va(vmi, list_head + tasks_offset, 0, &next_process) != VMI_SUCCESS)
        return 0;

    if (vmi_read_addr_va(vmi, list_head + pdbase_offset, 0, &pdbase) != VMI_SUCCESS)
        return 0;

    if (pdbase == pgd)
        return 0; // TODO - Correctly return a pointer to PsInitialSystemProcess

    list_head = next_process;

    while (1)
    {
        addr_t tmp_next;

        if (vmi_read_addr_va(vmi, next_process, 0, &tmp_next) != VMI_SUCCESS)
            return 0;

        if (list_head == tmp_next)
            return 0;

        if (vmi_read_addr_va(vmi, next_process + pdbase_offset - tasks_offset, 0, &pdbase) != VMI_SUCCESS)
            return 0;

        if (pdbase == pgd)
            return next_process - tasks_offset;

        next_process = tmp_next;
    }

    return 0;
}

//all_pids is a set(int) of all the running pids from pslist walk
//a set(type) is just a GHashTable where keys are assigned but not values
//using g_hash_table_add(table, key);
//
//the caller must free the returned table with g_hash_table_destroy(table);
GHashTable* vmi_get_all_pids_windows(vmi_instance_t vmi) {
  vmi_pid_t pid;  //current pid
  addr_t init_proc;  //ptr to eprocess of initial system process
  addr_t eprocess;  //ptr to eprocess of current walked process
  addr_t next_eprocess_list;  //ptr to eprocess's next_process ptr
  addr_t tasks_offset = process_vmi_windows_rekall.eprocess_tasks;

  init_proc = get_initial_system_process(vmi);
  if (vmi_read_addr_va(vmi, init_proc, 0, &eprocess) != VMI_SUCCESS)
        return NULL;
  init_proc = eprocess;

  GHashTable* all_pids = g_hash_table_new(g_direct_hash, g_direct_equal);
  while (1) {
    addr_t pid_ptr = eprocess + process_vmi_windows_rekall.eprocess_pid;
    if (vmi_read_32_va(vmi, pid_ptr, 0, (uint32_t *) &pid) == VMI_SUCCESS) {
      g_hash_table_add(all_pids, GINT_TO_POINTER(pid));
    }
    //else //skip this pid
    //  log_some_warning("failed to read pid from eprocess")

    if (vmi_read_addr_va(vmi, eprocess + tasks_offset, 0, &next_eprocess_list) != VMI_SUCCESS) {
      g_hash_table_destroy(all_pids);
      return NULL;
    }
    eprocess = next_eprocess_list - tasks_offset;
    if (eprocess == init_proc)
      break;
  }
  return all_pids;
}

addr_t vmi_current_process_windows(vmi_instance_t vmi, vmi_event_t *event)
{
    addr_t process;
    addr_t thread = vmi_current_thread_windows(vmi, event);

    // If we can't find the current process the fast way, fall back to the slower
    // but more reliable windows_find_eprocess_pgd.
    if (!thread)
        return windows_find_eprocess_pgd(vmi, event->x86_regs->cr3);

    addr_t kthread = thread + process_vmi_windows_rekall.kthread_process;
    if (vmi_read_addr_va(vmi, kthread, 0, &process) != VMI_SUCCESS)
        return windows_find_eprocess_pgd(vmi, event->x86_regs->cr3);

    return process;
}

vmi_pid_t vmi_current_pid_windows(vmi_instance_t vmi, vmi_event_t *event)
{
    if (!process_vmi_ready)
    {
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

char *vmi_current_name_windows(vmi_instance_t vmi, vmi_event_t *event)
{
    if (!process_vmi_ready)
    {
        fprintf(stderr, "ERROR: Windows Process VMI - Not initialized\n");
        return NULL;
    }

    addr_t process = vmi_current_process_windows(vmi, event);

    if (!process)
        return NULL;

    addr_t eprocess_pname = process + process_vmi_windows_rekall.eprocess_pname;

    return vmi_read_str_va(vmi, eprocess_pname, 0);
}

vmi_pid_t vmi_current_parent_pid_windows(vmi_instance_t vmi, vmi_event_t *event)
{
    if (!process_vmi_ready)
    {
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

mem_seg_t vmi_current_find_segment_windows(vmi_instance_t vmi, vmi_event_t *event, addr_t addr)
{
    mem_seg_t mem_seg =
    {
        mem_seg.base_va = 0,
        mem_seg.size = 0,
    };

    if (!process_vmi_ready)
    {
        fprintf(stderr, "ERROR: Windows Process VMI - Not initialized\n");
        return mem_seg;
    }

    addr_t process = vmi_current_process_windows(vmi, event);

    if (!process)
    {
        fprintf(stderr, "WARNING: Windows Process VMI - Could not find current process\n");
        return mem_seg;
    }

    // Windows tracks memory mappings using Virtual Address Descriptors (VADs), which serves the
    // same purpose of Linux's virtual memory areas (VMAs). VADs are organized as a balanced binary
    // tree starting with the root VAD.
    //
    // For more information, see: http://lilxam.tuxfamily.org/blog/?p=326&lang=en
    addr_t curr_vad;
    addr_t eprocess_vadroot = process + process_vmi_windows_rekall.eprocess_vadroot;

    if (vmi_read_addr_va(vmi, eprocess_vadroot, 0, &curr_vad) != VMI_SUCCESS)
    {
        fprintf(stderr, "WARNING: Windows Process VMI - Could not find root VAD\n");
        return mem_seg;
    }
    // root VAD is an _EX_FAST_REF, so the 3 least significant bits are a reference counter.
    curr_vad &= 0xFFFFFFFFFFFFFFF8;

    while (1)
    {
        // Get the starting virtual address for this VAD.
        addr_t startingvpn;
        addr_t mmvad_startingvpn = curr_vad + process_vmi_windows_rekall.mmvad_startingvpn;
        if (vmi_read_addr_va(vmi, mmvad_startingvpn, 0, &startingvpn) != VMI_SUCCESS)
            return mem_seg;
        startingvpn <<= 12; // virtual page number << 12 (4KB per page) = virtual address

        // If the address we're trying to find is less than startingvpn, we need to check the left
        // child of the current VAD.
        if (addr < startingvpn)
        {
            addr_t mmvad_leftchild = curr_vad + process_vmi_windows_rekall.mmvad_leftchild;
            if (vmi_read_addr_va(vmi, mmvad_leftchild, 0, &curr_vad) != VMI_SUCCESS)
                return mem_seg;

            if (!curr_vad)
                return mem_seg;

            continue;
        }

        // Get the ending virtual address for this VAD.
        addr_t endingvpn;
        addr_t mmvad_endingvpn = curr_vad + process_vmi_windows_rekall.mmvad_endingvpn;
        if (vmi_read_addr_va(vmi, mmvad_endingvpn, 0, &endingvpn) != VMI_SUCCESS)
            return mem_seg;
        endingvpn <<= 12;

        // If the address we're looking for is less than or equal to endingvpn, we've found our VAD.
        // (We've already confirmed that the address is greater than or equal to startingvpn).
        if (addr < endingvpn)
        {
            mem_seg.base_va = startingvpn;
            mem_seg.size = endingvpn - startingvpn;
            return mem_seg;
        }

        // The address we're looking for is greater than endingvpn, we need to check the right child.
        addr_t mmvad_rightchild = curr_vad + process_vmi_windows_rekall.mmvad_rightchild;
        if (vmi_read_addr_va(vmi, mmvad_rightchild, 0, &curr_vad) != VMI_SUCCESS)
            return mem_seg;

        if (!curr_vad)
            return mem_seg;
    }

    return mem_seg;
}
