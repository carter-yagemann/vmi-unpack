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
#include <stdlib.h>
#include <stdio.h>
#include <glib.h>

#include <libvmi/libvmi.h>
#include <libvmi/events.h>

#include <monitor.h>
#include <paging/intel_64.h>
#include <vmi/process.h>

#define HIGH_ADDR_MARK 0x70000000

#define GFN_SHIFT(paddr) ((paddr) >> 12)
#define PADDR_SHIFT(gfn) ((gfn) << 12)

int check_prev_vma(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, addr_t vaddr)
{
    mem_seg_t vma = vmi_current_find_segment(vmi, event, vaddr);
    mem_seg_t *p_vma;

    if (!vma.size)
    {
        fprintf(stderr, "WARNING: Monitor - Could not find VMA for virtual address 0x%lx\n", vaddr);
        return 1;
    }

    // Heuristic - Packers like to unpack and execute dummy layers/waves to throw off unpacking tools.
    // For easy ones like what ASPack uses, we can try to read the whole VMA into a buffer and see how
    // many bytes are actually read. If it's 1 page (4KB) or less, it's probably not the real program.
    size_t dump_size;
    char *buffer = (char *) malloc(vma.size);
    vmi_read_va(vmi, vma.base_va, pid, vma.size, buffer, &dump_size);
    free(buffer);
    if (dump_size <= 0x1000)
        return 0;

    p_vma = (mem_seg_t *) g_hash_table_lookup(prev_vma, &pid);
    if (p_vma == NULL)
    {
        vmi_pid_t *pid_new = (vmi_pid_t *) malloc(sizeof(vmi_pid_t));
        mem_seg_t *vma_new = (mem_seg_t *) malloc(sizeof(mem_seg_t));
        *pid_new = pid;
        vma_new->base_va = vma.base_va;
        vma_new->size = vma.size;
        g_hash_table_insert(prev_vma, pid_new, vma_new);
        return 1;
    }

    if (vma.base_va == p_vma->base_va && vma.size == p_vma->size)
        return 0;

    p_vma->base_va = vma.base_va;
    p_vma->size = vma.size;

    return 1;
}

void monitor_set_trap(vmi_instance_t vmi, addr_t paddr, vmi_mem_access_t access, vmi_pid_t pid, page_cat_t cat)
{
    addr_t *key;
    page_cat_t *cat_ptr;
    vmi_pid_t *value;

    if (g_hash_table_contains(trapped_pages, &paddr))
        return;

    vmi_set_mem_event(vmi, GFN_SHIFT(paddr), access, 0);

    // update trapped pages hash table
    key = (addr_t *) malloc(sizeof(addr_t));
    *key = paddr;
    cat_ptr = (page_cat_t *) malloc(sizeof(uint8_t));
    *cat_ptr = cat;
    g_hash_table_insert(trapped_pages, key, cat_ptr);

    // update physical address to PID hash table
    key = (addr_t *) malloc(sizeof(addr_t));
    *key = paddr;
    value = (vmi_pid_t *) malloc(sizeof(vmi_pid_t));
    *value = pid;
    g_hash_table_insert(page_p2pid, key, value);
}

void monitor_untrap_vma(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, addr_t vaddr)
{
    addr_t end_va, curr_va, curr_pa, dtb;
    mem_seg_t vma = vmi_current_find_segment(vmi, event, vaddr);

    if (!vma.size)
    {
        fprintf(stderr, "WARNING: Monitor - Could not find VMA for virtual address 0x%lx\n", vaddr);
        vmi_set_mem_event(vmi, event->mem_event.gfn, VMI_MEMACCESS_N, 0);
        return;
    }

    // todo: vmi_pid_to_dtb if VMI_FAILURE :: clear all events for this pid
    if (vmi_pid_to_dtb(vmi, pid, &dtb) == VMI_FAILURE) {
        // clear all events for `pid`

        // remove pid from global list of pids
        g_hash_table_remove(vmi_events_by_pid, GINT_TO_POINTER(pid));

        // remove all events for pids

        // if no more pids, bail out
    }

    end_va = vma.base_va + vma.size;
    for (curr_va = vma.base_va; curr_va < end_va; curr_va += 0x1000)
        if (VMI_SUCCESS == vmi_translate_uv2p(vmi, vaddr, pid, &curr_pa))
            vmi_set_mem_event(vmi, GFN_SHIFT(curr_pa), VMI_MEMACCESS_N, 0);
}

void monitor_trap_pt(vmi_instance_t vmi, addr_t pt, vmi_pid_t pid)
{
    unsigned index;
    addr_t entry_addr;
    uint64_t entry_val;
    addr_t next_addr;

    monitor_set_trap(vmi, pt, VMI_MEMACCESS_W, pid, PAGE_CAT_PT);

    for (index = 0; index < PAGING_INTEL_64_MAX_ENTRIES; index++)
    {
        entry_addr = pt + PAGING_INTEL_64_GET_ENTRY_OFFSET(index);
        vmi_read_64_pa(vmi, entry_addr, &entry_val);
        if (!PAGING_INTEL_64_IS_PRESENT(entry_val))
            continue;
        if (PAGING_INTEL_64_IS_WRITABLE(entry_val) && PAGING_INTEL_64_IS_USERMODE(entry_val))
        {
            next_addr = PAGING_INTEL_64_GET_4KB_FRAME_PADDR(entry_val);
            if (next_addr <= max_paddr)
                monitor_set_trap(vmi, next_addr, VMI_MEMACCESS_X, pid, PAGE_CAT_4KB_FRAME);
            continue;
        }
    }
}

void monitor_trap_pd(vmi_instance_t vmi, addr_t pd, vmi_pid_t pid)
{
    unsigned index;
    addr_t entry_addr;
    uint64_t entry_val;
    addr_t next_addr;

    monitor_set_trap(vmi, pd, VMI_MEMACCESS_W, pid, PAGE_CAT_PD);

    for (index = 0; index < PAGING_INTEL_64_MAX_ENTRIES; index++)
    {
        entry_addr = pd + PAGING_INTEL_64_GET_ENTRY_OFFSET(index);
        vmi_read_64_pa(vmi, entry_addr, &entry_val);
        if (!PAGING_INTEL_64_IS_PRESENT(entry_val))
            continue;
        if (PAGING_INTEL_64_IS_FRAME_PTR(entry_val) && PAGING_INTEL_64_IS_WRITABLE(entry_val)
            && PAGING_INTEL_64_IS_USERMODE(entry_val))
        {
            next_addr = PAGING_INTEL_64_GET_2MB_FRAME_PADDR(entry_val);
            if (next_addr <= max_paddr)
                monitor_set_trap(vmi, next_addr, VMI_MEMACCESS_X, pid, PAGE_CAT_2MB_FRAME);
            continue;
        }
        if (!PAGING_INTEL_64_IS_FRAME_PTR(entry_val))
        {
            next_addr = PAGING_INTEL_64_GET_PT_PADDR(entry_val);
            if (next_addr <= max_paddr)
                monitor_trap_pt(vmi, next_addr, pid);
            continue;
        }
    }
}

void monitor_trap_pdpt(vmi_instance_t vmi, addr_t pdpt, vmi_pid_t pid)
{
    unsigned index;
    addr_t entry_addr;
    uint64_t entry_val;
    addr_t next_addr;

    monitor_set_trap(vmi, pdpt, VMI_MEMACCESS_W, pid, PAGE_CAT_PDPT);

    for (index = 0; index < PAGING_INTEL_64_MAX_ENTRIES; index++)
    {
        entry_addr = pdpt + PAGING_INTEL_64_GET_ENTRY_OFFSET(index);
        vmi_read_64_pa(vmi, entry_addr, &entry_val);
        if (!PAGING_INTEL_64_IS_PRESENT(entry_val))
            continue;
        if (PAGING_INTEL_64_IS_FRAME_PTR(entry_val) && PAGING_INTEL_64_IS_WRITABLE(entry_val)
            && PAGING_INTEL_64_IS_USERMODE(entry_val))
        {
            next_addr = PAGING_INTEL_64_GET_1GB_FRAME_PADDR(entry_val);
            if (next_addr <= max_paddr)
                monitor_set_trap(vmi, next_addr, VMI_MEMACCESS_X, pid, PAGE_CAT_1GB_FRAME);
            continue;
        }
        if (!PAGING_INTEL_64_IS_FRAME_PTR(entry_val))
        {
            next_addr = PAGING_INTEL_64_GET_PD_PADDR(entry_val);
            if (next_addr <= max_paddr)
                monitor_trap_pd(vmi, next_addr, pid);
            continue;
        }
    }
}

void monitor_trap_pml4(vmi_instance_t vmi, addr_t pml4, vmi_pid_t pid)
{
    unsigned index;
    addr_t entry_addr;
    uint64_t entry_val;
    addr_t next_addr;

    monitor_set_trap(vmi, pml4, VMI_MEMACCESS_W, pid, PAGE_CAT_PML4);

    for (index = 0; index < PAGING_INTEL_64_MAX_ENTRIES; index++)
    {
        entry_addr = pml4 + PAGING_INTEL_64_GET_ENTRY_OFFSET(index);
        vmi_read_64_pa(vmi, entry_addr, &entry_val);
        if (!PAGING_INTEL_64_IS_PRESENT(entry_val))
            continue;
        next_addr = PAGING_INTEL_64_GET_PDPT_PADDR(entry_val);
        if (next_addr <= max_paddr)
            monitor_trap_pdpt(vmi, next_addr, pid);
    }
}

void monitor_trap_table(vmi_instance_t vmi, int pid)
{
    addr_t dtb;

    if (pid == 0)
    {
        fprintf(stderr, "ERROR: Monitor - Trapping PID 0 is not allowed\n");
        return;
    }

    if (vmi_pid_to_dtb(vmi, (vmi_pid_t) pid, &dtb) == VMI_FAILURE) {
        return;
    }

    if (dtb == 0)
    {
        fprintf(stderr, "ERROR: Monitor - Failed to find DTB for PID %d\n", pid);
        return;
    }

    monitor_trap_pml4(vmi, PAGING_INTEL_64_GET_PML4_PADDR(dtb), pid);
}

void queue_pending_rescan(addr_t paddr, vmi_pid_t pid, page_cat_t cat)
{
    pending_rescan_t *pending = (pending_rescan_t *) malloc(sizeof(pending_rescan_t));
    pending->paddr = paddr;
    pending->pid   = pid;
    pending->cat   = cat;

    pending_page_rescan = g_slist_prepend(pending_page_rescan, pending);
}

void process_pending_rescan(gpointer data, gpointer user_data)
{
    pending_rescan_t *rescan = (pending_rescan_t *) data;

    const page_cat_t cat = rescan->cat;
    switch (cat)
    {
        case PAGE_CAT_PML4:
            monitor_trap_pml4(monitor_vmi, rescan->paddr, rescan->pid);
            break;
        case PAGE_CAT_PDPT:
            monitor_trap_pdpt(monitor_vmi, rescan->paddr, rescan->pid);
            break;
        case PAGE_CAT_PD:
            monitor_trap_pd(monitor_vmi, rescan->paddr, rescan->pid);
            break;
        case PAGE_CAT_PT:
            monitor_trap_pt(monitor_vmi, rescan->paddr, rescan->pid);
            break;
        case PAGE_CAT_4KB_FRAME:
        case PAGE_CAT_2MB_FRAME:
        case PAGE_CAT_1GB_FRAME:
            break;
    }

    pending_page_rescan = g_slist_remove(pending_page_rescan, data);
}

void cr3_callback_dispatcher(gpointer cb, gpointer event)
{
    ((event_callback_t)cb)(monitor_vmi, event);
}

event_response_t monitor_handler_cr3(vmi_instance_t vmi, vmi_event_t *event)
{
    // If there are any registered callbacks, invoke them
    g_slist_foreach(cr3_callbacks, cr3_callback_dispatcher, event);

    vmi_pid_t pid = vmi_current_pid(vmi, event);
    page_cb_event_t *cb_event = (page_cb_event_t *) g_hash_table_lookup(page_cb_events, &pid);

    if (cb_event != NULL)
    {
        // Check if process' page table has been replaced (e.g. execve). If it has and the callback
        // wants to follow remappings, the callback has to be registered again. Otherwise, remove
        // the callback because it's no longer valid.
        if (cb_event->cr3 != event->x86_regs->cr3)
        {
            page_table_monitor_cb_t cb = cb_event->cb;
            uint8_t cb_flags = cb_event->flags;
            monitor_remove_page_table(vmi, pid);
            if (g_hash_table_contains(vmi_events_by_pid, GINT_TO_POINTER(pid))) {
	            g_hash_table_remove(vmi_events_by_pid, GINT_TO_POINTER(pid));
	            printf("*********** REMOVED PID %d\n *****", pid);
            }

            if (cb_flags & MONITOR_FOLLOW_REMAPPING) {
	            g_hash_table_add(vmi_events_by_pid, GINT_TO_POINTER(pid));
                monitor_add_page_table(vmi, pid, cb, cb_flags);
	            printf("*********** ADDED PID %d\n *****", pid);
            }
        }

        return VMI_EVENT_RESPONSE_NONE;
    }

    // This process isn't being tracked. If its parent is a process that *is* being tracked, check
    // if the callback for that process wants to follow children and if so, register it.
    vmi_pid_t parent_pid = vmi_current_parent_pid(vmi, event);
    page_cb_event_t *parent_cb_event = (page_cb_event_t *) g_hash_table_lookup(page_cb_events, &parent_pid);

    if (parent_cb_event != NULL && (parent_cb_event->flags & MONITOR_FOLLOW_CHILDREN))
    {
        g_hash_table_add(vmi_events_by_pid, GINT_TO_POINTER(pid));
        monitor_add_page_table(vmi, pid, parent_cb_event->cb, parent_cb_event->flags);
        printf("*********** ADDED PID %d\n *****", pid);
        return VMI_EVENT_RESPONSE_NONE;
    }

    // Iterater over `vmi_events_by_pid` and check if any of our
    // watched processes have exited. If so, remove them.

    vmi_pidcache_flush(vmi);
    GHashTableIter iter;
    addr_t temp_dtb;
    gpointer key, value;
    g_hash_table_iter_init(&iter, vmi_events_by_pid);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
	    if (vmi_pid_to_dtb(vmi, GPOINTER_TO_INT(key), &temp_dtb) != VMI_SUCCESS) {
		    g_hash_table_remove(vmi_events_by_pid, key);
		    printf("****** REMOVED DEAD PROCESS ******\n");
        }
    }


    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t monitor_handler_ss(vmi_instance_t vmi, vmi_event_t *event)
{
    g_slist_foreach(pending_page_rescan, process_pending_rescan, NULL);
    return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
}

event_response_t monitor_handler(vmi_instance_t vmi, vmi_event_t *event)
{
    addr_t paddr = PADDR_SHIFT(event->mem_event.gfn);
    vmi_pid_t *pid_ptr = (vmi_pid_t *) g_hash_table_lookup(page_p2pid, &paddr);

    if (pid_ptr == NULL)
    {
        fprintf(stderr, "WARNING: Monitor - Failed to find PID for physical address 0x%lx\n", paddr);
        vmi_set_mem_event(vmi, event->mem_event.gfn, VMI_MEMACCESS_N, 0);
        return VMI_EVENT_RESPONSE_NONE;
    }

    vmi_pid_t curr_pid = vmi_current_pid(vmi, event);

    // If the PID of the current process is greater than the PID retrieved from page_p2pid,
    // most likely the page was freed and then claimed by the current process. In other
    // words, the page_p2pid value is stale.
    if (curr_pid > *pid_ptr)
    {
        if (g_hash_table_contains(page_cb_events, &curr_pid))
        {
            addr_t *new_paddr = (addr_t *) malloc(sizeof(addr_t));
            *new_paddr = paddr;

            vmi_pid_t *new_pid = (vmi_pid_t *) malloc(sizeof(vmi_pid_t));
            *new_pid = curr_pid;

            g_hash_table_insert(page_p2pid, new_paddr, new_pid);

            *pid_ptr = curr_pid;
        }
        else
        {
            vmi_set_mem_event(vmi, event->mem_event.gfn, VMI_MEMACCESS_N, 0);
            return VMI_EVENT_RESPONSE_NONE;
        }
    }

    page_cb_event_t *cb_event = (page_cb_event_t *) g_hash_table_lookup(page_cb_events, pid_ptr);

    if (cb_event == NULL)
    {
        fprintf(stderr, "WARNING: Monitor - Failed to find callback event for PID %d\n", *pid_ptr);
        vmi_set_mem_event(vmi, event->mem_event.gfn, VMI_MEMACCESS_N, 0);
        return VMI_EVENT_RESPONSE_NONE;
    }

    page_cat_t *cat_ptr = (page_cat_t *) g_hash_table_lookup(trapped_pages, &paddr);

    if (cat_ptr == NULL)
    {
        fprintf(stderr, "WARNING: Monitor - Failed to lookup page category for physical address 0x%lx\n", paddr);
        vmi_set_mem_event(vmi, event->mem_event.gfn, VMI_MEMACCESS_N, 0);
        return VMI_EVENT_RESPONSE_NONE;
    }

    if (*cat_ptr == PAGE_CAT_4KB_FRAME || *cat_ptr == PAGE_CAT_2MB_FRAME || *cat_ptr == PAGE_CAT_1GB_FRAME)
    {
        if (event->mem_event.out_access & VMI_MEMACCESS_X)
        {
            if ((cb_event->flags & MONITOR_HIGH_ADDRS) || event->mem_event.gla < HIGH_ADDR_MARK)
                if (check_prev_vma(vmi, event, *pid_ptr, event->mem_event.gla))
                    cb_event->cb(vmi, event, *pid_ptr, *cat_ptr);
            monitor_untrap_vma(vmi, event, *pid_ptr, event->mem_event.gla);
        }
        else if (event->mem_event.out_access & VMI_MEMACCESS_W)
        {
            vmi_set_mem_event(vmi, event->mem_event.gfn, VMI_MEMACCESS_X, 0);
        }
        else
        {
            fprintf(stderr, "WARNING: Monitor - Caught unexpected memory access %d\n", event->mem_event.out_access);
            vmi_set_mem_event(vmi, event->mem_event.gfn, VMI_MEMACCESS_N, 0);
        }
        return VMI_EVENT_RESPONSE_NONE;
    }
    else     // page in process's page table
    {
        queue_pending_rescan(paddr, *pid_ptr, *cat_ptr);
        return (VMI_EVENT_RESPONSE_EMULATE | VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP);
    }
}

int monitor_init(vmi_instance_t vmi)
{
    if (vmi_get_page_mode(vmi, 0) != VMI_PM_IA32E)
    {
        fprintf(stderr, "ERROR: Monitor - Only IA-32e paging is supported at this time\n");
        page_table_monitor_init = 0;
        return 1;
    }

    page_cb_events = g_hash_table_new_full(g_int_hash, g_int_equal, free, free);
    page_p2pid = g_hash_table_new_full(g_int64_hash, g_int64_equal, free, free);
    trapped_pages = g_hash_table_new_full(g_int64_hash, g_int64_equal, free, free);
    prev_vma = g_hash_table_new_full(g_int_hash, g_int_equal, free, free);
    vmi_events_by_pid = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
    pending_page_rescan = NULL;
    cr3_callbacks = NULL;

    SETUP_MEM_EVENT(&page_table_monitor_event, 0, VMI_MEMACCESS_WX, monitor_handler, 1);
    if (vmi_register_event(vmi, &page_table_monitor_event) != VMI_SUCCESS)
    {
        fprintf(stderr, "ERROR: Monitor - Failed to register page table event\n");
        page_table_monitor_init = 0;
        return 1;
    }

    uint32_t vcpu_mask = (1U << vmi_get_num_vcpus(vmi)) - 1;
    SETUP_SINGLESTEP_EVENT(&page_table_monitor_ss, vcpu_mask, monitor_handler_ss, 1);
    if (vmi_register_event(vmi, &page_table_monitor_ss) != VMI_SUCCESS)
    {
        fprintf(stderr, "ERROR: Monitor - Failed to register single step event\n");
        vmi_clear_event(vmi, &page_table_monitor_event, NULL);
        page_table_monitor_init = 0;
        return 1;
    }

    SETUP_REG_EVENT(&page_table_monitor_cr3, CR3, VMI_REGACCESS_W, 0, monitor_handler_cr3);
    if (vmi_register_event(vmi, &page_table_monitor_cr3) != VMI_SUCCESS)
    {
        fprintf(stderr, "ERROR: Monitor - Failed to register CR3 monitoring event\n");
        vmi_clear_event(vmi, &page_table_monitor_event, NULL);
        vmi_clear_event(vmi, &page_table_monitor_ss, NULL);
        page_table_monitor_init = 0;
        return 1;
    }

    max_paddr = vmi_get_max_physical_address(vmi);
    monitor_vmi = vmi;

    page_table_monitor_init = 1;

    return 0;
}

void monitor_destroy(vmi_instance_t vmi)
{
    if (!page_table_monitor_init)
        return;

    vmi_clear_event(vmi, &page_table_monitor_cr3, NULL);
    vmi_clear_event(vmi, &page_table_monitor_event, NULL);
    vmi_clear_event(vmi, &page_table_monitor_ss, NULL);

    g_hash_table_destroy(page_cb_events);
    g_hash_table_destroy(page_p2pid);
    g_hash_table_destroy(trapped_pages);
    g_hash_table_destroy(vmi_events_by_pid);

    page_table_monitor_init = 0;
}

void monitor_add_page_table(vmi_instance_t vmi, vmi_pid_t pid, page_table_monitor_cb_t cb, uint8_t flags)
{
    if (cb == NULL)
    {
        fprintf(stderr, "ERROR: Monitor - Must specify callback function, cannot be null.\n");
        return;
    }

    if (!page_table_monitor_init)
    {
        fprintf(stderr, "ERROR: Monitor - Not initialized, cannot add page table\n");
        return;
    }

    if (g_hash_table_contains(page_cb_events, &pid))
    {
        fprintf(stderr, "ERROR: Monitor - Callback already registered for PID %d\n", pid);
        return;
    }

    vmi_pid_t *cb_event_key = (vmi_pid_t *) malloc(sizeof(vmi_pid_t));
    *cb_event_key = pid;
    page_cb_event_t *cb_event = (page_cb_event_t *) malloc(sizeof(page_cb_event_t));
    cb_event->pid = pid;
    if (vmi_pid_to_dtb(vmi, pid, &cb_event->cr3) == VMI_FAILURE) {
        free(cb_event_key);
        free(cb_event);

        return;
    }
    cb_event->flags = flags;
    cb_event->cb = cb;

    monitor_trap_table(vmi, pid);

    g_hash_table_insert(page_cb_events, cb_event_key, cb_event);
}

void monitor_remove_page_table(vmi_instance_t vmi, vmi_pid_t pid)
{

    if (!page_table_monitor_init)
    {
        fprintf(stderr, "ERROR: Monitor - Not initialized, cannot remove page table\n");
        return;
    }

    if (!g_hash_table_contains(page_cb_events, &pid))
        return;

    g_hash_table_remove(page_cb_events, &pid);
}

void monitor_add_cr3(event_callback_t cb)
{
    cr3_callbacks = g_slist_prepend(cr3_callbacks, cb);
}

void monitor_remove_cr3(event_callback_t cb)
{
    cr3_callbacks = g_slist_remove(cr3_callbacks, cb);
}
