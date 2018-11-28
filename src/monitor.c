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

addr_t monitor_idx2va(table_idx_t idx)
{
    return (addr_t)((idx.pt & 0x1FF)   << 12ULL) |
           ((idx.pd & 0x1FF)   << 21ULL) |
           ((idx.pdpt & 0x1FF) << 30ULL) |
           ((idx.pml4 & 0x1FF) << 39ULL);
}

table_idx_t monitor_va2idx(addr_t vaddr)
{
    table_idx_t idx =
    {
        .pt   = ((vaddr >> 12) & 0x1FF),
        .pd   = ((vaddr >> 21) & 0x1FF),
        .pdpt = ((vaddr >> 30) & 0x1FF),
        .pml4 = ((vaddr >> 39) & 0x1FF),
    };

    return idx;
}

void monitor_set_trap(vmi_instance_t vmi, addr_t paddr, vmi_mem_access_t access,
                      vmi_pid_t pid, page_cat_t cat, table_idx_t idx, uint8_t flags)
{
    if (g_hash_table_contains(trapped_pages, &paddr))
        return;

    if (cat == PAGE_CAT_4KB_FRAME || cat == PAGE_CAT_2MB_FRAME || cat == PAGE_CAT_1GB_FRAME)
    {
        addr_t vaddr = monitor_idx2va(idx);
        if (!(flags & MONITOR_HIGH_ADDRS) && vaddr >= HIGH_ADDR_MARK)
            return;
    }

    addr_t *key = (addr_t *) malloc(sizeof(addr_t));
    *key = paddr;
    vmi_pid_t *value = (vmi_pid_t *) malloc(sizeof(vmi_pid_t));
    *value = pid;
    page_cat_t *cat_ptr = (page_cat_t *) malloc(sizeof(uint8_t));
    *cat_ptr = cat;

    vmi_set_mem_event(vmi, GFN_SHIFT(paddr), access, 0);
    g_hash_table_insert(trapped_pages, key, cat_ptr);
    g_hash_table_insert(page_p2pid, key, value);
}

void monitor_trap_pt(vmi_instance_t vmi, addr_t pt, vmi_pid_t pid, table_idx_t idx, uint8_t flags)
{
    unsigned index;
    addr_t entry_addr;
    uint64_t entry_val;
    addr_t next_addr;

    monitor_set_trap(vmi, pt, VMI_MEMACCESS_W, pid, PAGE_CAT_PT, idx, flags);

    for (index = 0; index < PAGING_INTEL_64_MAX_ENTRIES; index++)
    {
        idx.pt = index;
        entry_addr = pt + PAGING_INTEL_64_GET_ENTRY_OFFSET(index);
        vmi_read_64_pa(vmi, entry_addr, &entry_val);
        if (!PAGING_INTEL_64_IS_PRESENT(entry_val))
            continue;
        if (PAGING_INTEL_64_IS_WRITABLE(entry_val) && PAGING_INTEL_64_IS_USERMODE(entry_val))
        {
            next_addr = PAGING_INTEL_64_GET_4KB_FRAME_PADDR(entry_val);
            if (next_addr <= max_paddr)
                monitor_set_trap(vmi, next_addr, VMI_MEMACCESS_X, pid, PAGE_CAT_4KB_FRAME, idx, flags);
            continue;
        }
    }
}

void monitor_trap_pd(vmi_instance_t vmi, addr_t pd, vmi_pid_t pid, table_idx_t idx, uint8_t flags)
{
    unsigned index;
    addr_t entry_addr;
    uint64_t entry_val;
    addr_t next_addr;

    monitor_set_trap(vmi, pd, VMI_MEMACCESS_W, pid, PAGE_CAT_PD, idx, flags);

    for (index = 0; index < PAGING_INTEL_64_MAX_ENTRIES; index++)
    {
        idx.pd = index;
        entry_addr = pd + PAGING_INTEL_64_GET_ENTRY_OFFSET(index);
        vmi_read_64_pa(vmi, entry_addr, &entry_val);
        if (!PAGING_INTEL_64_IS_PRESENT(entry_val))
            continue;
        if (PAGING_INTEL_64_IS_FRAME_PTR(entry_val) && PAGING_INTEL_64_IS_WRITABLE(entry_val)
            && PAGING_INTEL_64_IS_USERMODE(entry_val))
        {
            next_addr = PAGING_INTEL_64_GET_2MB_FRAME_PADDR(entry_val);
            if (next_addr <= max_paddr)
                monitor_set_trap(vmi, next_addr, VMI_MEMACCESS_X, pid, PAGE_CAT_2MB_FRAME, idx, flags);
            continue;
        }
        if (!PAGING_INTEL_64_IS_FRAME_PTR(entry_val))
        {
            next_addr = PAGING_INTEL_64_GET_PT_PADDR(entry_val);
            if (next_addr <= max_paddr)
                monitor_trap_pt(vmi, next_addr, pid, idx, flags);
            continue;
        }
    }
}

void monitor_trap_pdpt(vmi_instance_t vmi, addr_t pdpt, vmi_pid_t pid, table_idx_t idx, uint8_t flags)
{
    unsigned index;
    addr_t entry_addr;
    uint64_t entry_val;
    addr_t next_addr;

    monitor_set_trap(vmi, pdpt, VMI_MEMACCESS_W, pid, PAGE_CAT_PDPT, idx, flags);

    for (index = 0; index < PAGING_INTEL_64_MAX_ENTRIES; index++)
    {
        idx.pdpt = index;
        entry_addr = pdpt + PAGING_INTEL_64_GET_ENTRY_OFFSET(index);
        vmi_read_64_pa(vmi, entry_addr, &entry_val);
        if (!PAGING_INTEL_64_IS_PRESENT(entry_val))
            continue;
        if (PAGING_INTEL_64_IS_FRAME_PTR(entry_val) && PAGING_INTEL_64_IS_WRITABLE(entry_val)
            && PAGING_INTEL_64_IS_USERMODE(entry_val))
        {
            next_addr = PAGING_INTEL_64_GET_1GB_FRAME_PADDR(entry_val);
            if (next_addr <= max_paddr)
                monitor_set_trap(vmi, next_addr, VMI_MEMACCESS_X, pid, PAGE_CAT_1GB_FRAME, idx, flags);
            continue;
        }
        if (!PAGING_INTEL_64_IS_FRAME_PTR(entry_val))
        {
            next_addr = PAGING_INTEL_64_GET_PD_PADDR(entry_val);
            if (next_addr <= max_paddr)
                monitor_trap_pd(vmi, next_addr, pid, idx, flags);
            continue;
        }
    }
}

void monitor_trap_pml4(vmi_instance_t vmi, addr_t pml4, vmi_pid_t pid, table_idx_t idx, uint8_t flags)
{
    unsigned index;
    addr_t entry_addr;
    uint64_t entry_val;
    addr_t next_addr;

    monitor_set_trap(vmi, pml4, VMI_MEMACCESS_W, pid, PAGE_CAT_PML4, idx, flags);

    for (index = 0; index < PAGING_INTEL_64_MAX_ENTRIES; index++)
    {
        idx.pml4 = index;
        entry_addr = pml4 + PAGING_INTEL_64_GET_ENTRY_OFFSET(index);
        vmi_read_64_pa(vmi, entry_addr, &entry_val);
        if (!PAGING_INTEL_64_IS_PRESENT(entry_val))
            continue;
        next_addr = PAGING_INTEL_64_GET_PDPT_PADDR(entry_val);
        if (next_addr <= max_paddr)
            monitor_trap_pdpt(vmi, next_addr, pid, idx, flags);
    }
}

void monitor_trap_table(vmi_instance_t vmi, int pid, uint8_t flags)
{
    addr_t dtb;
    table_idx_t idx =
    {
        .pml4 = 0,
        .pdpt = 0,
        .pd   = 0,
        .pt   = 0,
    };

    if (pid == 0)
    {
        fprintf(stderr, "ERROR: Monitor - Trapping PID 0 is not allowed\n");
        return;
    }

    vmi_pid_to_dtb(vmi, (vmi_pid_t) pid, &dtb);

    if (dtb == 0)
    {
        fprintf(stderr, "ERROR: Monitor - Failed to find DTB for PID %d\n", pid);
        return;
    }

    monitor_trap_pml4(vmi, PAGING_INTEL_64_GET_PML4_PADDR(dtb), pid, idx, flags);
}

void queue_pending_rescan(addr_t paddr, vmi_pid_t pid, page_cat_t cat, table_idx_t idx, uint8_t flags)
{
    pending_rescan_t *pending = (pending_rescan_t *) malloc(sizeof(pending_rescan_t));
    pending->paddr = paddr;
    pending->pid   = pid;
    pending->cat   = cat;
    pending->idx   = idx;
    pending->flags = flags;

    pending_page_rescan = g_slist_prepend(pending_page_rescan, pending);
}

void process_pending_rescan(gpointer data, gpointer user_data)
{
    pending_rescan_t *rescan = (pending_rescan_t *) data;

    const page_cat_t cat = rescan->cat;
    switch (cat)
    {
        case PAGE_CAT_PML4:
            monitor_trap_pml4(monitor_vmi, rescan->paddr, rescan->pid, rescan->idx, rescan->flags);
            break;
        case PAGE_CAT_PDPT:
            monitor_trap_pdpt(monitor_vmi, rescan->paddr, rescan->pid, rescan->idx, rescan->flags);
            break;
        case PAGE_CAT_PD:
            monitor_trap_pd(monitor_vmi, rescan->paddr, rescan->pid, rescan->idx, rescan->flags);
            break;
        case PAGE_CAT_PT:
            monitor_trap_pt(monitor_vmi, rescan->paddr, rescan->pid, rescan->idx, rescan->flags);
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

            if (cb_flags & MONITOR_FOLLOW_REMAPPING)
                monitor_add_page_table(vmi, pid, cb, cb_flags);
        }

        return VMI_EVENT_RESPONSE_NONE;
    }

    // This process isn't being tracked. If its parent is a process that *is* being tracked, check
    // if the callback for that process wants to follow children and if so, register it.
    vmi_pid_t parent_pid = vmi_current_parent_pid(vmi, event);
    page_cb_event_t *parent_cb_event = (page_cb_event_t *) g_hash_table_lookup(page_cb_events, &parent_pid);

    if (parent_cb_event != NULL && (parent_cb_event->flags & MONITOR_FOLLOW_CHILDREN))
    {
        monitor_add_page_table(vmi, pid, parent_cb_event->cb, parent_cb_event->flags);
        return VMI_EVENT_RESPONSE_NONE;
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
                cb_event->cb(vmi, event, *pid_ptr, *cat_ptr);
            vmi_set_mem_event(vmi, event->mem_event.gfn, VMI_MEMACCESS_N, 0);
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
        table_idx_t idx = monitor_va2idx(event->mem_event.gla);
        queue_pending_rescan(paddr, *pid_ptr, *cat_ptr, idx, cb_event->flags);
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

    page_cb_events = g_hash_table_new_full(g_int_hash, g_int_equal, NULL, NULL);
    page_p2pid = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, NULL);
    trapped_pages = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, NULL);
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
    vmi_pid_to_dtb(vmi, pid, &cb_event->cr3);
    cb_event->flags = flags;
    cb_event->cb = cb;

    monitor_trap_table(vmi, pid, flags);

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
