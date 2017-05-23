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

#define GFN_SHIFT(paddr) ((paddr) >> 12)
#define PADDR_SHIFT(gfn) ((gfn) << 12)

void monitor_set_trap(vmi_instance_t vmi, addr_t paddr, vmi_mem_access_t access,
                      vmi_pid_t pid, GHashTable *table, page_cat_t cat) {

    if (g_hash_table_contains(table, &paddr))
        return;

    addr_t *key = (addr_t *) malloc(sizeof(addr_t));
    *key = paddr;
    vmi_pid_t *value = (vmi_pid_t *) malloc(sizeof(vmi_pid_t));
    *value = pid;
    page_cat_t *cat_ptr = (page_cat_t *) malloc(sizeof(uint8_t));
    *cat_ptr = cat;

    vmi_set_mem_event(vmi, GFN_SHIFT(paddr), access, 0);
    g_hash_table_insert(table, key, cat_ptr);
    g_hash_table_insert(page_p2pid, key, value);
}

void monitor_trap_pt(vmi_instance_t vmi, addr_t pt, GHashTable *table, vmi_pid_t pid) {

    unsigned index;
    addr_t entry_addr;
    uint64_t entry_val;
    addr_t next_addr;

    monitor_set_trap(vmi, pt, VMI_MEMACCESS_W, pid, table, PAGE_CAT_PT);

    for (index = 0; index < PAGING_INTEL_64_MAX_ENTRIES; index++) {
        entry_addr = pt + PAGING_INTEL_64_GET_ENTRY_OFFSET(index);
        vmi_read_64_pa(vmi, entry_addr, &entry_val);
        if (!PAGING_INTEL_64_IS_PRESENT(entry_val))
            continue;
        if (PAGING_INTEL_64_IS_WRITABLE(entry_val) && PAGING_INTEL_64_IS_USERMODE(entry_val)) {
            next_addr = PAGING_INTEL_64_GET_4KB_FRAME_PADDR(entry_val);
            if (next_addr <= max_paddr)
                monitor_set_trap(vmi, next_addr, VMI_MEMACCESS_X, pid, table, PAGE_CAT_4KB_FRAME);
            continue;
        }
    }
}

void monitor_trap_pd(vmi_instance_t vmi, addr_t pd, GHashTable *table, vmi_pid_t pid) {

    unsigned index;
    addr_t entry_addr;
    uint64_t entry_val;
    addr_t next_addr;

    monitor_set_trap(vmi, pd, VMI_MEMACCESS_W, pid, table, PAGE_CAT_PD);

    for (index = 0; index < PAGING_INTEL_64_MAX_ENTRIES; index++) {
        entry_addr = pd + PAGING_INTEL_64_GET_ENTRY_OFFSET(index);
        vmi_read_64_pa(vmi, entry_addr, &entry_val);
        if (!PAGING_INTEL_64_IS_PRESENT(entry_val))
            continue;
        if (PAGING_INTEL_64_IS_FRAME_PTR(entry_val) && PAGING_INTEL_64_IS_WRITABLE(entry_val)
                && PAGING_INTEL_64_IS_USERMODE(entry_val)) {
            next_addr = PAGING_INTEL_64_GET_2MB_FRAME_PADDR(entry_val);
            if (next_addr <= max_paddr)
                monitor_set_trap(vmi, next_addr, VMI_MEMACCESS_X, pid, table, PAGE_CAT_2MB_FRAME);
            continue;
        }
        if (!PAGING_INTEL_64_IS_FRAME_PTR(entry_val)) {
            next_addr = PAGING_INTEL_64_GET_PT_PADDR(entry_val);
            if (next_addr <= max_paddr)
                monitor_trap_pt(vmi, next_addr, table, pid);
            continue;
        }
    }
}

void monitor_trap_pdpt(vmi_instance_t vmi, addr_t pdpt, GHashTable *table, vmi_pid_t pid) {

    unsigned index;
    addr_t entry_addr;
    uint64_t entry_val;
    addr_t next_addr;

    monitor_set_trap(vmi, pdpt, VMI_MEMACCESS_W, pid, table, PAGE_CAT_PDPT);

    for (index = 0; index < PAGING_INTEL_64_MAX_ENTRIES; index++) {
        entry_addr = pdpt + PAGING_INTEL_64_GET_ENTRY_OFFSET(index);
        vmi_read_64_pa(vmi, entry_addr, &entry_val);
        if (!PAGING_INTEL_64_IS_PRESENT(entry_val))
            continue;
        if (PAGING_INTEL_64_IS_FRAME_PTR(entry_val) && PAGING_INTEL_64_IS_WRITABLE(entry_val)
                && PAGING_INTEL_64_IS_USERMODE(entry_val)) {
            next_addr = PAGING_INTEL_64_GET_1GB_FRAME_PADDR(entry_val);
            if (next_addr <= max_paddr)
                monitor_set_trap(vmi, next_addr, VMI_MEMACCESS_X, pid, table, PAGE_CAT_1GB_FRAME);
            continue;
        }
        if (!PAGING_INTEL_64_IS_FRAME_PTR(entry_val)) {
            next_addr = PAGING_INTEL_64_GET_PD_PADDR(entry_val);
            if (next_addr <= max_paddr)
                monitor_trap_pd(vmi, next_addr, table, pid);
            continue;
        }
    }
}

void monitor_trap_pml4(vmi_instance_t vmi, addr_t pml4, GHashTable *table, vmi_pid_t pid) {

    unsigned index;
    addr_t entry_addr;
    uint64_t entry_val;
    addr_t next_addr;

    monitor_set_trap(vmi, pml4, VMI_MEMACCESS_W, pid, table, PAGE_CAT_PML4);

    for (index = 0; index < PAGING_INTEL_64_MAX_ENTRIES; index++) {
        entry_addr = pml4 + PAGING_INTEL_64_GET_ENTRY_OFFSET(index);
        vmi_read_64_pa(vmi, entry_addr, &entry_val);
        if (!PAGING_INTEL_64_IS_PRESENT(entry_val))
            continue;
        next_addr = PAGING_INTEL_64_GET_PDPT_PADDR(entry_val);
        if (next_addr <= max_paddr)
            monitor_trap_pdpt(vmi, next_addr, table, pid);
    }
}

void monitor_trap_table(vmi_instance_t vmi, int pid, GHashTable *table) {

    addr_t dtb;

    if (pid == 0) {
        fprintf(stderr, "ERROR: Monitor - Trapping PID 0 is not allowed\n");
        return;
    }

    dtb = vmi_pid_to_dtb(vmi, (vmi_pid_t) pid);

    if (dtb == 0) {
        fprintf(stderr, "ERROR: Monitor - Failed to find DTB for PID %d\n", pid);
        return;
    }

    monitor_trap_pml4(vmi, PAGING_INTEL_64_GET_PML4_PADDR(dtb), table, pid);
}

void queue_pending_rescan(addr_t paddr, GHashTable *cb_table, vmi_pid_t pid, page_cat_t cat) {

    pending_rescan_t *pending = (pending_rescan_t *) malloc(sizeof(pending_rescan_t));
    pending->paddr = paddr;
    pending->cb_table = cb_table;
    pending->pid = pid;
    pending->cat = cat;

    pending_page_rescan = g_slist_prepend(pending_page_rescan, pending);
}

void process_pending_rescan(gpointer data, gpointer user_data) {

    pending_rescan_t *rescan = (pending_rescan_t *) data;

    const page_cat_t cat = rescan->cat;
    switch (cat) {
        case PAGE_CAT_PML4:
            monitor_trap_pml4(monitor_vmi, rescan->paddr, rescan->cb_table, rescan->pid);
            break;
        case PAGE_CAT_PDPT:
            monitor_trap_pdpt(monitor_vmi, rescan->paddr, rescan->cb_table, rescan->pid);
            break;
        case PAGE_CAT_PD:
            monitor_trap_pd(monitor_vmi, rescan->paddr, rescan->cb_table, rescan->pid);
            break;
        case PAGE_CAT_PT:
            monitor_trap_pt(monitor_vmi, rescan->paddr, rescan->cb_table, rescan->pid);
            break;
        case PAGE_CAT_4KB_FRAME:
        case PAGE_CAT_2MB_FRAME:
        case PAGE_CAT_1GB_FRAME:
            break;
    }

    pending_page_rescan = g_slist_remove(pending_page_rescan, data);
}

event_response_t monitor_handler_ss(vmi_instance_t vmi, vmi_event_t *event) {

    g_slist_foreach(pending_page_rescan, process_pending_rescan, NULL);
    return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
}

event_response_t monitor_handler(vmi_instance_t vmi, vmi_event_t *event) {

    addr_t paddr = PADDR_SHIFT(event->mem_event.gfn);
    vmi_pid_t *pid_ptr = (vmi_pid_t *) g_hash_table_lookup(page_p2pid, &paddr);

    if (pid_ptr == NULL) {
        fprintf(stderr, "Failed to find PID for physical address 0x%lx\n", paddr);
        vmi_set_mem_event(vmi, event->mem_event.gfn, VMI_MEMACCESS_N, 0);
        return VMI_EVENT_RESPONSE_NONE;
    }

    page_cb_event_t *cb_event = (page_cb_event_t *) g_hash_table_lookup(page_cb_events, pid_ptr);

    if (cb_event == NULL) {
        fprintf(stderr, "Failed to find callback event for PID %d\n", *pid_ptr);
        vmi_set_mem_event(vmi, event->mem_event.gfn, VMI_MEMACCESS_N, 0);
        return VMI_EVENT_RESPONSE_NONE;
    }

    page_cat_t *cat_ptr = (page_cat_t *) g_hash_table_lookup(cb_event->trapped_pages, &paddr);

    if (cat_ptr == NULL) {
        fprintf(stderr, "Failed to lookup page category for physical address 0x%lx\n", paddr);
        vmi_set_mem_event(vmi, event->mem_event.gfn, VMI_MEMACCESS_N, 0);
        return VMI_EVENT_RESPONSE_NONE;
    }

    if (*cat_ptr == PAGE_CAT_4KB_FRAME || *cat_ptr == PAGE_CAT_2MB_FRAME || *cat_ptr == PAGE_CAT_1GB_FRAME) {
        if (event->mem_event.out_access & VMI_MEMACCESS_X) {
            cb_event->cb(vmi, event, *cat_ptr);
            vmi_set_mem_event(vmi, event->mem_event.gfn, VMI_MEMACCESS_W, 0);
        } else if (event->mem_event.out_access & VMI_MEMACCESS_W) {
            vmi_set_mem_event(vmi, event->mem_event.gfn, VMI_MEMACCESS_X, 0);
        } else {
            fprintf(stderr, "ERROR: Monitor - Caught unexpected memory access %d\n", event->mem_event.out_access);
            vmi_set_mem_event(vmi, event->mem_event.gfn, VMI_MEMACCESS_N, 0);
        }
        return VMI_EVENT_RESPONSE_NONE;
    } else { // page in process's page table
        queue_pending_rescan(paddr, cb_event->trapped_pages, *pid_ptr, *cat_ptr);
        return (VMI_EVENT_RESPONSE_EMULATE | VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP);
    }
}

void monitor_free_addr(gpointer data) {

    addr_t *paddr = (addr_t *) data;
    vmi_set_mem_event(monitor_vmi, GFN_SHIFT(*paddr), VMI_MEMACCESS_N, 0);
    free(data);
}

void free_page_cb_event(gpointer data) {

    page_cb_event_t *cb_event = (page_cb_event_t *) data;
    g_hash_table_destroy(cb_event->trapped_pages);
    free(data);
}

void monitor_init(vmi_instance_t vmi) {

    if (vmi_get_page_mode(vmi, 0) != VMI_PM_IA32E) {
        fprintf(stderr, "ERROR: Monitor - Only IA-32e paging is supported at this time\n");
        page_table_monitor_init = 0;
        return;
    }

    page_cb_events = g_hash_table_new_full(g_int_hash, g_int_equal, NULL, free_page_cb_event);
    page_p2pid = g_hash_table_new_full(g_int64_hash, g_int64_equal, free, free);
    pending_page_rescan = NULL;

    SETUP_MEM_EVENT(&page_table_monitor_event, 0, VMI_MEMACCESS_WX, monitor_handler, 1);
    vmi_register_event(vmi, &page_table_monitor_event);

    uint32_t vcpu_mask = (1U << vmi_get_num_vcpus(vmi)) - 1;
    SETUP_SINGLESTEP_EVENT(&page_table_monitor_ss, vcpu_mask, monitor_handler_ss, 1);
    vmi_register_event(vmi, &page_table_monitor_ss);

    max_paddr = vmi_get_max_physical_address(vmi);
    monitor_vmi = vmi;

    page_table_monitor_init = 1;
}

void monitor_destroy(vmi_instance_t vmi) {

    if (!page_table_monitor_init)
        return;

    vmi_clear_event(vmi, &page_table_monitor_event, NULL);
    vmi_clear_event(vmi, &page_table_monitor_ss, NULL);

    g_hash_table_destroy(page_cb_events);
    g_hash_table_destroy(page_p2pid);
    g_slist_free_full(pending_page_rescan, free);
    pending_page_rescan = NULL;

    page_table_monitor_init = 0;
}

void monitor_add_page_table(vmi_instance_t vmi, vmi_pid_t pid, page_table_monitor_cb_t cb) {

    if (cb == NULL) {
        fprintf(stderr, "ERROR: Monitor - Must specify callback function, cannot be null.\n");
        return;
    }

    if (!page_table_monitor_init) {
        fprintf(stderr, "ERROR: Monitor - Not initialized, cannot add page table\n");
        return;
    }

    if (g_hash_table_contains(page_cb_events, &pid)) {
        fprintf(stderr, "ERROR: Monitor - Callback already registered for PID %d\n", pid);
        return;
    }

    page_cb_event_t *cb_event = (page_cb_event_t *) malloc(sizeof(page_cb_event_t));
    cb_event->pid = pid;
    cb_event->cb = cb;
    cb_event->trapped_pages = g_hash_table_new_full(g_int64_hash, g_int64_equal, monitor_free_addr, free);

    monitor_trap_table(vmi, pid, cb_event->trapped_pages);

    g_hash_table_insert(page_cb_events, &cb_event->pid, cb_event);
}

void monitor_remove_page_table(vmi_instance_t vmi, vmi_pid_t pid) {

    if (!page_table_monitor_init) {
        fprintf(stderr, "ERROR: Monitor - Not initialized, cannot remove page table\n");
        return;
    }

    if (!g_hash_table_contains(page_cb_events, &pid)) {
        fprintf(stderr, "ERROR: Monitor - No callback registered for PID %d\n", pid);
        return;
    }

    g_hash_table_remove(page_cb_events, &pid);
}
