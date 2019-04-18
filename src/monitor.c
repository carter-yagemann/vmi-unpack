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
#define KERNEL_MARK    (1UL << 63)

#define GFN_SHIFT(paddr) ((paddr) >> 12)
#define PADDR_SHIFT(gfn) ((gfn) << 12)

int check_prev_vma(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, addr_t vaddr, addr_t paddr)
{
    mem_seg_t vma = vmi_current_find_segment(vmi, event, vaddr);
    prev_vma_t *p_vma;

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

    p_vma = (prev_vma_t *) g_hash_table_lookup(prev_vma, &pid);
    if (p_vma == NULL)
    {
        vmi_pid_t *pid_new = (vmi_pid_t *) malloc(sizeof(vmi_pid_t));
        prev_vma_t *vma_new = (prev_vma_t *) malloc(sizeof(prev_vma_t));
        *pid_new = pid;
        vma_new->vma.base_va = vma.base_va;
        vma_new->vma.size = vma.size;
        vma_new->paddr = paddr;
        g_hash_table_insert(prev_vma, pid_new, vma_new);
        return 1;
    }

    if (vma.base_va == p_vma->vma.base_va && vma.size == p_vma->vma.size)
        return 0;

    p_vma->vma.base_va = vma.base_va;
    p_vma->vma.size = vma.size;

    return 1;
}

// maintain global trapped_pages hash and set memory traps
void monitor_set_trap(vmi_instance_t vmi, addr_t paddr, vmi_mem_access_t access, vmi_pid_t pid, page_cat_t cat)
{
    trapped_page_t *trap = g_hash_table_lookup(trapped_pages, (gpointer)paddr);

    if (!trap) {
      trap = g_slice_new(trapped_page_t);
      trap->pid = pid;
      trap->cat = cat;
      g_hash_table_insert(trapped_pages, (gpointer)paddr, trap);
      vmi_set_mem_event(vmi, GFN_SHIFT(paddr), access, 0);
      pid_events_t *my_pid_events = g_hash_table_lookup(vmi_events_by_pid, GINT_TO_POINTER(pid));
      if (my_pid_events)
        g_hash_table_add(my_pid_events->wr_traps, (gpointer)paddr);
      trace_trap(paddr, trap, "new trap");
    }
}

// remove entries from global trapped_pages hash and remove memory traps
void monitor_unset_trap(vmi_instance_t vmi, addr_t paddr)
{
    vmi_set_mem_event(vmi, GFN_SHIFT(paddr), VMI_MEMACCESS_N, 0);
    trapped_page_t *trap = g_hash_table_lookup(trapped_pages, (gpointer)paddr);
    if (trap) {
      pid_events_t *my_pid_events = g_hash_table_lookup(vmi_events_by_pid, GINT_TO_POINTER(trap->pid));
      if (my_pid_events)
        g_hash_table_remove(my_pid_events->wr_traps, (gpointer)paddr);
    }
    g_hash_table_remove(trapped_pages, (gpointer)paddr);
}

// after a page that has been written to has also been executed,
// we "untrap" it by setting all pages in that VMA back to VMI_MEMACCESS_N
void monitor_untrap_vma(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, mem_seg_t vma)
{
    GHashTable *exec_map;
    pid_events_t *my_pid_events;

    if (!vma.size)
    {
        fprintf(stderr, "WARNING: monitor_untrap_vma - Could not find VMA for virtual address 0x%lx\n", event->mem_event.gla);
        return;
    }

    my_pid_events = g_hash_table_lookup(vmi_events_by_pid, GINT_TO_POINTER(pid));
    if (!my_pid_events) {
      fprintf(stderr, "WARNING: monitor_untrap_vma - Could not find PID %d\n", pid);
      return;
    }
    exec_map = g_hash_table_lookup(my_pid_events->write_exec_map, (gpointer)vma.base_va);
    if (!exec_map) {
	    fprintf(stderr, "WARNING: monitor_untrap_vma - Could not find exec_map for pid %d\n", pid);
      return;
    }
    fprintf(stderr, "monitor_untrap_vma: pid=%d, base_va=0x%lx, paddr=0x%lx\n",
        pid, vma.base_va, PADDR_SHIFT(event->mem_event.gfn));
    guint num_pages = 0;
    gpointer *pages = g_hash_table_get_keys_as_array(exec_map, &num_pages);
    if (pages)
      for (int i = 0; i < num_pages; i++)
        // performance optimization, we might miss some (W->X->W->X) patterns on the same page, but alternative is very slow
        vmi_set_mem_event(vmi, (addr_t)pages[i], VMI_MEMACCESS_N, 0);
    g_free(pages);
    g_hash_table_remove(my_pid_events->write_exec_map, (gpointer)vma.base_va);
}

// a page belonging to the PID has been written to. place an
// "execute" trap on that page with VMI_MEMACCESS_X
void monitor_trap_vma(vmi_instance_t vmi, vmi_event_t *event, vmi_pid_t pid, mem_seg_t vma)
{
  if (!vma.size) {
    fprintf(stderr, "WARNING:%s-Could not find VMA: vaddr=0x%lx paddr=0x%lx\n",
    __FUNCTION__, event->mem_event.gla, PADDR_SHIFT(event->mem_event.gfn));
    return;
  }
  if (vma.base_va >= KERNEL_MARK)
  {
    fprintf(stderr, "WARNING: monitor_trap_vma - Tried to trap kernel pages, request ignored\n");
    return;
  }
  pid_events_t *my_pid_events = g_hash_table_lookup(vmi_events_by_pid, GINT_TO_POINTER(pid));
  if (my_pid_events) {
    GHashTable *exec_map = g_hash_table_lookup(my_pid_events->write_exec_map, (gpointer)vma.base_va);
    if (!exec_map) {
      exec_map = g_hash_table_new(g_direct_hash, g_direct_equal);
      g_hash_table_insert(my_pid_events->write_exec_map, (gpointer)vma.base_va, exec_map);
    }
    if (!g_hash_table_contains(exec_map, (gpointer)event->mem_event.gfn)) {
      fprintf(stderr, "monitor_trap_vma: %d, base_va=0x%lx, paddr=0x%lx\n",
          pid, vma.base_va, PADDR_SHIFT(event->mem_event.gfn));
      g_hash_table_add(exec_map, (gpointer)event->mem_event.gfn);
      vmi_set_mem_event(vmi, event->mem_event.gfn, VMI_MEMACCESS_X, 0);
    }
  }
}

void destroy_trapped_page(gpointer val) { g_slice_free(trapped_page_t, val); }

//called by g_hash_table_destroy() when g_hash_table_new_full() is used
void destroy_watched_pid(gpointer val) {
  g_hash_table_destroy(((pid_events_t *)val)->write_exec_map);
  g_hash_table_destroy(((pid_events_t *)val)->wr_traps);
  g_slice_free(pid_events_t, val);
}

pid_events_t* add_new_pid(vmi_pid_t pid) {
  pid_events_t* pval = g_hash_table_lookup(vmi_events_by_pid, GINT_TO_POINTER(pid));
  if (pval)
    //skip if the pid already exists
    return pval;
  pval = g_slice_new(pid_events_t);
  pval->pid = pid;
  pval->write_exec_map = g_hash_table_new_full(g_direct_hash, g_direct_equal,
    NULL, (GDestroyNotify)g_hash_table_destroy);
  pval->wr_traps = g_hash_table_new_full(g_direct_hash, g_direct_equal,
    NULL, NULL);
  g_hash_table_insert(vmi_events_by_pid, GINT_TO_POINTER(pid), pval);
  return pval;
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
                monitor_set_trap(vmi, next_addr, VMI_MEMACCESS_W, pid, PAGE_CAT_4KB_FRAME);
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
                monitor_set_trap(vmi, next_addr, VMI_MEMACCESS_W, pid, PAGE_CAT_2MB_FRAME);
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
                monitor_set_trap(vmi, next_addr, VMI_MEMACCESS_W, pid, PAGE_CAT_1GB_FRAME);
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

void monitor_trap_table(vmi_instance_t vmi, pid_events_t *pid_event)
{
    addr_t dtb = PAGING_INTEL_64_GET_PML4_PADDR(pid_event->cr3);

    if (pid_event->pid == 0)
    {
        fprintf(stderr, "ERROR: Monitor - Trapping PID 0 is not allowed\n");
        return;
    }

    if (dtb == 0)
    {
        fprintf(stderr, "ERROR: Monitor - Failed to find DTB for PID %d\n", pid_event->pid);
        return;
    }

    monitor_trap_pml4(vmi, dtb, pid_event->pid);
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

    //fprintf(stderr, "%s: paddr=0x%lx pid=%d cat=%s\n",
    //    __FUNCTION__, rescan->paddr, rescan->pid, cat2str(rescan->cat));
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
        case PAGE_CAT_NOT_SET:
            break;
    }

    pending_page_rescan = g_slist_remove(pending_page_rescan, data);
    free(data);
}

void cr3_callback_dispatcher(gpointer cb, gpointer event)
{
    ((event_callback_t)cb)(monitor_vmi, event);
}

void print_events_by_pid(void) {
  GHashTableIter iter;
  gpointer key, value;
  g_hash_table_iter_init(&iter, vmi_events_by_pid);
  while (g_hash_table_iter_next(&iter, &key, &value)) {
    vmi_pid_t pid = GPOINTER_TO_INT(key);
    pid_events_t *pid_event = value;
    fprintf(stderr, "%s: events_by_pid, pid=%d cr3=0x%lx\n", __FUNCTION__, pid, pid_event->cr3);
  }
}

void print_cr3_to_pid(void) {
  GHashTableIter iter;
  gpointer key, value;
  g_hash_table_iter_init(&iter, cr3_to_pid);
  while (g_hash_table_iter_next(&iter, &key, &value)) {
    reg_t cr3 = (long)key;
    vmi_pid_t pid = GPOINTER_TO_INT(value);
    fprintf(stderr, "%s: cr3_to_pid, pid=%d cr3=0x%lx\n", __FUNCTION__, pid, cr3);
  }
}

void vmi_list_all_processes_windows(vmi_instance_t vmi, vmi_event_t *event);
event_response_t monitor_handler_cr3(vmi_instance_t vmi, vmi_event_t *event)
{
    //bail out right away if monitoring is not started or is now off
    if (!page_table_monitor_init)
      return VMI_EVENT_RESPONSE_NONE;

    // If there are any registered callbacks, invoke them
    g_slist_foreach(cr3_callbacks, cr3_callback_dispatcher, event);

    vmi_pid_t pid = vmi_current_pid(vmi, event);
    pid_events_t *pid_event = g_hash_table_lookup(vmi_events_by_pid, GINT_TO_POINTER(pid));
    reg_t evt_cr3 = event->x86_regs->cr3;

    //bail out right away if the cr3 is one that we track
    if (g_hash_table_contains(cr3_to_pid, (gpointer)evt_cr3)) {
      vmi_pid_t cr3_pid = GPOINTER_TO_INT(g_hash_table_lookup(cr3_to_pid, (gpointer)evt_cr3));
      //but before we bail, trap its page table once it executes the first time
      if (cr3_pid == 0) {
        if (pid_event) {
          //addr_t rip_pa = 0;
          //vmi_v2pcache_flush(vmi, evt_cr3);
          //vmi_pagetable_lookup(vmi, evt_cr3, event->x86_regs->rip, &rip_pa);
          fprintf(stderr, "%s: trapping table, pid=%d evt_cr3=0x%lx\n", __FUNCTION__, pid, evt_cr3);
          g_hash_table_insert(cr3_to_pid, (gpointer)event->x86_regs->cr3, GINT_TO_POINTER(pid));
          monitor_trap_table(vmi, pid_event);
        } else {
          //print_events_by_pid();
          //print_cr3_to_pid();
          //vmi_list_all_processes_windows(vmi, event);
        }
      }
      return VMI_EVENT_RESPONSE_NONE;
    }

    //bail out right away if we already track this PID
    if (pid_event) {
      return VMI_EVENT_RESPONSE_NONE;
    }

    // This process isn't being tracked. If its parent is a process that *is* being tracked, check
    // if the callback for that process wants to follow children and if so, register it.
    vmi_pid_t parent_pid = vmi_current_parent_pid(vmi, event);
    pid_events_t *parent_cb_event = g_hash_table_lookup(vmi_events_by_pid, GINT_TO_POINTER(parent_pid));

    if (parent_cb_event != NULL && (parent_cb_event->flags & MONITOR_FOLLOW_CHILDREN))
    {
        monitor_add_page_table(vmi, pid, parent_cb_event->cb, parent_cb_event->flags, 0);
        fprintf(stderr, "*********** FOUND CHILD: PID %d *****\n", pid);
        return VMI_EVENT_RESPONSE_NONE;
    }

    // Iterater over `vmi_events_by_pid` and check if any of our
    // watched processes have exited. If so, remove them.

    GHashTable *all_pids = vmi_get_all_pids(vmi);
    if (!all_pids)
      return VMI_EVENT_RESPONSE_NONE;
    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, vmi_events_by_pid);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
      vmi_pid_t pid = GPOINTER_TO_INT(key);
      if (!g_hash_table_contains(all_pids, key)) {
        monitor_remove_page_table(vmi, pid);
        fprintf(stderr, "****** REMOVED DEAD PROCESS: %d ******\n", pid);
      }
    }
    g_hash_table_destroy(all_pids);

    return VMI_EVENT_RESPONSE_NONE;
}

event_response_t monitor_handler_ss(vmi_instance_t vmi, vmi_event_t *event)
{
    g_slist_foreach(pending_page_rescan, process_pending_rescan, NULL);
    return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
}

event_response_t monitor_handler(vmi_instance_t vmi, vmi_event_t *event)
{
    vmi_pid_t pid;
    pid_events_t *my_pid_events;
    const size_t len = 80;
    char mesg[len];
    char *curr_name;

    //bail out right away if monitoring is not started or is now off
    if (!page_table_monitor_init)
      return VMI_EVENT_RESPONSE_NONE;

    addr_t paddr = PADDR_SHIFT(event->mem_event.gfn);
    trapped_page_t *trap = g_hash_table_lookup(trapped_pages, (gpointer)paddr);

    if (trap == NULL)
    {
        fprintf(stderr, "WARNING: Monitor - Failed to find PID for physical address 0x%lx\n", paddr);
        trace_trap(paddr, trap, "trap not found");
        monitor_unset_trap(vmi, paddr);
        return VMI_EVENT_RESPONSE_NONE;
    }

    pid = trap->pid;
    vmi_pid_t curr_pid = vmi_current_pid(vmi, event);

    //printf("monitor_handler:recv_event rip=%p paddr=%p cat=%s access=%s curr_pid=%d\n",
    //    (void *) event->x86_regs->rip, (void *) paddr, cat2str(trap->cat), access2str(event), curr_pid);

    // If the PID of the current process is not equal to the PID retrieved from trapped_pages, then:
    // 1, a system process is changing our PIDs pagetable. ignore.
    // 2, its an execve() and our PID is being replaced. update trap->pid.
    // 3, since we dont keep track of when our PIDs pagetable shrinks, its possible
    //    that the page belongs to some other PID and not us. forget the page.
    // 5, some other PID that we dont track accessed, write or exec, a userspace page that 
    //    our PID currently has in its pagetable. WTF!
    // 6, trapped_pages had the page, but we dont care about it. forget the page.
    if (curr_pid != pid && !is_pagetable_page(trap->cat))
    {
      if (g_hash_table_contains(vmi_events_by_pid, GINT_TO_POINTER(curr_pid))) {
        curr_name = vmi_current_name(vmi, event);
        snprintf(mesg, len-1, "=pid_change curr_name=%s curr_pid=%d access=%s",
            curr_name, curr_pid, access2str(event));
        free(curr_name);
        trace_trap(paddr, trap, mesg);
        pid = trap->pid = curr_pid;
      } else {
        //it is possible that the PID we are watching no longer has this page anymore
        my_pid_events = g_hash_table_lookup(vmi_events_by_pid, GINT_TO_POINTER(pid));
        if (my_pid_events) {
          addr_t page;
          vmi_v2pcache_flush(vmi, my_pid_events->cr3);
          status_t s = vmi_pagetable_lookup(vmi, my_pid_events->cr3, event->mem_event.gla, &page);
          if (s != VMI_SUCCESS) {
            //our PID no longer has this page
            monitor_unset_trap(vmi, paddr);
            return VMI_EVENT_RESPONSE_NONE;
          } else {
            //our PID has this page and some other PID accessed it as W or X
            curr_name = vmi_current_name(vmi, event);
            snprintf(mesg, len-1, "=unknown_pid curr_name=%s curr_pid=%d access=%s",
                curr_name, curr_pid, access2str(event));
            free(curr_name);
            trace_trap(paddr, trap, mesg);
            monitor_unset_trap(vmi, paddr);
            return VMI_EVENT_RESPONSE_NONE;
          }
        } else {
          //trapped_pages has this page, but we dont care about it. forget it.
          trace_trap(paddr, trap, "forget this");
          monitor_unset_trap(vmi, paddr);
          return VMI_EVENT_RESPONSE_NONE;
        }
      }
    }

    my_pid_events = g_hash_table_lookup(vmi_events_by_pid, GINT_TO_POINTER(pid));
    if (my_pid_events == NULL)
    {
        fprintf(stderr, "WARNING: Monitor - Failed to find callback event for PID %d\n", pid);
        monitor_unset_trap(vmi, paddr);
        return VMI_EVENT_RESPONSE_NONE;
    }

    if (is_userspace_page(trap->cat))
    {
      mem_seg_t vma = vmi_current_find_segment(vmi, event, event->mem_event.gla);
      if (!vma.size) {
        char mesg[] = "%s:VMA not found"
          ":pid=%d:curr_pid=%d"
          ":pid_cr3=0x%lx:event_cr3=0x%lx"
          ":pt_lookup,pid_pa=0x%lx,evt_pa=0x%lx"
          ":evt_vaddr=0x%lx:evt_paddr=0x%lx"
          "\n";
        addr_t pid_pa = 0, evt_pa = 0;

        vmi_v2pcache_flush(vmi, my_pid_events->cr3);
        vmi_pagetable_lookup(vmi, my_pid_events->cr3, event->mem_event.gla, &pid_pa);
        vmi_v2pcache_flush(vmi, event->x86_regs->cr3);
        vmi_pagetable_lookup(vmi, event->x86_regs->cr3, event->mem_event.gla, &evt_pa);
        fprintf(stderr, mesg, __FUNCTION__,
            pid, curr_pid,
            my_pid_events->cr3, event->x86_regs->cr3,
            pid_pa, evt_pa,
            event->mem_event.gla, paddr
            );

        // write traps are only set by monitor_set_trap() and exec by monitor_trap_vma()
        if (event->mem_event.out_access & VMI_MEMACCESS_W)
            monitor_unset_trap(vmi, paddr);
        else if (event->mem_event.out_access & VMI_MEMACCESS_X) {
            vma = vmi_current_find_segment(vmi, event, event->mem_event.gla);
            monitor_untrap_vma(vmi, event, pid, vma);
        }
        return VMI_EVENT_RESPONSE_NONE;
      }
      if (event->mem_event.out_access & VMI_MEMACCESS_X)
      {
        if ((my_pid_events->flags & MONITOR_HIGH_ADDRS) || event->mem_event.gla < HIGH_ADDR_MARK)
          if (check_prev_vma(vmi, event, pid, event->mem_event.gla, paddr))
            my_pid_events->cb(vmi, event, pid, trap->cat);
        monitor_untrap_vma(vmi, event, pid, vma);
      }
      else if (event->mem_event.out_access & VMI_MEMACCESS_W)
      {
        monitor_trap_vma(vmi, event, pid, vma);
      }
      else
      {
        fprintf(stderr, "WARNING: Monitor - Caught unexpected memory access %d\n", event->mem_event.out_access);
        monitor_unset_trap(vmi, paddr);
      }
      return VMI_EVENT_RESPONSE_NONE;
    }
    else     // page in process's page table
    {
      //fprintf(stderr, "%s: paddr=0x%lx pid=%d cat=%s access=%s curr_pid=%d\n",
      //    __FUNCTION__, paddr, pid, cat2str(trap->cat), access2str(event), curr_pid);
      queue_pending_rescan(paddr, pid, trap->cat);
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

    trapped_pages = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, destroy_trapped_page);
    cr3_to_pid = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
    prev_vma = g_hash_table_new_full(g_int_hash, g_int_equal, free, free);
    vmi_events_by_pid = g_hash_table_new_full(g_direct_hash, g_direct_equal,
        NULL, destroy_watched_pid);
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
    fprintf(stderr, "monitor_destroy() called\n");
    if (!page_table_monitor_init)
        return;

    vmi_clear_event(vmi, &page_table_monitor_cr3, NULL);
    vmi_clear_event(vmi, &page_table_monitor_event, NULL);
    vmi_clear_event(vmi, &page_table_monitor_ss, NULL);
    fprintf(stderr, "monitor_destroy() events cleared\n");

    g_hash_table_destroy(trapped_pages);
    g_hash_table_destroy(cr3_to_pid);
    g_hash_table_destroy(vmi_events_by_pid);
    g_slist_free_full(pending_page_rescan, free);

    page_table_monitor_init = 0;
}

void monitor_add_page_table(vmi_instance_t vmi, vmi_pid_t pid, page_table_monitor_cb_t cb, uint8_t flags, reg_t cr3)
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

    if (g_hash_table_contains(vmi_events_by_pid, GINT_TO_POINTER(pid)))
    {
        fprintf(stderr, "ERROR: Monitor - Callback already registered for PID %d\n", pid);
        return;
    }

    pid_events_t *pid_event = add_new_pid(pid);
    if (cr3 == 0) {
      vmi_pidcache_flush(vmi);
      if (vmi_pid_to_dtb(vmi, pid, &pid_event->cr3) == VMI_FAILURE) {
        g_hash_table_remove(vmi_events_by_pid, GINT_TO_POINTER(pid));
        return;
      }
    } else pid_event->cr3 = cr3;
    pid_event->flags = flags;
    pid_event->cb = cb;
    //set the pid to 0 as a flag that its page table has not been scanned yet
    //then delay trapping its page table until it first executes
    g_hash_table_insert(cr3_to_pid, (gpointer)pid_event->cr3, 0);
    fprintf(stderr, "%s: pid=%d cr3=0x%lx\n", __FUNCTION__, pid, pid_event->cr3);

    //monitor_trap_table(vmi, pid_event);
}

void monitor_remove_page_table(vmi_instance_t vmi, vmi_pid_t pid)
{
    pid_events_t *my_pid_events;

    if (!page_table_monitor_init)
    {
        fprintf(stderr, "ERROR: Monitor - Not initialized, cannot remove page table\n");
        return;
    }

    fprintf(stderr, "%s: pid=%d\n", __FUNCTION__, pid);
    my_pid_events = g_hash_table_lookup(vmi_events_by_pid, GINT_TO_POINTER(pid));
    if (my_pid_events) {
      //remove from cr3_to_pid before my_pid_events gets destroyed
      g_hash_table_remove(cr3_to_pid, (gpointer)my_pid_events->cr3);
      int i;
      //clear userspace traps
      GHashTableIter iter;
      gpointer base_va, exec_map;
      g_hash_table_iter_init(&iter, my_pid_events->write_exec_map);
      while (g_hash_table_iter_next(&iter, &base_va, &exec_map)) {
        guint num_pages = 0;
        gpointer *pages = g_hash_table_get_keys_as_array(exec_map, &num_pages);
          if (pages) {
            for (i = 0; i < num_pages; i++)
              monitor_unset_trap(vmi, PADDR_SHIFT((addr_t)pages[i]));
            g_free(pages);
          }
      }
      //clear write traps
      guint num_entries = 0;
      gpointer *entries = g_hash_table_get_keys_as_array(my_pid_events->wr_traps, &num_entries);
      if (entries) {
        for (i = 0; i < num_entries; i++)
          monitor_unset_trap(vmi, (addr_t)entries[i]);
        g_free(entries);
      }
      g_hash_table_remove(vmi_events_by_pid, GINT_TO_POINTER(pid));
    }
}

void monitor_add_cr3(event_callback_t cb)
{
    cr3_callbacks = g_slist_prepend(cr3_callbacks, cb);
}

void monitor_remove_cr3(event_callback_t cb)
{
    cr3_callbacks = g_slist_remove(cr3_callbacks, cb);
}
