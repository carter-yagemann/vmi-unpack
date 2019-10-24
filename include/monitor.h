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

#ifndef PAGING_MONITOR_H
#define PAGING_MONITOR_H

#include <stdbool.h>
#include <glib.h>

#include <libvmi/libvmi.h>
#include <libvmi/events.h>

#include <vmi/process.h>

addr_t max_paddr;
bool page_table_monitor_init;
vmi_event_t page_table_monitor_event;
vmi_event_t page_table_monitor_ss;
vmi_event_t page_table_monitor_cr3;
GHashTable *trapped_pages;     // key: addr_t, value: page_attr_t
GHashTable *cr3_to_pid;        // key: reg_t, value: vmi_pid_t
GHashTable *prev_vma;          // key: vmi_pid_t, value: prev_vma_t
GHashTable *vmi_events_by_pid; // key: vmi_pid_t, value: pid_events_t
GSList *pending_page_rescan;   // queue of table rescans
GSList *pending_page_retrap;   // queue of userspace retraps
GSList *cr3_callbacks;         // list of CR3 write callbacks

typedef struct
{
    mem_seg_t vma;
    addr_t paddr;
} prev_vma_t;

typedef enum
{
    PAGE_CAT_NOT_SET,
    PAGE_CAT_PML4,
    PAGE_CAT_PDPT,
    PAGE_CAT_PD,
    PAGE_CAT_PT,
    PAGE_CAT_4KB_FRAME,  // non-page table pages
    PAGE_CAT_2MB_FRAME,
    PAGE_CAT_1GB_FRAME,
} page_cat_t;

#define is_pagetable_page(cat) (\
                                cat == PAGE_CAT_PML4 ||\
                                cat == PAGE_CAT_PDPT ||\
                                cat == PAGE_CAT_PD ||\
                                cat == PAGE_CAT_PT)

#define is_userspace_page(cat) (\
                                cat == PAGE_CAT_4KB_FRAME ||\
                                cat == PAGE_CAT_2MB_FRAME ||\
                                cat == PAGE_CAT_1GB_FRAME)

static inline const char *cat2str(page_cat_t cat)
{
    static const char *catname[] =
    {
        "PAGE_CAT_NOT_SET",
        "PAGE_CAT_PML4",
        "PAGE_CAT_PDPT",
        "PAGE_CAT_PD",
        "PAGE_CAT_PT",
        "PAGE_CAT_4KB_FRAME",
        "PAGE_CAT_2MB_FRAME",
        "PAGE_CAT_1GB_FRAME",
    };
    return catname[cat];
}

static inline const char *access2str(vmi_event_t *evt)
{
    if (evt->mem_event.out_access & VMI_MEMACCESS_X)
        return "VMI_MEMACCESS_X";
    if (evt->mem_event.out_access & VMI_MEMACCESS_W)
        return "VMI_MEMACCESS_W";
    return "VMI_MEMACCESS_UNKNOWN";
}

// args: vmi, event, pid, page category
typedef void (*page_table_monitor_cb_t)(vmi_instance_t, vmi_event_t *, vmi_pid_t, page_cat_t);

typedef struct
{
    addr_t paddr;
    vmi_pid_t pid;
    page_cat_t cat;
    vmi_mem_access_t access;
} pending_rescan_t;

typedef struct
{
    vmi_instance_t vmi;   //to avoid needing a global vmi handle
    vmi_event_t *event;   //some things need the event
    GSList **list;        //some thing iterate a GSList
    gpointer data;        //one extra pointer for anything else
} foreach_data_t;

typedef struct
{
    vmi_pid_t pid;
    char *process_name;
    reg_t cr3;
    uint8_t flags;
    page_table_monitor_cb_t cb;
    GHashTable *write_exec_map;
    GHashTable *wr_traps;
} pid_events_t;

typedef struct
{
    vmi_pid_t pid;
    page_cat_t cat;
} trapped_page_t;

#ifdef TRACE_TRAPS
#define trace_trap(addr, trap, mesg) fprintf(stderr, \
        "%s:trace_trap paddr=%p pid=%d cat=%s mesg=%s\n", \
        __FUNCTION__, (gpointer)addr, trap->pid, cat2str(trap->cat), mesg)
#else
#define trace_trap(addr, trap, mesg)
#endif

typedef struct
{
    vmi_pid_t pid;
    reg_t cr3;
    uint8_t flags;
    page_table_monitor_cb_t cb;
} page_cb_event_t;

pid_events_t *add_new_pid(vmi_pid_t pid);

/**
 * Initializes the page table monitor.
 *
 * @param vmi a libVMI instance
 *
 * @return 0 on success, not 0 otherwise.
 */
int monitor_init(vmi_instance_t vmi);

/**
 * Destroys the page table monitor.
 *
 * @param vmi a libVMI instance
 */
void monitor_destroy(vmi_instance_t vmi);

/**
 * Registers a callback function that will be invoked every time a new page is
 * created for a particular PID. Note that only one callback can be registered
 * per PID at a time.
 *
 * @param vmi a libVMI instance
 * @param pid a PID to monitor
 * @param cb a function to invoke when new pages are created
 * @param optional flags:
 *
 *     MONITOR_FOLLOW_REMAPPING - If this flag is set, the monitor will continue to track the process
 *                                even if its page table is changed (i.e. PID is the same but CR3 is
 *                                modified). Linux's execve is an example of how this can happen.
 *
 *     MONITOR_FOLLOW_CHILDREN  - If this flag is set, the monitor will also track children created
 *                                by the process.
 *
 *     MONITOR_HIGH_ADDRS       - If this flag is set, the monitor will track pages mapped to virtual
 *                                addresses above 0x70000000. These pages are ignored by default because
 *                                they typically belong to libraries, heap and stack, which is not
 *                                relevant to capturing most packers.
 *
 * @param cr3 if not NULL, use this for new PIDs cr3
 */
void monitor_add_page_table(vmi_instance_t vmi, vmi_pid_t pid, page_table_monitor_cb_t cb, uint8_t flags, reg_t cr3);

#define MONITOR_FOLLOW_REMAPPING (1U << 0)
#define MONITOR_FOLLOW_CHILDREN  (1U << 1)
#define MONITOR_HIGH_ADDRS       (1U << 2)

/**
 * Removes a registered callback.
 *
 * @param vmi a libVMI instance
 * @param pid a PID
 */
void monitor_remove_page_table(vmi_instance_t vmi, vmi_pid_t pid);

/**
 * Registers a CR3 callback.
 *
 * LibVMI only allows one CR3 write event to be registered at a time.
 * The monitor needs such an event, so other callbacks of this type
 * cannot be registered once the monitor is initialized. This method
 * allows others to still get CR3 write events, although in a
 * restricted manner. Specifically, the reponse returned by the
 * callback will be ignored.
 *
 * @param cb a libVMI event callback
 */
void monitor_add_cr3(event_callback_t cb);

/**
 * Removes a previously registered CR3 write callback.
 *
 * @param cb a libVMI event callback
 */
void monitor_remove_cr3(event_callback_t cb);

#endif
