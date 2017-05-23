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

addr_t max_paddr;
bool page_table_monitor_init;
vmi_instance_t monitor_vmi;
vmi_event_t page_table_monitor_event;
vmi_event_t page_table_monitor_ss;
GHashTable *page_cb_events; // key: vmi_pid_t, value: page_cb_event_t
GHashTable *page_p2pid; // key: addr_t (4KB aligned), value: vmi_pid_t
GSList *pending_page_rescan; // queue of table rescans

typedef enum {
    PAGE_CAT_PML4,
    PAGE_CAT_PDPT,
    PAGE_CAT_PD,
    PAGE_CAT_PT,
    PAGE_CAT_4KB_FRAME,  // non-page table pages
    PAGE_CAT_2MB_FRAME,
    PAGE_CAT_1GB_FRAME,
} page_cat_t;

// args: vmi, event, page category
typedef void (*page_table_monitor_cb_t)(vmi_instance_t,vmi_event_t*,page_cat_t);

typedef struct {
    addr_t paddr;
    GHashTable *cb_table;
    vmi_pid_t pid;
    page_cat_t cat;
} pending_rescan_t;

typedef struct {
    vmi_pid_t pid;
    page_table_monitor_cb_t cb;
    GHashTable *trapped_pages; // key: addr_t, value: uint8_t (page type)
} page_cb_event_t;

/**
 * Initializes the page table monitor.
 *
 * @param vmi a libVMI instance
 */
void monitor_init(vmi_instance_t vmi);

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
 * @param filter only invoke cb when the new page matches this filter
 */
void monitor_add_page_table(vmi_instance_t vmi, vmi_pid_t pid, page_table_monitor_cb_t cb);

/**
 * Removes a registered callback.
 *
 * @param vmi a libVMI instance
 * @param pid a PID
 */
void monitor_remove_page_table(vmi_instance_t vmi, vmi_pid_t pid);

#endif
