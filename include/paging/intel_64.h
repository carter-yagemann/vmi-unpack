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

#ifndef PAGING_INTEL_64_H
#define PAGING_INTEL_64_H

#include <stdbool.h>
#include <inttypes.h>

/* General Table Entry Macros */
#define PAGING_INTEL_64_MAX_ENTRIES 512U
#define PAGING_INTEL_64_GET_ENTRY_OFFSET(index) (index * 8)

#define PAGING_INTEL_64_IS_PRESENT(entry) (entry & 0x1)
#define PAGING_INTEL_64_IS_WRITABLE(entry) (entry & 0x2)
#define PAGING_INTEL_64_IS_USERMODE(entry) (entry & 0x4)
#define PAGING_INTEL_64_IS_FRAME_PTR(entry) (entry & 0x80)
#define PAGING_INTEL_64_IS_EXECUTABLE(entry) (entry & 0x8000000000000000)

/* PML4 Pointer Specific (normally CR3) */
#define PAGING_INTEL_64_GET_PML4_PADDR(pml4p) (pml4p & 0xFFFFFFFFFF000)
/* PML4 Specific */
#define PAGING_INTEL_64_GET_PDPT_PADDR(pml4e) (pml4e & 0xFFFFFFFFFF000)

/* PDPT Specific */
#define PAGING_INTEL_64_GET_PD_PADDR(pdpte) (pdpte & 0xFFFFFFFFFF000)
#define PAGING_INTEL_64_GET_1GB_FRAME_PADDR(pdpte) (pdpte & 0xFFFFF40000000)

/* PD Specific */
#define PAGING_INTEL_64_GET_PT_PADDR(pde) (pde & 0xFFFFFFFFFF000)
#define PAGING_INTEL_64_GET_2MB_FRAME_PADDR(pde) (pde & 0xFFFFFFFE00000)

/* PT Specific */
#define PAGING_INTEL_64_GET_4KB_FRAME_PADDR(pte) (pte & 0xFFFFFFFFFF000)

#endif
