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

#include <libvmi/libvmi.h>

#include <paging/intel_64.h>

void walk_pt(vmi_instance_t vmi, addr_t pt)
{

    unsigned index;
    addr_t entry_addr;
    uint64_t entry_val;

    for (index = 0; index < PAGING_INTEL_64_MAX_ENTRIES; index++)
    {
        entry_addr = pt + PAGING_INTEL_64_GET_ENTRY_OFFSET(index);
        vmi_read_64_pa(vmi, entry_addr, &entry_val);
        if (!PAGING_INTEL_64_IS_PRESENT(entry_val))
            continue;
        if (!PAGING_INTEL_64_IS_USERMODE(entry_val))
            continue;
        printf("4KB @paddr 0x%lx\n", PAGING_INTEL_64_GET_4KB_FRAME_PADDR(entry_addr));
    }
}

void walk_pd(vmi_instance_t vmi, addr_t pd)
{

    unsigned index;
    addr_t entry_addr;
    uint64_t entry_val;

    for (index = 0; index < PAGING_INTEL_64_MAX_ENTRIES; index++)
    {
        entry_addr = pd + PAGING_INTEL_64_GET_ENTRY_OFFSET(index);
        vmi_read_64_pa(vmi, entry_addr, &entry_val);
        if (!PAGING_INTEL_64_IS_PRESENT(entry_val))
            continue;
        if (!PAGING_INTEL_64_IS_USERMODE(entry_val))
            continue;
        if (PAGING_INTEL_64_IS_FRAME_PTR(entry_val))
        {
            printf("2MB @paddr 0x%lx\n", PAGING_INTEL_64_GET_2MB_FRAME_PADDR(entry_addr));
        }
        else
        {
            walk_pt(vmi, PAGING_INTEL_64_GET_PT_PADDR(entry_val));
        }
    }
}

void walk_pdpt(vmi_instance_t vmi, addr_t pdpt)
{

    unsigned index;
    addr_t entry_addr;
    uint64_t entry_val;

    for (index = 0; index < PAGING_INTEL_64_MAX_ENTRIES; index++)
    {
        entry_addr = pdpt + PAGING_INTEL_64_GET_ENTRY_OFFSET(index);
        vmi_read_64_pa(vmi, entry_addr, &entry_val);
        if (!PAGING_INTEL_64_IS_PRESENT(entry_val))
            continue;
        if (!PAGING_INTEL_64_IS_USERMODE(entry_val))
            continue;
        if (PAGING_INTEL_64_IS_FRAME_PTR(entry_val))
        {
            printf("1GB @paddr 0x%lx\n", PAGING_INTEL_64_GET_1GB_FRAME_PADDR(entry_addr));
        }
        else
        {
            walk_pd(vmi, PAGING_INTEL_64_GET_PD_PADDR(entry_val));
        }
    }
}

void walk_pml4(vmi_instance_t vmi, int pid)
{

    addr_t dtb;
    uint64_t pml4;
    unsigned index;
    addr_t entry_addr;
    uint64_t entry_val;

    vmi_pid_to_dtb(vmi, (vmi_pid_t) pid, &dtb);

    // PML4
    pml4 = PAGING_INTEL_64_GET_PML4_PADDR(dtb);
    for (index = 0; index < PAGING_INTEL_64_MAX_ENTRIES; index++)
    {
        entry_addr = pml4 + PAGING_INTEL_64_GET_ENTRY_OFFSET(index);
        vmi_read_64_pa(vmi, entry_addr, &entry_val);
        if (PAGING_INTEL_64_IS_PRESENT(entry_val) && !PAGING_INTEL_64_IS_FRAME_PTR(entry_val))
            walk_pdpt(vmi, PAGING_INTEL_64_GET_PDPT_PADDR(entry_val));
    }
}

/**
 * Walks the page table for a given process in a given guest VM and prints out
 * the mapped physical addresses that belong to user mode.
 */
int main(int argc, char *argv[])
{

    if (argc < 3)
    {
        printf("%s <domain_name> <pid>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Initialize libVMI
    vmi_instance_t vmi;
    if (vmi_init_complete(&vmi, argv[1], VMI_INIT_DOMAINNAME, NULL,
                          VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL) == VMI_FAILURE)
    {
        printf("ERROR: Failed to initialize libVMI.\n");
        if (vmi != NULL)
        {
            vmi_destroy(vmi);
        }
        return EXIT_FAILURE;
    }

    vmi_pause_vm(vmi);
    walk_pml4(vmi, atoi(argv[2]));
    vmi_resume_vm(vmi);

    vmi_destroy(vmi);
    return EXIT_SUCCESS;
}
