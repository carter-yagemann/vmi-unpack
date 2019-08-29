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
#include <string.h>
#include <unistd.h>
#include <CUnit/Basic.h>

#include <rekall_parser.h>
#include <dump.h>

/* REKALL */

char *linux_rekall_fp = "test/inputs/linux-rekall-example.json";
char *windows_rekall_fp = "test/inputs/windows-rekall-example.json";

int init_rekall_suite()
{
    if (access(linux_rekall_fp, R_OK) == -1)
    {
        printf("ERROR: Cannot read %s!\n", linux_rekall_fp);
        return -1;
    }
    if (access(windows_rekall_fp, R_OK) == -1)
    {
        printf("ERROR: Cannot read %s!\n", windows_rekall_fp);
        return -1;
    }
    return 0;
}

void test_linux_rekall()
{
    linux_rekall_t rekall;
    CU_ASSERT(parse_rekall_linux(&rekall, linux_rekall_fp) == 1);
    CU_ASSERT(rekall.current_task == 47232);
    CU_ASSERT(rekall.task_struct_comm == 1264);
    CU_ASSERT(rekall.task_struct_pid == 820);
    CU_ASSERT(rekall.task_struct_parent == 840);
    CU_ASSERT(rekall.task_struct_mm == 720);
    CU_ASSERT(rekall.task_struct_tasks == 640);
    CU_ASSERT(rekall.mm_struct_mmap == 0);
    CU_ASSERT(rekall.vm_area_struct_vm_start == 0);
    CU_ASSERT(rekall.vm_area_struct_vm_end == 8);
    CU_ASSERT(rekall.vm_area_struct_vm_next == 16);
    CU_ASSERT(rekall.mm_struct_pgd == 64);
}

void test_windows_rekall()
{
    windows_rekall_t rekall;
    CU_ASSERT(parse_rekall_windows(&rekall, windows_rekall_fp) == 1);
    CU_ASSERT(rekall.kprocess_pdbase == 40);
    CU_ASSERT(rekall.kpcr_prcb == 384);
    CU_ASSERT(rekall.kprcb_currentthread == 8);
    CU_ASSERT(rekall.kthread_process == 528);
    CU_ASSERT(rekall.eprocess_pname == 736);
    CU_ASSERT(rekall.eprocess_pid == 384);
    CU_ASSERT(rekall.eprocess_parent_pid == 656);
    CU_ASSERT(rekall.eprocess_vadroot == 1096);
    CU_ASSERT(rekall.eprocess_objecttable == 512);
    CU_ASSERT(rekall.eprocess_peb == 824);
    CU_ASSERT(rekall.mmvad_leftchild == 8);
    CU_ASSERT(rekall.mmvad_rightchild == 16);
    CU_ASSERT(rekall.mmvad_startingvpn == 24);
    CU_ASSERT(rekall.mmvad_endingvpn == 32);
    CU_ASSERT(rekall.mmvad_controlarea == 72);
    CU_ASSERT(rekall.controlarea_fileobject == 64);
    CU_ASSERT(rekall.fileobject_filename == 88);
    CU_ASSERT(rekall.mmvad_flags == 40);
    CU_ASSERT(rekall.mmvad_flags_sizeof == 8);
    CU_ASSERT(rekall.flags_vadtype_start == 52);
    CU_ASSERT(rekall.flags_vadtype_end == 55);
    CU_ASSERT(rekall.flags_isprivate_start == 63);
    CU_ASSERT(rekall.flags_isprivate_end == 64);
    CU_ASSERT(rekall.flags_protection_start == 56);
    CU_ASSERT(rekall.flags_protection_end == 61);
    CU_ASSERT(rekall.peb_imagebaseaddress == 16);
}

/* DUMP */

void test_compare_hashes_dump()
{
    // hash_a == hash_b != hash_c != hash_d
    unsigned char hash_a[] = "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD";
    unsigned char hash_b[] = "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD";
    unsigned char hash_c[] = "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDI";
    unsigned char hash_d[] = "IAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD";

    CU_ASSERT(compare_hashes(hash_a, hash_b) == 0);
    CU_ASSERT(compare_hashes(hash_b, hash_c) != 0);
    CU_ASSERT(compare_hashes(hash_b, hash_d) != 0);
}

int main(int argc, char *argv[])
{
    unsigned int fails;
    CU_pSuite pSuiteRekall = NULL;
    CU_pSuite pSuiteDump = NULL;

    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    // Rekall

    pSuiteRekall = CU_add_suite("Suite_Rekall", init_rekall_suite, NULL);
    if (!pSuiteRekall)
    {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if (!CU_add_test(pSuiteRekall, "test linux rekall", test_linux_rekall) ||
        !CU_add_test(pSuiteRekall, "test windows rekall", test_windows_rekall))
    {
        CU_cleanup_registry();
        return CU_get_error();
    }

    // Dump

    pSuiteDump = CU_add_suite("Suite_Dump", NULL, NULL);
    if (!pSuiteDump)
    {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if (!CU_add_test(pSuiteDump, "test compare hashes dump", test_compare_hashes_dump))
    {
        CU_cleanup_registry();
        return CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_NORMAL);
    CU_basic_run_tests();
    fails = CU_get_number_of_tests_failed();
    CU_cleanup_registry();
    if (fails > 0)
        return -1;
    return 0;
}
