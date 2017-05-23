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

#include <rekall_parser.h>

int main(int argc, char *argv[]) {

    if (argc < 2) {
        printf("%s <json_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    windows_rekall_t rekall;
    if (!parse_rekall_windows(&rekall, argv[1])) {
        printf("Failed to parse rekall file\n");
    } else {
        printf("kprc_prcb = %ld, kpcr_currentthread = %ld, kthread_process = %ld, eprocess_pname = %ld, eprocess_pid = %ld\n",
                rekall.kpcr_prcb, rekall.kprcb_currentthread, rekall.kthread_process, rekall.eprocess_pname,
                rekall.eprocess_pid);
    }

    return EXIT_SUCCESS;
}
