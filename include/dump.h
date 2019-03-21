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

#ifndef UNPACK_DUMP_H
#define UNPACK_DUMP_H

#include <pthread.h>
#include <semaphore.h>
#include <glib.h>
#include <openssl/sha.h>

#include <libvmi/libvmi.h>

pthread_t dump_worker;
char *dump_output_dir;
sem_t dump_sem;
GQueue *dump_queue;
GHashTable *pid_layer; // key: vmi_pid_t, value: uint64_t current layer
GSList *seen_hashes;

#define SEG_SIZE_MAX 100

typedef struct
{
    char *buf;
    addr_t base_va;
    size_t size;
} vad_seg_t;

typedef struct
{
    vmi_pid_t pid;
    reg_t rip;
    unsigned char sha256[SHA256_DIGEST_LENGTH];
    vad_seg_t **segments;
    unsigned segment_count;
} dump_layer_t;

/**
 * Compares two SHA256 hashes.
 *
 * @param a The first hash to compare.
 * @param b The second hash to compare.
 *
 * @return 0 if a = b, otherwise not 0.
 */
gint compare_hashes(gconstpointer a, gconstpointer b);

/**
 * Initializes all the data structures and starts a worker thread. This must be
 * called before add_to_queue() can be used.
 *
 * @param dir The director layers should be dumped into.
 */
void start_dump_thread(char *dir);

/**
 * Stops the worker thread and processes any remaining items in the queue.
 */
void stop_dump_thread();

/**
 * Addes a new layer to the queue to be dumped into the output directory.
 *
 * @param buffer A pointer to the buffer to dump. This should be left allocated
 * and the worker thread will handle freeing it.
 * @param size The size of the buffer.
 * @param pid The PID of the process that executed the page.
 * @param rip The value of the RIP register when this layer was executed.
 * @param base The base virtual address the buffer was read from.
 *
 * Note: The base_addr may not equal rip. For example, if the dump is an entire
 * VMA but the instruction that triggered the dump was somewhere in the middle.
 */
void add_to_dump_queue(char *buffer, uint64_t size, vmi_pid_t pid, reg_t rip, reg_t base);

#endif
