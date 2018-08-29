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
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <semaphore.h>
#include <glib.h>
#include <openssl/sha.h>

#include <libvmi/libvmi.h>

#include <dump.h>

#define LAYER_FILENAME_LEN 128

gint compare_hashes(gconstpointer a, gconstpointer b)
{
    int pos;
    unsigned char *a_ptr, *b_ptr;

    a_ptr = (unsigned char *) a;
    b_ptr = (unsigned char *) b;

    for (pos = 0; pos < SHA256_DIGEST_LENGTH; pos++)
        if (a_ptr[pos] != b_ptr[pos])
            return 1;

    return 0;
}

char *gen_layer_filename(dump_layer_t *dump_layer)
{
    uint64_t *layer_ptr;
    vmi_pid_t pid = dump_layer->pid;
    reg_t rip = dump_layer->rip;
    reg_t base_addr = dump_layer->base;
    int dir_len = strlen(dump_output_dir);

    if (!g_hash_table_contains(pid_layer, &pid))
    {
        vmi_pid_t *pid_ptr = (vmi_pid_t *) malloc(sizeof(vmi_pid_t));
        *pid_ptr = pid;
        layer_ptr = (uint64_t *) malloc(sizeof(uint64_t));
        *layer_ptr = 0;
        g_hash_table_insert(pid_layer, pid_ptr, layer_ptr);
    }

    layer_ptr = (uint64_t *) g_hash_table_lookup(pid_layer, &pid);

    // format: <output_dir>/<pid>-<layer>-<base_addr>-<rip>.bin\0
    char *filename = (char *) malloc(dir_len + LAYER_FILENAME_LEN);
    snprintf(filename, LAYER_FILENAME_LEN, "%s%010d-%016lx-%016lx-%016lx.bin",
             dump_output_dir, pid, *layer_ptr, base_addr, rip);

    (*layer_ptr)++;

    return filename;
}

void *dump_worker_loop(void *data)
{
    dump_layer_t *layer;
    FILE *ofile;
    unsigned char *hash;
    char *filename;

    while (1)
    {

        sem_wait(&dump_sem);

        layer = (dump_layer_t *) g_queue_pop_head(dump_queue);

        if (layer->pid == 0 && layer->buff == NULL)
        {
            free(layer);
            break; // signal to stop
        }

        // Only dump the layer if we haven't seen the hash before
        filename = gen_layer_filename(layer);
        if (!g_slist_find_custom(seen_hashes, layer->sha256, compare_hashes))
        {
            ofile = fopen(filename, "wb");
            fwrite(layer->buff, sizeof(char), layer->size, ofile);
            fclose(ofile);
            // add hash to seen_hashes
            hash = (unsigned char *) malloc(SHA256_DIGEST_LENGTH);
            memcpy(hash, layer->sha256, SHA256_DIGEST_LENGTH);
            seen_hashes = g_slist_prepend(seen_hashes, hash);
        }

        free(filename);
        free(layer->buff);
        free(layer);
    }

    return NULL;
}

void start_dump_thread(char *dir)
{
    if (dir == NULL)
    {
        fprintf(stderr, "ERROR: Dump Thread - Cannot start thread with an output dir of NULL\n");
        return;
    }

    // Make copy of output dir string (malloc extra space in case we need to append a trailing '/')
    dump_output_dir = (char *) malloc(strlen(dir) + 2);
    strcpy(dump_output_dir, dir);
    int tail = strlen(dump_output_dir);
    if (dump_output_dir[tail - 1] != '/')
    {
        dump_output_dir[tail] = '/';
        dump_output_dir[tail + 1] = '\0';
    }

    // Create semaphore, queue, and hashtable
    if (sem_init(&dump_sem, 0, 0))
    {
        fprintf(stderr, "ERROR: Dump Thread - Failed to initialize semaphore\n");
        return;
    }
    dump_queue = g_queue_new();
    pid_layer = g_hash_table_new_full(g_int_hash, g_int_equal, free, free);
    seen_hashes = NULL;

    // Start worker thread
    pthread_create(&dump_worker, NULL, dump_worker_loop, NULL);
}

void stop_dump_thread()
{
    // Signal the worker that we're done by adding an empty item to its queue
    add_to_dump_queue(NULL, 0, 0, 0, 0);

    pthread_join(dump_worker, NULL);

    free(dump_output_dir);
    sem_destroy(&dump_sem);
    g_queue_free(dump_queue);
    g_hash_table_destroy(pid_layer);
    g_slist_free_full(seen_hashes, free);
}

void add_to_dump_queue(char *buffer, uint64_t size, vmi_pid_t pid, reg_t rip, reg_t base)
{
    dump_layer_t *layer;

    if (!buffer || !size)
        return;  // Don't dump empty layers!

    layer = (dump_layer_t *) malloc(sizeof(dump_layer_t));
    layer->pid = pid;
    layer->rip = rip;
    layer->base = base;
    layer->buff = buffer;
    layer->size = size;
    SHA256((unsigned char *) buffer, size, layer->sha256);
    g_queue_push_tail(dump_queue, layer);

    sem_post(&dump_sem);
}
