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
#include <openssl/crypto.h>

#include <libvmi/libvmi.h>

#include <dump.h>

#define LAYER_FILENAME_LEN 128
#define LAYER_FILENAME_PREFIX_LEN 4

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

char *gen_layer_filename(dump_layer_t *dump_layer, int dump_count)
{
    char *filename = calloc(LAYER_FILENAME_PREFIX_LEN + (SHA256_DIGEST_LENGTH * 2) + 1, sizeof(char));
    char prefix[LAYER_FILENAME_PREFIX_LEN+1];
    prefix[LAYER_FILENAME_PREFIX_LEN] = 0x0;
    sprintf(prefix, "%%0%dd.", LAYER_FILENAME_PREFIX_LEN-1);
    sprintf(filename, prefix, dump_count);
    char *offset = filename + LAYER_FILENAME_PREFIX_LEN;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(offset+(i*2), "%x", dump_layer->sha256[i]);
    }
    filename[LAYER_FILENAME_PREFIX_LEN + (SHA256_DIGEST_LENGTH * 2)] = 0x0;
    return filename;
}

void free_layer(dump_layer_t *layer) {
    if (layer) {
        if(layer->segments) {
            for(int i = 0; i < layer->segment_count; i++) {
                free(layer->segments[i]);
            }
            free(layer->segments);
        }
        free(layer);
    }
}

void *dump_worker_loop(void *data)
{
    dump_layer_t *layer;
    FILE *ofile;
    unsigned char *hash;
    char *filename;
    static int dump_count = 0;

    while (1)
    {

        sem_wait(&dump_sem);

        layer = (dump_layer_t *) g_queue_pop_head(dump_queue);

        if (!layer)
        {
            break; // signal to stop
        }

        // Only dump the layer if we haven't seen the hash before
        filename = gen_layer_filename(layer, dump_count);
        printf("dump_worker_loop: considering dump of %s\n", filename);
        if (!g_slist_find_custom(seen_hashes, layer->sha256, compare_hashes))
        {
            printf("dump_worker_loop: starting dump of %s\n", filename);
            ofile = fopen(filename, "wb");
            for (int i = 0; i < layer->segment_count; i++) {
                fwrite(layer->segments[i]->buf,
                       sizeof(char),
                       layer->segments[i]->size,
                       ofile);
            }
            fclose(ofile);
            // add hash to seen_hashes
            hash = (unsigned char *) malloc(SHA256_DIGEST_LENGTH);
            memcpy(hash, layer->sha256, SHA256_DIGEST_LENGTH);
            seen_hashes = g_slist_prepend(seen_hashes, hash);
            printf("dump_worker_loop: finished dump of %s\n", filename);
        }

        free(filename);
        free_layer(layer);
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

void add_eod()
{
    dump_layer_t *layer = NULL;
    g_queue_push_tail(dump_queue, layer);

    sem_post(&dump_sem);
}

void stop_dump_thread()
{
    add_eod();  // Signals dump worker to quit

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
    layer->segment_count = 1;
    layer->segments = malloc(sizeof(vad_seg_t) * 1);
    layer->segments[0]->base_va = base;
    layer->segments[0]->buf = buffer;
    layer->segments[0]->size = size;

    SHA256_CTX c;
    SHA256_Init(&c);
    for (int i = 0; i < layer->segment_count; i++) {
        SHA256_Update(&c,
                      (unsigned char *)layer->segments[i]->buf,
                      layer->segments[i]->size);
    }
    SHA256_Final(layer->sha256, &c);
    OPENSSL_cleanse(&c, sizeof(c));
    g_queue_push_tail(dump_queue, layer);

    sem_post(&dump_sem);
}
