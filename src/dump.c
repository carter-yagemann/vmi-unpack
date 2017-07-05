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

#include <libvmi/libvmi.h>

#include <dump.h>

char *gen_layer_filename(vmi_pid_t pid, reg_t rip) {

    int dir_len = strlen(dump_output_dir);

    // format: <output_dir><pid>-<layer>-<rip>.bin\0
    char *filename = (char *) malloc(dir_len + 49);
    sprintf(filename, "%s%010d-%016lx-%016lx.bin", dump_output_dir, pid, layer_num, rip);

    // TODO - Layer number should be per-PID
    layer_num++;

    return filename;
}

void *dump_worker_loop(void *data) {

    dump_layer_t *layer;
    FILE *ofile;

    while (1) {

        sem_wait(&dump_sem);

        layer = (dump_layer_t *) g_queue_pop_head(dump_queue);

        if (layer->pid == 0 && layer->rip == 0 && layer->buff == NULL && layer->size == 0) {
            free(layer);
            break; // signal to stop
        }

        char *filename = gen_layer_filename(layer->pid, layer->rip);
        ofile = fopen(filename, "wb");
        fwrite(layer->buff, sizeof(char), layer->size, ofile);
        fclose(ofile);

        free(filename);
        free(layer->buff);
        free(layer);
    }

    return NULL;
}

void start_dump_thread(char *dir) {

    if (dir == NULL) {
        fprintf(stderr, "ERROR: Dump Thread - Cannot start thread with an output dir of NULL\n");
        return;
    }

    // Make copy of output dir string (malloc extra space in case we need to append a trailing '/')
    dump_output_dir = (char *) malloc(strlen(dir) + 2);
    strcpy(dump_output_dir, dir);
    int tail = strlen(dump_output_dir);
    if (dump_output_dir[tail - 1] != '/') {
        dump_output_dir[tail] = '/';
        dump_output_dir[tail + 1] = '\0';
    }

    // Create semaphore and queue
    if(sem_init(&dump_sem, 0, 0)) {
        fprintf(stderr, "ERROR: Dump Thread - Failed to initialize semaphore\n");
        return;
    }
    dump_queue = g_queue_new();

    // TODO - layer should be per-PID
    layer_num = 0;

    // Start worker thread
    pthread_create(&dump_worker, NULL, dump_worker_loop, NULL);
}

void stop_dump_thread() {

    // Signal the worker that we're done by adding an empty item to its queue
    add_to_dump_queue(NULL, 0, 0, 0);

    pthread_join(dump_worker, NULL);

    free(dump_output_dir);
    sem_destroy(&dump_sem);
    g_queue_free(dump_queue);
}

void add_to_dump_queue(char *buffer, uint64_t size, vmi_pid_t pid, reg_t rip) {

    dump_layer_t *layer = (dump_layer_t *) malloc(sizeof(dump_layer_t));
    layer->pid = pid;
    layer->rip = rip;
    layer->buff = buffer;
    layer->size = size;
    g_queue_push_tail(dump_queue, layer);

    sem_post(&dump_sem);
}
