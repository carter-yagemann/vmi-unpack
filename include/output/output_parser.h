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

#ifndef OUTPUT_PARSER_H
#define OUTPUT_PARSER_H

#include <stdbool.h>
#include <stdint.h>

#include <output/pe.h>

typedef enum
{
    UNKNOWN,
    DOS,
} image_type;

extern image_type base_image_type;
extern void *base_image_raw;

/**
 * Parses the image at the provided filepath and attempts to identify its type.
 * This method must be called before any of the other parser methods can be
 * used.
 *
 * @param base_image The path to an image file to use for initialization.
 *
 * @return 1 if successful, otherwise 0.
 */
bool output_init_parser(char *base_image);

/**
 * Fixes the layer's header in a similar manner to how Ether does it.
 * The exact fixes depends on the base image's type, but generally involves
 * repointing the entry to the newly unpacked address and fixing the section
 * headers to match the base image.
 *
 * Note that the entry parameter should be a RVA, i.e. a virtual address
 * relative to the virtual address the image was loaded into. In other words:
 *
 *     entry = (executed virtual address - base virtual address)
 *
 * @param layer a pointer to the layer.
 * @param layer_size the size of this layer.
 * @param entry the address that was executed when this layer was dumped.
 */
void (*output_fix_header)(void *layer, ssize_t layer_size, uint64_t entry);

/* DOS */

typedef struct
{
    PIMAGE_DOS_HEADER dos_header;
    PIMAGE_NT_HEADERS nt_header;
    PIMAGE_OPTIONAL_HEADER opt_header;
    PIMAGE_FILE_HEADER file_header;
    PIMAGE_SECTION_HEADER sect_header;
} mapped_pe_t;

mapped_pe_t base_image_pe;

bool parse_dos_header(void *buffer, mapped_pe_t *pe);
void output_fix_dos_header(void *layer, ssize_t layer_size, uint64_t entry);

#endif
