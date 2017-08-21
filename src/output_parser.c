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
#include <sys/stat.h>

#include <output/output_parser.h>
#include <output/pe.h>

image_type base_image_type = UNKNOWN;
void *base_image_raw = NULL;

bool output_init_parser(char *base_image)
{
    if (base_image_raw)
    {
        free(base_image_raw);
        base_image_raw = NULL;
    }

    if (!base_image)
    {
        fprintf(stderr, "ERROR: Output Parser - Filepath for base image is null.\n");
        return 0;
    }

    struct stat image_stat;
    if (stat(base_image, &image_stat))
    {
        fprintf(stderr, "ERROR: Output Parser - Failed to stat %s\n", base_image);
        return 0;
    }

    FILE *base_image_fp = fopen(base_image, "r");
    if (!base_image_fp)
    {
        fprintf(stderr, "ERROR: Output Parser - Failed to open %s\n", base_image);
        return 0;
    }

    base_image_raw = malloc(image_stat.st_size);
    if (!base_image_raw)
    {
        fprintf(stderr, "ERROR: Output Parser - Failed to allocate memory for base image\n");
        return 0;
    }

    if (fread(base_image_raw, 1, image_stat.st_size, base_image_fp) != image_stat.st_size)
    {
        fprintf(stderr, "ERROR: Output Parser - Failed to copy base image into memory\n");
        return 0;
    }
    fclose(base_image_fp);

    // Is this a DOS header?
    if (parse_dos_header(base_image_raw, &base_image_pe))
    {
        base_image_type = DOS;
        output_fix_header = output_fix_dos_header;
        return 1;
    }

    fprintf(stderr, "ERROR: Output Parser - Base image is an unsupported type of executable\n");
    return 0;
}

bool parse_dos_header(void *buffer, mapped_pe_t *pe)
{
    // Locate DOS header and check magic number
    pe->dos_header = (PIMAGE_DOS_HEADER) buffer;
    if (pe->dos_header->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    // Locate NT header and check signature
    base_image_pe.nt_header = (PIMAGE_NT_HEADERS)(base_image_raw + pe->dos_header->e_lfanew);
    if (base_image_pe.nt_header->Signature != IMAGE_NT_SIGNATURE)
        return 0;

    pe->opt_header = (PIMAGE_OPTIONAL_HEADER) & (pe->nt_header->OptionalHeader);
    pe->sect_header = (PIMAGE_SECTION_HEADER)((unsigned long) pe->nt_header + sizeof(IMAGE_NT_HEADERS));
    return 1;
}

void output_fix_dos_header(void *layer, ssize_t layer_size, uint64_t entry)
{
    if (base_image_type != DOS)
    {
        fprintf(stderr, "ERROR: Output Parser - Parser not initialized, cannot fix header\n");
        return;
    }

    if (!layer)
    {
        fprintf(stderr, "ERROR: Output Parser - Layer is null, cannot fix header\n");
        return;
    }

    if (layer_size < 1)
    {
        fprintf(stderr, "ERROR: Output Parser - Layer size is less than 1, cannot fix header\n");
        return;
    }

    // TODO - Implement output_fix_dos_header()
    fprintf(stderr, "WARNING: Output Parser - DOS header fixer not implemented.\n");
}
