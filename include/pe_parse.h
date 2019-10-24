#ifndef PE_PARSE_H
#define PE_PARSE_H

#ifdef __cplusplus
#include <parser-library/parse.h>
using namespace peparse;
typedef parsed_pe* parsed_pe_t;
typedef bounded_buffer* bounded_buffer_t;
extern "C" {
#else
typedef void* parsed_pe_t;
typedef void* bounded_buffer_t;
#endif

void show_parsed_imports(parsed_pe_t p);
void free_parsed_pe(parsed_pe_t p);
void show_imports(const char* filepath);
bounded_buffer_t malloc_bounded_buffer(size_t size);
parsed_pe_t parse_pe_buffer(bounded_buffer_t buf);

#ifdef __cplusplus
} //end extern "C"
#endif

#endif
