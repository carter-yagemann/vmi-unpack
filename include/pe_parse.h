#ifndef PE_PARSE_H
#define PE_PARSE_H

#ifdef __cplusplus
#include <parser-library/parse.h>
using namespace peparse;
typedef parsed_pe* parsed_pe_t; 
extern "C" {
#else
typedef void* parsed_pe_t; 
#endif

void show_parsed_imports(parsed_pe_t p);
void free_parsed_pe(parsed_pe_t p);
void show_imports(const char* filepath);

#ifdef __cplusplus
} //end extern "C"
#endif

#endif
