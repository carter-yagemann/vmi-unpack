/*
The MIT License (MIT)

Copyright (c) 2013 Andrew Ruef

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>

#include <parser-library/parse.h>
#include <pe_parse.h>

using namespace peparse;

int printExps(void *N, VA funcAddr, std::string &mod, std::string &func) {
  static_cast<void>(N);

  auto address = static_cast<std::uint32_t>(funcAddr);

  std::cout << "EXP: ";
  std::cout << mod;
  std::cout << "!";
  std::cout << func;
  std::cout << ": 0x";
  std::cout << std::hex << address;
  std::cout << "\n";
  return 0;
}

int printImports(void *N,
                 VA impAddr,
                 const std::string &modName,
                 const std::string &symName) {
  static_cast<void>(N);

  auto address = static_cast<std::uint32_t>(impAddr);

  std::cout << "0x" << std::hex << address << " " << modName << "!" << symName;
  std::cout << "\n";
  return 0;
}

int printRelocs(void *N, VA relocAddr, reloc_type type) {
  static_cast<void>(N);

  std::cout << "TYPE: ";
  switch (type) {
    case ABSOLUTE:
      std::cout << "ABSOLUTE";
      break;
    case HIGH:
      std::cout << "HIGH";
      break;
    case LOW:
      std::cout << "LOW";
      break;
    case HIGHLOW:
      std::cout << "HIGHLOW";
      break;
    case HIGHADJ:
      std::cout << "HIGHADJ";
      break;
    case MIPS_JMPADDR:
      std::cout << "MIPS_JMPADDR";
      break;
    case MIPS_JMPADDR16:
      std::cout << "MIPS_JMPADD16";
      break;
    case DIR64:
      std::cout << "DIR64";
      break;
    default:
      std::cout << "UNKNOWN";
      break;
  }

  std::cout << " VA: 0x" << std::hex << relocAddr << "\n";

  return 0;
}

int printSymbols(void *N,
                 std::string &strName,
                 uint32_t &value,
                 int16_t &sectionNumber,
                 uint16_t &type,
                 uint8_t &storageClass,
                 uint8_t &numberOfAuxSymbols) {
  static_cast<void>(N);

  std::cout << "Symbol Name: " << strName << "\n";
  std::cout << "Symbol Value: 0x" << std::hex << value << "\n";

  std::cout << "Symbol Section Number: ";
  switch (sectionNumber) {
    case IMAGE_SYM_UNDEFINED:
      std::cout << "UNDEFINED";
      break;
    case IMAGE_SYM_ABSOLUTE:
      std::cout << "ABSOLUTE";
      break;
    case IMAGE_SYM_DEBUG:
      std::cout << "DEBUG";
      break;
    default:
      std::cout << sectionNumber;
      break;
  }
  std::cout << "\n";

  std::cout << "Symbol Type: ";
  switch (type) {
    case IMAGE_SYM_TYPE_NULL:
      std::cout << "NULL";
      break;
    case IMAGE_SYM_TYPE_VOID:
      std::cout << "VOID";
      break;
    case IMAGE_SYM_TYPE_CHAR:
      std::cout << "CHAR";
      break;
    case IMAGE_SYM_TYPE_SHORT:
      std::cout << "SHORT";
      break;
    case IMAGE_SYM_TYPE_INT:
      std::cout << "INT";
      break;
    case IMAGE_SYM_TYPE_LONG:
      std::cout << "LONG";
      break;
    case IMAGE_SYM_TYPE_FLOAT:
      std::cout << "FLOAT";
      break;
    case IMAGE_SYM_TYPE_DOUBLE:
      std::cout << "DOUBLE";
      break;
    case IMAGE_SYM_TYPE_STRUCT:
      std::cout << "STRUCT";
      break;
    case IMAGE_SYM_TYPE_UNION:
      std::cout << "UNION";
      break;
    case IMAGE_SYM_TYPE_ENUM:
      std::cout << "ENUM";
      break;
    case IMAGE_SYM_TYPE_MOE:
      std::cout << "IMAGE_SYM_TYPE_MOE";
      break;
    case IMAGE_SYM_TYPE_BYTE:
      std::cout << "BYTE";
      break;
    case IMAGE_SYM_TYPE_WORD:
      std::cout << "WORD";
      break;
    case IMAGE_SYM_TYPE_UINT:
      std::cout << "UINT";
      break;
    case IMAGE_SYM_TYPE_DWORD:
      std::cout << "DWORD";
      break;
    default:
      std::cout << "UNKNOWN";
      break;
  }
  std::cout << "\n";

  std::cout << "Symbol Storage Class: ";
  switch (storageClass) {
    case IMAGE_SYM_CLASS_END_OF_FUNCTION:
      std::cout << "FUNCTION";
      break;
    case IMAGE_SYM_CLASS_NULL:
      std::cout << "NULL";
      break;
    case IMAGE_SYM_CLASS_AUTOMATIC:
      std::cout << "AUTOMATIC";
      break;
    case IMAGE_SYM_CLASS_EXTERNAL:
      std::cout << "EXTERNAL";
      break;
    case IMAGE_SYM_CLASS_STATIC:
      std::cout << "STATIC";
      break;
    case IMAGE_SYM_CLASS_REGISTER:
      std::cout << "REGISTER";
      break;
    case IMAGE_SYM_CLASS_EXTERNAL_DEF:
      std::cout << "EXTERNAL DEF";
      break;
    case IMAGE_SYM_CLASS_LABEL:
      std::cout << "LABEL";
      break;
    case IMAGE_SYM_CLASS_UNDEFINED_LABEL:
      std::cout << "UNDEFINED LABEL";
      break;
    case IMAGE_SYM_CLASS_MEMBER_OF_STRUCT:
      std::cout << "MEMBER OF STRUCT";
      break;
    default:
      std::cout << "UNKNOWN";
      break;
  }
  std::cout << "\n";

  std::cout << "Symbol Number of Aux Symbols: "
            << static_cast<std::uint32_t>(numberOfAuxSymbols) << "\n";

  return 0;
}

int printRsrc(void *N, resource r) {
  static_cast<void>(N);

  if (r.type_str.length())
    std::cout << "Type (string): " << r.type_str << "\n";
  else
    std::cout << "Type: 0x" << std::hex << r.type << "\n";

  if (r.name_str.length())
    std::cout << "Name (string): " << r.name_str << "\n";
  else
    std::cout << "Name: 0x" << std::hex << r.name << "\n";

  if (r.lang_str.length())
    std::cout << "Lang (string): " << r.lang_str << "\n";
  else
    std::cout << "Lang: 0x" << std::hex << r.lang << "\n";

  std::cout << "Codepage: 0x" << std::hex << r.codepage << "\n";
  std::cout << "RVA: " << std::dec << r.RVA << "\n";
  std::cout << "Size: " << std::dec << r.size << "\n";
  return 0;
}

int printSecs(void *N,
              VA secBase,
              std::string &secName,
              image_section_header s,
              bounded_buffer *data) {
  static_cast<void>(N);
  static_cast<void>(s);

  std::cout << "Sec Name: " << secName << "\n";
  std::cout << "Sec Base: 0x" << std::hex << secBase << "\n";
  if (data)
    std::cout << "Sec Size: " << std::dec << data->bufLen << "\n";
  else
    std::cout << "Sec Size: 0" << "\n";
  return 0;
}

#define DUMP_FIELD(x)                                                   \
  std::cout << "" #x << ": 0x";                                         \
  std::cout << std::hex << static_cast<std::uint64_t>(p->peHeader.nt.x) \
            << "\n";
#define DUMP_DEC_FIELD(x)                                               \
  std::cout << "" #x << ": ";                                           \
  std::cout << std::dec << static_cast<std::uint64_t>(p->peHeader.nt.x) \
            << "\n";

extern "C" {
  void show_imports(const char* filepath) {
    parsed_pe *p = ParsePEFromFile(filepath);
    if (p != NULL) {
      // print out some things
      if (p->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC) {
        DUMP_FIELD(OptionalHeader.AddressOfEntryPoint);
      } else {
        DUMP_FIELD(OptionalHeader64.AddressOfEntryPoint);
      }
  #undef DUMP_FIELD
  #undef DUMP_DEC_FIELD
      show_parsed_imports(p);
      DestructParsedPE(p);
    } else {
      std::cout << "Error: " << GetPEErr() << " (" << GetPEErrString() << ")"
                << "\n";
      std::cout << "Location: " << GetPEErrLoc() << "\n";
    }
  }

  void show_parsed_imports(parsed_pe *p) {
    std::cout << "Imports: " << "\n";
    IterImpVAString(p, printImports, NULL);
  }

  void free_parsed_pe(parsed_pe *p) {
    DestructParsedPE(p);
  }

  bounded_buffer_t malloc_bounded_buffer(size_t size) {
    return mallocBuffer(size);
  }

  parsed_pe_t parse_pe_buffer(bounded_buffer_t buf) {
    return ParsePEFromBuffer(buf);
  }
}