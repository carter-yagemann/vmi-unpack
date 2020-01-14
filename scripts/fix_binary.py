import click
from collections import defaultdict
import json
import ntpath
import sys

import distorm3
import lief

#flags and constants
DEBUG = False
#DEBUG = True
VERBOSE = True
IMAGE_SCN_CNT_CODE = (1<<5)
IMAGE_SCN_MEM_EXECUTE = (1<<29)
IMAGE_SCN_MEM_READ = (1<<30)
IMAGE_SCN_MEM_WRITE = (1<<31)
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = (1<<6)

_nc = lambda path: ntpath.normcase(path)


def debug_print(msg):
    if DEBUG:
        print(msg)


def verbose_print(msg):
    if VERBOSE:
        print(msg)


def get_imports_from_json(fn, proc_name):
    with open(fn, 'r') as json_fd:
        json_dict = json.load(json_fd)
    proc_dict = json_dict[proc_name]
    proc_imports = proc_dict["imports"]
    new_imports_dict = defaultdict(set)
    for lib in proc_imports.values(): 
        for entry in lib:
            func_line = entry['name'].strip()
            debug_print(
                "from_json: func_line={}".format(func_line)
            )
            lib_name, func_name = func_line.split('!')
            if not len(func_name):
                continue
            lib_name = lib_name.lower()
            debug_print(
                "from_json: lib={} func={}".format(lib_name, func_name)
            )
            new_imports_dict[lib_name].add(func_name)
    return new_imports_dict


def get_current_imports(_binary):
    cur_libs = defaultdict(set)
    for lib in _binary.imports:
        lib_name = lib.name.lower()
        for entry in lib.entries:
            if entry.is_ordinal:
                continue
            debug_print(
                "current_imports: lib={} func={}".format(lib_name, entry.name)
            )
            cur_libs[lib_name].add(entry.name)
    return cur_libs


def fix_oep(_binary, oep):
    try:
        new_oep = int(oep, 16)
    except ValueError:
        new_oep = int(oep)
    old_oep = int(_binary.optional_header.addressof_entrypoint)
    verbose_print(
        "old_oep={} new_oep={}".format(hex(old_oep), hex(new_oep))
    )
    _binary.optional_header.addressof_entrypoint = new_oep


def get_imports_to_add(_cur, _new):
    _to_add = defaultdict(set)
    #copy _new since we are popping items
    _new = dict(_new)
    for cur_lib in _cur:
        if cur_lib not in _new:
            continue
        for func in _new.pop(cur_lib):
            if func not in _cur[cur_lib]:
                debug_print(
                    "existing_lib={} new_func={}".format(cur_lib, func)
                )
                _to_add[cur_lib].add(func)
    for new_lib in _new:
        for func in _new[new_lib]:
            debug_print(
                "new_lib={} new_func={}".format(new_lib, func)
            )
            _to_add[new_lib].add(func)
    return _to_add


def add_new_imports(_binary, _new):
    #copy _new since we are popping items
    _new = dict(_new)
    #first, add new functions for existing libraries
    for lib in _binary.imports:
        lib_name = _nc(lib.name)
        if lib_name not in _new:
            continue
        for new_func in _new.pop(lib_name):
            debug_print(
                "add_entry: lib={} func={}".format(lib_name, new_func)
            )
            lib.add_entry(new_func)
    #second, add new libraries and their new functions
    for lib_name in list(_new.keys()):
        debug_print(
            "add_library: lib={}".format(lib_name)
        )
        lib = _binary.add_library(lib_name)
        for new_func in _new.pop(lib_name):
            debug_print(
                "add_entry: lib={} func={}".format(lib_name, new_func)
            )
            lib.add_entry(new_func)
    if len(_new):
        print("warning: there are left over libraries after adding new imports")
        for lib_name in _new:
            print("warning: left over library name={}".format(lib_name))


def build_imports(_binary):
    builder = lief.PE.Builder(_binary)
    builder.build_imports(True)
    builder.patch_imports(True)
    builder.build()
    return builder


def save_build(_builder, new_fn):
    debug_print("saving new pe: file={}".format(new_fn))
    _builder.write(new_fn)


def get_virtual_memory_size(_binary):
    min_offset = sys.maxsize
    total_size = 0
    for sec in _binary.sections:
        if sec.virtual_address < min_offset:
            min_offset = sec.virtual_address
        total_size += sec.virtual_size
    total_size += min_offset
    return total_size


def align(vaddr, page_size=4096):
    """page align an address"""
    slack = vaddr % page_size
    pad = page_size - slack
    aligned_vaddr = vaddr + pad
    return aligned_vaddr


def alignments(value, multiple_of):
    """align an address with a section alignment"""
    if value <= multiple_of:
        return multiple_of
    c = 1
    while value > multiple_of * c:
        c += 1
    return multiple_of * c


def fix_section(section, next_section_vaddr):
    section.sizeof_raw_data = next_section_vaddr - section.virtual_address
    section.pointerto_raw_data = section.virtual_address
    section.virtual_size = section.sizeof_raw_data 


def fix_sections(sections, virtualmemorysize):
    num_sections = len(sections)
    for i in range(num_sections - 1):
        curr_section = sections[i]
        next_section = sections[i + 1]
        fix_section(curr_section, next_section.virtual_address)
    # handle last section differently: we have no next section's virtual address. Thus we take the end of the image
    fix_section(sections[num_sections - 1], virtualmemorysize)


def restore_section_data(_binary, _bytes):
    for section in _binary.sections:
        start = section.virtual_address
        end = start + section.virtual_size
        section.content = _bytes[start:end]
    _build = lief.PE.Builder(_binary)
    _build.build_imports(False)
    _build.patch_imports(False)
    _build.build()
    return lief.parse(_build.get_build())


def fix_image_size(_binary, padded_size):
    sec_alignment = _binary.optional_header.section_alignment
    _binary.optional_header.sizeof_image = alignments(padded_size, sec_alignment)


def fix_section_mem_protections(_binary):
    #lazy strategy: make them all rwx
    rwx_flags = (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)
    for sec in _binary.sections:
        sec.characteristics |= rwx_flags


def fix_checksum(_binary, checksum=0):
    """
    The following are checked for validation at load time:
        all drivers
        any DLL loaded at boot time
        any DLL that is loaded into a critical Windows process
    Regular PE executables do not need a valid checksum
    """
    _binary.optional_header.checksum = checksum


def fix_imagebase(_binary, base=0x400000):
    _binary.optional_header.imagebase = base


def fix_dll_characteristics(_binary):
    """remove dynamic base feature to prevent relocations"""
    _binary.optional_header.dll_characteristics = (
            _binary.optional_header.dll_characteristics
            & ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
            )


def find_section_from_ptr(addr, _binary):
    base = _binary.optional_header.imagebase
    if addr < base:
        return None
    lowest_vaddr = min([sec.virtual_address for sec in _binary.sections])
    if addr >= base and addr < base + lowest_vaddr:
        return addr
    rva = addr - base
    try:
        _binary.section_from_rva(rva)
        return addr
    except lief.not_found:
        return None


def get_addr_in_operand(operand):
    if (operand.type == 'AbsoluteMemoryAddress' or
            operand.type == 'AbsoluteMemory'):
        return operand.disp
    if operand.type == 'Immediate':
        return operand.value
    return None


def get_relocs(_bytes, _binary):
    relocs = []
    for op in distorm3.Decompose(0x0, _bytes, distorm3.Decode32Bits):
        if not op.valid:
            continue
        operand_sizes = {}
        total = 0
        for i, operand in enumerate(op.operands):
            addr_size = 0
            if (operand.type == 'AbsoluteMemoryAddress' or
                    operand.type == 'AbsoluteMemory'):
                addr_size = int(operand.dispSize / 8)
            if operand.type == 'Immediate':
                addr_size = int(operand.size / 8)
            if addr_size:
                operand_sizes[i] = addr_size
                total += addr_size
        opcode_size = op.size - total
        for i, operand in enumerate(op.operands):
            addr = get_addr_in_operand(operand)
            if (addr is not None and
                find_section_from_ptr(addr, _binary) is not None):
                addr_size = int(operand.size / 8)
                offset = opcode_size + operand_sizes.get(i-1, 0)
                rva = op.address + offset
                #print(f"{rva:x}")
                relocs.append(rva)
    return relocs


def get_all_relocations(_binary):
    all_relocs = {}
    for section in _binary.sections:
        if section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE):
            _bytes = bytes(section.content)
            relocs = get_relocs(_bytes, _binary)
            debug_print(f"section=0x{section.virtual_address:x} size={len(_bytes)} nr_reloc={len(relocs)}")
            all_relocs[section.virtual_address] = relocs
    return all_relocs


def do_relocations(_all_relocs, _binary, new_base=0x400000):
    va_type = lief.Binary.VA_TYPES.RVA
    old_base = _binary.optional_header.imagebase
    debug_print(f"do_relocations: old_base=0x{old_base:x}")
    for vaddr, relocs in _all_relocs.items():
        section = _binary.section_from_rva(vaddr)
        section_bytes = section.content
        for reloc in relocs:
            ptr_addr = vaddr + reloc
            debug_print(f"do_relocations: ptr_addr=0x{ptr_addr:x}")
            #try:
            #    buf = _binary.get_content_from_virtual_address(ptr_addr, 4, va_type)
            #except:
            #    debug_print(f"do_relocations: cannot read ptr_addr=0x{ptr_addr:x}")
            #    continue
            buf = section_bytes[reloc:reloc + 4]
            buf_str = str(list(map(hex, buf)))
            debug_print(f"do_relocations: buf_str=0x{buf_str}")
            ptr = buf_to_uint32(buf)
            debug_print(f"do_relocations: ptr=0x{ptr:x}")
            if ptr < old_base:
                continue
            # example: old_base = 0xaa0000, new_base = 0x400000, ptr = 0xaa1234
            # ptr - old_base == 0x1234, 0x1234 + new_base == 0x401234
            new_ptr = (ptr - old_base) + new_base
            debug_print(f"do_relocations: new_ptr=0x{new_ptr:x}")
            new_ptr_bytes = uint32_to_buf(new_ptr)
            buf_str = str(list(map(hex, new_ptr_bytes)))
            debug_print(f"do_relocations: new_ptr_bytes=0x{buf_str}")
            for i, _byte in enumerate(new_ptr_bytes):
                section_bytes[reloc + i] = _byte
            #_binary.patch_address(ptr_addr, new_ptr, 4, va_type)
        section.content = section_bytes
    _build = lief.PE.Builder(_binary)
    _build.build_imports(False)
    _build.patch_imports(False)
    _build.build()
    return lief.parse(_build.get_build())

@click.command()
@click.argument('pe_fn')
@click.argument('new_pe_fn')
@click.argument('jsonfuncs_fn')
@click.argument('proc_name')
@click.argument('oep')
def main(pe_fn, new_pe_fn, jsonfuncs_fn, proc_name, oep):
    verbose_print("opening existing pe: file={}".format(pe_fn))
    with open(pe_fn, 'rb') as fd:
        pe_bytes = list(fd.read())
    binary = lief.parse(pe_bytes)

    cur_imports = get_current_imports(binary)
    new_imports = get_imports_from_json(jsonfuncs_fn, proc_name)
    imports_to_add = get_imports_to_add(cur_imports, new_imports)

    fix_oep(binary, oep)
    virtual_size = get_virtual_memory_size(binary)
    padded_virtual_size = align(virtual_size)
    fix_sections(binary.sections, padded_virtual_size)
    binary = restore_section_data(binary, pe_bytes)
    all_relocs = get_all_relocations(binary)
    binary = do_relocations(all_relocs, binary)
    fix_image_size(binary, padded_virtual_size)
    fix_section_mem_protections(binary)
    fix_checksum(binary)
    fix_imagebase(binary)
    fix_dll_characteristics(binary)

    add_new_imports(binary, imports_to_add)
    builder = build_imports(binary)
    save_build(builder, new_pe_fn)


if __name__ == '__main__':
    main()
