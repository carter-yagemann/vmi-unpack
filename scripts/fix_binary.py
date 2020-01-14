import click
from collections import defaultdict
import json
import ntpath
import struct
import sys

import lief

#flags and constants
DEBUG = False
#DEBUG = True
VERBOSE = True
import_blacklist = [
#    "ntdll.dll",
#    "wow64cpu.dll",
#    "wow64.dll",
#    "wow64win.dll",
#    "kernelbase.dll",
]

_nc = lambda path: ntpath.normcase(path)
buf_to_uint32 = lambda buf: struct.unpack("I", bytes(buf))[0]
uint32_to_buf = lambda n: struct.pack("I", n)


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


def parse_volatility_json(fn):
    with open(fn, 'r') as fd:
        res = json.load(fd)
        vads = [dict(zip(res['columns'], r)) for r in res['rows']]
    return (vads, res)


def parse_impscan_json(fn):
    is_list, _ = parse_volatility_json(fn)
    is_rva = defaultdict(lambda: int(0x10000))
    is_lookup = defaultdict(dict)
    for entry in is_list:
        lib = _nc(entry['Module'])
        if lib in import_blacklist:
            continue
        func = entry['Function']
        iat = entry['IAT'] & 0xffff
        if iat < is_rva[lib]:
            is_rva[lib] = iat
        is_lookup[lib][func] = iat
    obj = lambda: None
    obj.rva = is_rva
    obj.lookup = is_lookup
    obj.raw = is_list
    return obj


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
    rwx_flags = (
            lief.PE.SECTION_CHARACTERISTICS.MEM_READ
            | lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE
            | lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE
            )
    for sec in _binary.sections:
        sec.characteristics |= rwx_flags
        sec.characteristics &= ~lief.PE.SECTION_CHARACTERISTICS.CNT_UNINITIALIZED_DATA


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
    _binary.optional_header.remove(lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE)
    #_binary.optional_header.remove(lief.PE.DLL_CHARACTERISTICS.NX_COMPAT)


def build_imports(_binary):
    builder = lief.PE.Builder(_binary)
    builder.build_imports(True)
    builder.patch_imports(False)
    builder.build()
    return lief.parse(builder.get_build())


def save_build(_builder, new_fn):
    verbose_print("saving new pe: file={}".format(new_fn))
    _builder.write(new_fn)


def remove_iat_dir(_binary):
    _iat = _binary.data_directory(lief.PE.DATA_DIRECTORY.IAT)
    _iat.rva = 0
    _iat.size = 0


def find_import_descriptor(lib_name, _bin):
    import_dir = _bin.data_directory(lief.PE.DATA_DIRECTORY.IMPORT_TABLE)
    sec = _bin.section_from_rva(import_dir.rva)
    sec_base = sec.virtual_address
    sec_bytes = bytes(sec.content)
    found_offset = None
    offset = import_dir.rva - sec_base
    descriptor_bytes = bytes(sec_bytes[offset:offset+20])
    lookup_rva, _, _, name_rva, iat_rva = struct.unpack("IIIII", descriptor_bytes)
    while lookup_rva != 0x0 and name_rva != 0x0:
        name_offset = name_rva - sec_base
        if name_offset > len(sec_bytes) or name_offset <= 0x0:
            debug_print(f"bad name_offset: 0x{name_offset:x}")
        else:
            tmp_name = ""
            b = sec_bytes[name_offset]
            while b != 0x0:
                tmp_name += chr(b)
                name_offset += 1
                b = sec_bytes[name_offset]
            debug_print(f"lib={tmp_name} offset=0x{offset:x}")
            if _nc(tmp_name) == _nc(lib_name):
                found_offset = offset
        offset += 20
        descriptor_bytes = bytes(sec_bytes[offset:offset+20])
        (lookup_rva, _, _, name_rva, iat_rva
        )= struct.unpack("IIIII", descriptor_bytes)
    if found_offset is not None:
        debug_print(f"found_offset=0x{found_offset:x}")
    return sec, found_offset


def patch_iat(_bin, _impscan):
    import_descriptor_offsets = {}
    imports_sec = None
    addr_size = 4
    for lib in _bin.imports:
        if _nc(lib.name) not in _impscan.rva:
            debug_print(f"cannot find rva for {lib.name}")
            continue
        il_rva = lib.import_lookup_table_rva
        il_offset = _bin.rva_to_offset(il_rva)
        il_section = _bin.section_from_offset(il_offset)
        il_bytes = il_section.content
        tb_offset = il_offset - il_section.pointerto_raw_data
        tb_ptr = int(tb_offset)
        tb_val = buf_to_uint32(bytes(il_bytes[tb_ptr:tb_ptr + addr_size]))
        for entry in lib.entries:
            #iat_val = int(entry.iat_value)
            iat_val = tb_val
            debug_print("{}:{}:iat_value=0x{:x}".format(lib.name, entry.name, iat_val))
            vaddr = _impscan.lookup[_nc(lib.name)][entry.name]
            old_iat = _bin.get_content_from_virtual_address(vaddr, 4)
            old_iat = buf_to_uint32(old_iat)
            debug_print("vaddr=0x{:x} old_iat=0x{:x}".format(vaddr, old_iat))
            _bin.patch_address(vaddr, iat_val, size=4)
            tb_ptr += addr_size
            tb_val = buf_to_uint32(bytes(il_bytes[tb_ptr:tb_ptr + addr_size]))
        new_rva = _impscan.rva[_nc(lib.name)]
        debug_print("{}:old_rva=0x{:x} new_rva=0x{:x}".format(
            lib.name, lib.import_address_table_rva, new_rva))
        imports_sec, desc_offset = find_import_descriptor(lib.name, _bin)
        #lib.import_address_table_rva = new_rva
        #fix descriptor
        sec_bytes = list(imports_sec.content)
        buf = uint32_to_buf(new_rva)
        off = int(desc_offset) + 16
        for i, b in enumerate(buf):
            sec_bytes[off + i] = b
        imports_sec.content = sec_bytes
@click.command()
@click.argument('pe_fn')
@click.argument('new_pe_fn')
@click.argument('jsonfuncs_fn')
@click.argument('proc_name')
@click.argument('impscan_fn')
@click.argument('oep')
def main(pe_fn, new_pe_fn, jsonfuncs_fn, proc_name, impscan_fn, oep):
    verbose_print("opening existing pe: file={}".format(pe_fn))
    with open(pe_fn, 'rb') as fd:
        pe_bytes = list(fd.read())
    binary = lief.parse(pe_bytes)

    cur_imports = get_current_imports(binary)
    new_imports = get_imports_from_json(jsonfuncs_fn, proc_name)
    imports_to_add = get_imports_to_add(cur_imports, new_imports)
    impscan_obj = parse_impscan_json(impscan_fn)

    fix_oep(binary, oep)
    virtual_size = get_virtual_memory_size(binary)
    padded_virtual_size = align(virtual_size)
    fix_sections(binary.sections, padded_virtual_size)
    binary = restore_section_data(binary, pe_bytes)
    fix_image_size(binary, padded_virtual_size)
    fix_section_mem_protections(binary)
    fix_checksum(binary)
    fix_dll_characteristics(binary)

    add_new_imports(binary, imports_to_add)
    binary = build_imports(binary)
    remove_iat_dir(binary)
    patch_iat(binary, impscan_obj)
    save_build(binary, new_pe_fn)

if __name__ == '__main__':
    main()
