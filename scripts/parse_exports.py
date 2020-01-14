from __future__ import print_function
import json
from collections import defaultdict
import ntpath
from pprint import pprint
import re
import sys

from blessings import Terminal
import click
from progressbar import ProgressBar

import fix_binary


class Writer(object):
    def __init__(self, location):
        self.location = location
    def write(self, string):
        with term.location(0, self.location):
            sys.stdout.write(string + '\n')
    def flush(self):
        sys.stdout.flush()


dllexp_fn = 'win7_all_exports.dllexp.txt'
exports_fn = 'win7_master_dll_exports.json'
redirects_fn = 'win7_master_dll_redirects.json'
impscan_fn = 'impscan.section0000.0001.2464.json'
ldr_fn = 'ldrmodules.0001.928.json'
dllexp_columns = ['func','addr','reladdr','ord','libname','path','type']
address_patt_32 = r'^0x[0-9a-f]{8}$'
address_patt_64 = r'^0x[0-9a-f]{16}$'
redir_patt = r'^([^.]+?)\.([^.]+?)$'

_nc = ntpath.normcase
term = Terminal()
re_addr_32 = re.compile(address_patt_32, re.I)
re_addr_64 = re.compile(address_patt_64, re.I)
re_redir = re.compile(redir_patt)


def parse_volatility_json(fn):
    with open(fn, 'r') as fd:
        res = json.load(fd)
        vads = [dict(zip(res['columns'], r)) for r in res['rows']]
    return (vads, res)


def create_dll_exports(in_fn, out_fn):
    win7_dlls = defaultdict(dict)
    with open(in_fn, 'r') as fd:
        lines = fd.readlines()
    with ProgressBar(max_value=len(lines), prefix='lines:') as bar:
        for i, line in enumerate(lines):
            line = line.strip()
            dll_info = dict(zip(
                dllexp_columns,
                line.split('\t')
            ))
            func = dll_info['func']
            path = dll_info['path']
            _, path = ntpath.splitdrive(path)
            dll_info['path'] = path
            win7_dlls[path][func] = dll_info
            bar.update(i)
    print(f"dumping to {out_fn}")
    with open(out_fn, 'w') as fd:
        json.dump(win7_dlls, fd)
    return win7_dlls


def read_dll_exports(in_fn):
    print(f"reading from {in_fn}")
    with open(in_fn, 'r') as fd:
        win7_dlls = json.load(fd)
    return win7_dlls


def create_dll_redirects(_dlls, out_fn):
    _redirects = defaultdict(lambda: defaultdict(set))
    total = sum([len(funcs) for funcs in _dlls.values()])
    bottom_line = Writer(term.height-2)
    tick = 0
    with ProgressBar(max_value=total, prefix='redirects:',
                     fd=Writer(term.height-4),
                     ) as lib_bar:
        for i, (path, funcs) in enumerate(_dlls.items()):
            _bits = None
            lib_bn = ntpath.basename(path)
            with ProgressBar(max_value=len(funcs), prefix=lib_bn + ':',
                             fd=Writer(term.height-3),
                             ) as func_bar:
                for j, (func, info) in enumerate(funcs.items()):
                    addr = info['addr']
                    m = re_redir.match(addr)
                    if m:
                        dest_lib = m.groups()[0] + '.dll'
                        dest_func = m.groups()[1]
                        _redirects[_nc(dest_lib)][dest_func].add((_nc(path),func))
                    elif re_addr_32.match(addr):
                        if _bits is None:
                            _bits = 32
                    elif re_addr_64.match(addr):
                        if _bits is None:
                            _bits = 64
                    else:
                        print(f"error: cannot parse addr={addr}")
                    func_bar.update(j)
                    lib_bar.update(tick)
                    tick += 1
            bottom_line.write(f"lib:{lib_bn} = {_bits} bits                       ")
    #change set() to list(), for json
    _redirects = {lib: {func: list(_set)
                        for func, _set in funcs.items()}
                  for lib, funcs in _redirects.items()}
    print(f"dumping to {out_fn}")
    with open(out_fn, 'w') as fd:
        json.dump(_redirects, fd)
    return _redirects


def read_dll_redirects(in_fn):
    with open(redirects_fn, 'r') as fd:
        win7_redirects = json.load(fd)
    return win7_redirects


def create_ldr_map(_fn):
    ldr_raw, _ = parse_volatility_json(_fn)
    ldr_map = [_nc(l['MappedPath'])
               for l in ldr_raw]
    return ldr_map


def read_impscan(_fn):
    with open(_fn, 'r') as fd:
        impscan_raw = json.load(fd)
    impscan_map = [dict(zip(impscan_raw['columns'], r)) for r in impscan_raw['rows']]
    imports_by_jump = {i['IAT']: i for i in impscan_map}
    return imports_by_jump


def show_imports_by_jump(_ibj):
    print("what was scanned from unpacked binary:")
    for jump in _ibj:
        mod = _ibj[jump]["Module"]
        func = _ibj[jump]["Function"]
        print(f"addr:{jump:08x} {mod}:{func}")


def get_split_jumps(_imp_by_j):
    sorted_jumps = sorted(_imp_by_j.keys())
    split_jumps = []
    last_jump = sorted_jumps[0]
    cur_jumps = [last_jump]
    for jump in sorted_jumps[1:]:
        if jump == last_jump + 4:
            cur_jumps.append(jump)
        else:
            split_jumps.append(cur_jumps)
            cur_jumps = [jump]
        last_jump = jump
    split_jumps.append(cur_jumps)
    return split_jumps


def show_split_jumps(_sj):
    print("after sorted and splitting up all the jumps:")
    pprint(_sj)


def reconstruct_imports(_splits, _imp_by_j, _map, _redirs):
    #do the magic
    chosen_so_far = []
    _new_imports = {}
    #each jump set is one library to import
    for jset in _splits:
        #count how many times each library.function combo can be used
        lib_stats = defaultdict(int)
        #keep track of each possible lib.func combo per jump
        funcs_in_jset = []
        #each jump is one function for this library
        for jump in jset:
            lib_bn = _nc(_imp_by_j[jump]['Module'])
            func = _imp_by_j[jump]['Function']
            slot_dict = {lib_bn: func}
            funcs_in_jset.append(slot_dict)
            lib_stats[lib_bn] += 1
            if lib_bn in _redirs and func in _redirs[lib_bn]:
                redirs = _redirs[lib_bn][func]
                for dll_path, other_func in redirs:
                    if dll_path in _map:
                        path_bn = ntpath.basename(dll_path)
                        slot_dict[path_bn] = other_func
                        lib_stats[path_bn] += 1
        #print(lib_stats)
        #figure out which lib to use:
        #
        found_candidate = False
        #strategy 1:
        #    there are N functions,
        #    and foo.dll is seen N times,
        #    of all libs counts, if only one of them is seen N times
        #    then it, foo.dll, must be the correct lib
        candidates = [lib
                    for lib, count in lib_stats.items()
                    if count >= len(jset)]
        if len(candidates) == 1:
            chosen_lib = candidates[0]
            if chosen_lib not in chosen_so_far:
                #print(f"choosing {chosen_lib}")
                chosen_so_far.append(chosen_lib)
                found_candidate = True
            else:
                print(f"error: strategy 1 used, "
                      "but {chosen_lib} was already chosen")
        else:
        #strategy 2:
        #   just pick the last lib that hasn't been chosen yet
            for candidate in candidates[::-1]:
                if candidate not in chosen_so_far:
                    chosen_lib = candidate
                    #print(f"choosing {chosen_lib}")
                    chosen_so_far.append(chosen_lib)
                    found_candidate = True
                    break
        if not found_candidate:
            print(lib_stats)
            print(candidates)
            raise RuntimeError("no valid candidate found")
        else:
            #we found it
            _new_imports[chosen_lib] = [slot[chosen_lib] for slot in funcs_in_jset]
    return _new_imports


def show_new_imports(_imports, _impscan_obj):
    print("reconstructed imports:")
    for lib in _imports:
        print(f"{lib} rva:{_impscan_obj.rva[lib]:x}")
        for func in _imports[lib]:
            print(f"\t{func} rva:{_impscan_obj.lookup[lib][func]:x}")


def generate_redirects(exp_fn, redir_fn):
    win7_dlls = read_dll_exports(exp_fn)
    create_dll_redirects(win7_dlls, redir_fn)


def test_reconstruction():
    impscan_obj = fix_binary.parse_impscan_json(impscan_fn)
    new_imports = fix_binary.reconstruct_imports(ldr_fn, redirects_fn, impscan_obj)
    show_new_imports(new_imports, impscan_obj)
    exit()
    win7_redirects = read_dll_redirects(redirects_fn)
    ldr_map = create_ldr_map(ldr_fn)
    imports_by_jump = read_impscan(impscan_fn)
    #json.dump(imports_by_jump, open('imports_by_jump.json', 'w'))
    #show_imports_by_jump(imports_by_jump)
    split_jumps = get_split_jumps(imports_by_jump)
    #json.dump(split_jumps, open('split_jumps.json', 'w'))
    #show_split_jumps(split_jumps)
    new_imports = reconstruct_imports(split_jumps, imports_by_jump, ldr_map, win7_redirects)

@click.command()
@click.argument('dllexp_fn')
@click.argument('exports_fn')
@click.argument('redirects_fn')
@click.argument('impscan_fn')
@click.argument('ldr_fn')
def main(dllexp_fn, exports_fn, redirects_fn, impscan_fn, ldr_fn):
    create_dll_exports(dllexp_fn, exports_fn)
    generate_redirects(exports_fn, redirects_fn)
    test_reconstruction()

if __name__ == '__main__':
    main()
