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


def update_dll_exports(master_fn, updates_fn):
    with open(master_fn, 'r') as fd:
        master_exports = json.load(fd)
    with open(updates_fn, 'r') as fd:
        updates_exports = json.load(fd)
    for new_path in updates_exports:
        if new_path in master_exports:
            master_exports[new_path] = updates_exports[new_path]
    with open(master_fn, 'w') as fd:
        json.dump(master_exports, fd)
    return master_exports


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


def show_imports_by_jump(_ibj):
    print("what was scanned from unpacked binary:")
    for jump in _ibj:
        mod = _ibj[jump]["Module"]
        func = _ibj[jump]["Function"]
        print(f"addr:{jump:08x} {mod}:{func}")


def show_split_jumps(_sj):
    print("after sorted and splitting up all the jumps:")
    pprint(_sj)


def show_new_imports(_imports, _impscan_obj):
    print("reconstructed imports:")
    for lib in _imports:
        print(f"{lib} rva:{_impscan_obj.rva[lib]:x}")
        for func in _imports[lib]:
            print(f"\t{func} rva:{_impscan_obj.lookup[lib][func]:x}")


def generate_redirects(exp_fn, redir_fn):
    win7_dlls = read_dll_exports(exp_fn)
    create_dll_redirects(win7_dlls, redir_fn)


def test_reconstruction(_redirects_fn, _impscan_fn, _ldr_fn):
    impscan_obj = fix_binary.parse_impscan_json(_impscan_fn)
    new_imports = fix_binary.reconstruct_imports(_ldr_fn, _redirects_fn, impscan_obj)
    show_new_imports(new_imports, impscan_obj)


@click.group()
def cli():
    pass


@cli.command('exports')
@click.argument('dllexp_fn')
@click.argument('exports_fn')
def cli_create_exports(dllexp_fn, exports_fn):
    """create exports from dllexp input"""
    create_dll_exports(dllexp_fn, exports_fn)


@cli.command('redirects')
@click.argument('exports_fn')
@click.argument('redirects_fn')
def cli_create_redirects(exports_fn, redirects_fn):
    """create redirects from processing master exports json"""
    generate_redirects(exports_fn, redirects_fn)


@cli.command('test')
@click.argument('redirects_fn')
@click.argument('impscan_fn')
@click.argument('ldr_fn')
def cli_run_test(redirects_fn, impscan_fn, ldr_fn):
    """test import reconstruction"""
    test_reconstruction(redirects_fn, impscan_fn, ldr_fn)


@cli.command('update')
@click.argument('master_fn')
@click.argument('update_fn')
def update(master_fn, update_fn):
    """add new export updates to master exports json"""
    update_dll_exports(master_fn, update_fn)


if __name__ == '__main__':
    cli()
