#!/home/linuxbrew/.linuxbrew/bin/python3
#!/usr/bin/env python3
from __future__ import print_function

import click
from glob import glob
import json
import os
import os.path
import sys


def find_vadinfo_files(_pid, sh_glob='vadinfo.000?.{}.json'):
    return glob(sh_glob.format(_pid))


def parse_vadinfo(fn):
    with open(fn, 'r') as fd:
        res = json.load(fd)
        vads = [dict(zip(res['columns'], r)) for r in res['rows']]
    return (vads, res)


def find_orig_exe(fn, vads, glob_tmpl='{}.????????.0x{:016x}-0x{:016x}.dmp'):
    exe_fn = None
    for vad in vads:
        if fn in vad['FileNameWithDevice']:
            exe_fn = glob_tmpl.format(fn, vad['Start'], vad['End'])
            break
    return exe_fn


@click.command()
@click.argument('dump_path')
@click.argument('orig_name')
@click.argument('pid')
def main(dump_path, orig_name, pid):
    orig_pwd = os.getcwd()
    os.chdir(dump_path)
    vadinfo_fns = find_vadinfo_files(pid)
    assert len(vadinfo_fns) > 0
    my_vads = {}
    for vinfo in vadinfo_fns:
        key = vinfo.split('.')[1]
        my_vads[key] = lambda: None  # make a simple object
        my_vads[key].vads, _ = parse_vadinfo(vinfo)
        my_vads[key].exe_glob = find_orig_exe(orig_name, my_vads[key].vads)
    for path in glob('000?'):
        if path not in my_vads:
            continue
        full_glob = os.path.join(dump_path, path, my_vads[path].exe_glob)
        found = glob(full_glob)
        if found and len(found) == 1:
            print(found[0])
    os.chdir(orig_pwd)


if __name__ == '__main__':
    main()
