#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2018 Carter Yagemann
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import print_function

import click
import logging
import os
import socket
import sys
import tempfile
from datetime import datetime
from hashlib import sha256
import libvirt
from subprocess import Popen, call, check_output
from time import sleep
import xml.etree.ElementTree as ET
if sys.version_info.major <= 2:
    from ConfigParser import RawConfigParser, NoOptionError
else:
    from configparser import RawConfigParser, NoOptionError


class Args(object):
    pass

args = Args()
log = None


class DummyChild(object):
    """A dummy Popen object used in simulation mode"""
    def __init__(self):
        """Init dummy child"""
        self.returncode = 0
        self.pid = 1000

    def poll(self):
        """Dummy child immediately returns"""
        return self.returncode

    def wait(self):
        """Dummy child immediately returns"""
        return self.returncode

    def send_signal(self, signal):
        """Dummy child accepts all signals"""
        pass

    def terminate(self):
        """Dummy child doesn't need to be terminated"""
        pass

    def kill(self):
        """Dummy child doesn't need to be killed"""
        pass

def run_cmd(cmd, async=False, sudo=False, logfile=None):
    """Wrapper for subprocess.Popen that checks relevant configurations.

    Note that when simulate flag is checked, a DummyChild is used instead
    of Popen. DummyChild "fakes" enough of the Popen methods and attributes
    to allow the server to run normally without actually running any commands.

    Keyword Arguments:
    cmd -- Command array, as would be passed to Popen or call.
    async -- Whether this command should run async or not.
    sudo -- Whether command should be ran via sudo.
    logfile -- If specified, a filepath to write stdout and stderr to.

    Return:
    Return code if async is False, otherwise a Popen object.
    """
    if sudo:
        cmd = ['sudo'] + cmd

    log.debug('Command: ' + ' '.join(cmd))
    if args.simulate:
        child = DummyChild()
    else:
        if logfile:
            fd = open(logfile, 'w')
        else:
            fd = open(os.devnull, 'w')
        child = Popen(cmd, stdout=fd, stderr=fd)

    if async:
        return child
    else:
        return child.wait()

def get_disk_from_xml(data):
    """Finds the disk defined in a libvirt XML file"""
    xml = ET.fromstring(data)
    disk_xpath = ".//disk[@device='disk']/source"
    disk = xml.find(disk_xpath)
    if disk is None:
        return None
    disk = disk.get('file')
    log.debug('Disk: %s' % disk)
    return disk

def create_snapshot(filename, snapname):
    """Creates a snapshot of the target VM"""
    cmd = [utils['qemu-img'], 'snapshot', '-c', snapname, filename]
    res = run_cmd(cmd)
    if res != 0:
        log.debug('qemu-img returned ' + str(res))
        log.error('Failed to create snapshot')
        sys.exit(1)

def revert_and_delete_snapshot(filename, snapname):
    """Reverts a disk to a previous snapshot and then deletes it"""
    cmd = [utils['qemu-img'], 'snapshot', '-a', snapname, filename]
    res = run_cmd(cmd)
    if res != 0:
        log.debug('qemu-img returned ' + str(res))
        log.error('Failed to revert snapshot')
        sys.exit(1)
    cmd = [utils['qemu-img'], 'snapshot', '-d', snapname, filename]
    res = run_cmd(cmd)
    if res != 0:
        log.debug('qemu-img returned ' + str(res))
        log.error('Failed to delete snapshot')
        sys.exit(1)

def init_socket():
    """Initialize the socket for sending samples to the guest VM"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(config['timeout'])
    try:
        sock.bind((config['host_ip'], 52174))
    except socket.error:
        log.error("Failed to bind to port, aborting")
        sys.exit(1)
    return sock

def run_sample(filepath):
    """Run this sample through VMI-Unpack"""
    shasum = sha256(open(filepath, 'rb').read()).hexdigest()
    res_dir = os.path.join(args.out_dir, shasum)
    if os.path.exists(res_dir):
        log.warning("Output directory for " + shasum + " already exists, skipping")
        return

    log.debug("Connecting to Xen")
    xen = libvirt.open('xen:///system')
    if xen == None:
        log.error('Failed to open connection to xen:///system')
        sys.exit(1)

    log.debug("Creating snapshot image")
    xmlconfig = open(config['xml_conf'], 'r').read()
    vm_img = get_disk_from_xml(xmlconfig)
    if vm_img is None:
        log.error('Failed to extract disk filepath from libvirt XML')
        xen.close()
        sys.exit(1)
    vm_img_name = os.path.basename(vm_img)
    if len(vm_img_name) < 6 or vm_img_name[-6:] != '.qcow2':
        log.error('VM image must be a .qcow2')
        xen.close()
        sys.exit(1)
    create_snapshot(vm_img, 'vmi-unpack')

    log.debug("Starting VM")
    try:
        guest = xen.createXML(xmlconfig, 0)
    except libvirt.libvirtError as ex:
        log.error("Failed to create gutest VM: %s" % str(ex))
        revert_and_delete_snapshot(vm_img, 'vmi-unpack')
        xen.close()
        sys.exit(1)
    if guest == None:
        log.error('Failed to create a domain from XML definition')
        revert_and_delete_snapshot(vm_img, 'vmi-unpack')
        xen.close()
        sys.exit(1)

    if not args.simulate:  # Cannot simulate socket I/O
        log.info("Waiting for VM to startup")
        try:
            sock.listen(0)
            conn, addr = sock.accept()
        except socket.timeout:
            log.error("VM did not startup within timeout, aborting")
            guest.destroy()
            revert_and_delete_snapshot(vm_img, 'vmi-unpack')
            xen.close()
            return
        log.debug("Connection from " + str(addr))

    log.debug("Starting unpacker")
    unpack_dir = tempfile.mkdtemp(prefix='vmi-output-')
    unpack_log = os.path.join(unpack_dir, 'unpack.log')
    unpack_cmd = [utils['unpack'], '-d', guest.name(), '-r', config['rekall'], '-e', config['vol_bin'],
                  '-v', config['vol_prof'], '-o', unpack_dir, '-n', 'sample.exe', '-f']
    if config['use_sudo']:
        unpacker = run_cmd(unpack_cmd, sudo=True, async=True, logfile=unpack_log)
    else:
        unpacker = run_cmd(unpack_cmd, sudo=False, async=True, logfile=unpack_log)

    start = datetime.now()  # Mark the beginning of unpacking time

    if not args.simulate:  # Cannot simulate socket I/O
        log.debug("Sending sample to client")
        with open(filepath, 'rb') as ifile:
            conn.send(ifile.read())
        conn.shutdown(socket.SHUT_RDWR)  # So the agent knows we're done sending data
        conn.close()

    log.info("Running sample for " + str(config['runtime']) + " seconds")
    while (datetime.now() - start).seconds < config['runtime']:
        sleep(5)
        res = unpacker.poll()
        if not res is None:
            if res == 0:
                log.info("Unpacker exited early")
            else:
                log.debug("unpack exited with code " + str(res))
                log.warning("Unpacker exited with error(s)")
            break

    if unpacker.poll() is None:
        log.debug("Stopping unpack")
        kill_cmd = [utils['killall'], 'unpack']
        if config['use_sudo']:
            run_cmd(kill_cmd, sudo=True)
        else:
            run_cmd(kill_cmd, sudo=False)
    guest.destroy()

    log.debug("Storing results")
    if not args.simulate:  # There are no results if commands were simulated
        os.rename(unpack_dir, res_dir)
    else:
        os.rmdir(unpack_dir)

    revert_and_delete_snapshot(vm_img, 'vmi-unpack')
    xen.close()

def run_dir(dirpath):
    """Run samples in the provided directory"""
    items = [os.path.join(dirpath, entry) for entry in os.listdir(args.sample)]
    samples = [sample for sample in items if os.path.isfile(sample)]
    count = len(samples)
    log.info("Found " + str(count) + " samples")
    for sample in samples:
        run_sample(sample)
        count -= 1
        log.info(str(count) + ' samples remaining')

def init_log(level):
    """Initialize the logging interface"""
    format = '%(asctime)-15s %(levelname)s: %(message)s'
    logging.basicConfig(format=format)
    logger = logging.getLogger('vmi-unpack')
    logger.setLevel(level)
    return logger

def lookup_bin(name):
    """Looks up the path to a bin using Linux environment variables. Not as
       robust as a program like which, but should be good enough."""
    log.debug('PATH = ' + str(os.environ['PATH']))

    path_dirs = os.environ['PATH'].split(':')
    for path_dir in path_dirs:
        candidate = os.path.join(path_dir, name)
        if os.path.isfile(candidate):
            return candidate

    log.warning('Failed to find ' + str(name))
    return None

def find_utils():
    """Find all the utilities used by this script"""
    utils = dict()

    for bin_ in ['qemu-img', 'killall']:
        res = lookup_bin(bin_)
        if not res:
            log.error('Cannot find required program: ' + str(bin_))
            sys.exit(1)
        utils[bin_] = res

    # unpack is special because its apart of this project so we'll try looking
    # in a few places for it along with PATH.
    if os.path.isfile('../bin/unpack'):
        utils['unpack'] = '../bin/unpack'
    elif os.path.isfile('./bin/unpack'):
        utils['unpack'] = './bin/unpack'
    else:
        utils['unpack'] = lookup_bin('unpack')
    if not utils['unpack']:
        log.error('Cannot find unpack. Is it compiled? If so, try adding it to PATH')
        sys.exit(1)

    return utils

def parse_conf(conf_fd):
    """Parse configuration file"""
    config = RawConfigParser()
    config.readfp(conf_fd)

    try:
        settings = {
            'host_ip':  config.get('main', 'host_ip'),
            'runtime':  config.getint('main', 'runtime'),
            'timeout':  config.getint('main', 'timeout'),
            'use_sudo': config.getboolean('main', 'use_sudo'),
            'rekall':   config.get('main', 'rekall'),
            'xml_conf': config.get('main', 'xml_conf'),
            'vol_bin':  config.get('main', 'vol_bin'),
            'vol_prof': config.get('main', 'vol_prof'),
        }
    except (NoOptionError, ValueError) as e:
        log.error('Configuration is missing parameters. See example.conf.')
        sys.exit(1)

    errors = False
    for filepath in ['rekall', 'xml_conf']:
        if not os.path.isfile(settings[filepath]):
            log.error('Not a file: ' + str(settings[filepath]))
            errors = True
    if errors:
        log.error('Config file contains errors')
        sys.exit(1)

    return settings


@click.command()
@click.option('-c', '--conf', type=click.File('r'), default='./example.conf',
              help='Path to configuration (default: ./example.conf)')
@click.option('-l', '--log-level', 'loglevel', type=click.IntRange(0, 50, clamp=True), default=20,
              help='Logging level (10: Debug, 20: Info, 30: Warning, '
              '40: Error, 50: Critical) (default: Info)')
@click.option('--dry-run', 'simulate', is_flag=True,
              help='Show commands that would run (logged at debug level) '
              'instead of actually running them')
@click.option('-o', '--outdir', type=click.Path(), required=True,
              help='Path to store all output data and logs')
@click.option('-s', '--sample', type=click.Path(), required=True,
              help='Path to sample file or directory of files to unpack')
def main(conf, loglevel, simulate, outdir, sample):
    """Main method"""
    global args, config, utils, sock, log

    log = init_log(loglevel)
    args.loglevel = loglevel
    args.conf = conf
    args.simulate = simulate
    args.out_dir = outdir
    args.sample = sample

    config = parse_conf(args.conf)
    utils = find_utils()
    sock = init_socket()

    if os.path.isfile(args.sample):
        run_sample(args.sample)
    elif os.path.isdir(args.sample):
        run_dir(args.sample)
    else:
        log.error("%s is neither a file nor directory" % args.sample)

    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        log.debug("Socket already disconnected")
    sock.close()

if __name__ == '__main__':
    main()
