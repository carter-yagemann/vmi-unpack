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

def run_cmd(cmd, async=False, sudo=False):
    """Wrapper for subprocess.Popen that checks relevant configurations.

    Note that when simulate flag is checked, a DummyChild is used instead
    of Popen. DummyChild "fakes" enough of the Popen methods and attributes
    to allow the server to run normally without actually running any commands.

    Keyword Arguments:
    cmd -- Command array, as would be passed to Popen or call.
    async -- Whether this command should run async or not.
    sudo -- Whether command should be ran via sudo.

    Return:
    Return code if async is False, otherwise a Popen object.
    """
    if sudo:
        cmd = ['sudo'] + cmd

    if args.simulate:
        log.debug('Command: ' + ' '.join(cmd))
        child = DummyChild()
    else:
        fnull = open(os.devnull, 'w')
        child = Popen(cmd, stdout=fnull, stderr=fnull)

    if async:
        return child
    else:
        return child.wait()

def create_snapshot():
    """Creates a snapshot of the target VM"""
    tmp = tempfile.mkstemp(prefix='vmi-snapshot-')

    cmd = [utils['qemu-img'], 'create', '-f', 'qcow2', '-o',
           'backing_file=' + str(config['vm_img']), tmp[1]]
    res = run_cmd(cmd)
    if res != 0:
        log.debug('qemu-img returned ' + str(res))
        log.error('Failed to create image snapshot')
        os.remove(tmp[1])
        sys.exit(1)

    return tmp[1]

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

    # TODO - Checking filetypes before sending samples to the client agent.

    shasum = sha256(open(filepath, 'rb').read()).hexdigest()
    res_dir = os.path.join(args.out_dir, shasum)
    if os.path.exists(res_dir):
        log.warning("Output directory for " + shasum + " already exists, skipping")
        return

    log.debug("Preparing VM")
    log.debug("Creating snapshot image")
    snapshot = create_snapshot()

    log.debug("Starting VM")
    xen = libvirt.open('xen:///system')
    if xen == None:
        print('Failed to open connection to xen:///system',
              file=sys.stderr)
        os.remove(snapshot)
        sys.exit(1)
    xmlconfig = open(config['xml_conf'], 'r')
    guest = xen.createXML(xmlconfig, 0)
    if guest == None:
        print('Failed to create a domain from XML definition',
              file=sys.stderr)
        os.remove(snapshot)
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
            if os.path.isfile(snapshot):
                os.remove(snapshot)
            xen.close()
            return

        log.debug("Connection from " + str(addr))

    log.debug("Starting unpacker")
    unpack_dir = tempfile.mkdtemp(prefix='vmi-output-')
    unpack_cmd = [utils['unpack'], '-d', vm_name, '-r', config['rekall'], '-o', unpack_dir, '-n', 'sample.exe', '-f']
    if config['use_sudo']:
        unpacker = run_cmd(unpack_cmd, sudo=True, async=True)
    else:
        unpacker = run_cmd(unpack_cmd, sudo=False, async=True)

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
                log.warning("Unpacker exited early")
            else:
                log.debug("unpack exited with code " + str(res))
                log.warning("Unpacker exited with error(s)")
            break

    if unpacker.poll() is None:
        log.debug("Stopping unpack")
        kill_cmd = [utils['killall'], '-9', 'unpack']
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

    if os.path.isfile(snapshot):
        os.remove(snapshot)
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

log = init_log(30)


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
            'xl_conf':  config.get('main', 'xl_conf'),
            'vm_img':   config.get('main', 'vm_img'),
        }
    except (NoOptionError, ValueError) as e:
        log.error('Configuration is missing parameters. See example.conf.')
        sys.exit(1)

    errors = False
    for filepath in ['rekall', 'xl_conf', 'vm_img']:
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
@click.option('-s', '--sample', type=click.File('rb'), required=True,
              help='Path to sample executable file to unpack')
#@click.option('-d', '--domain', type=str, required=True,
#              help='The name of the VM domain to use')
#@click.option('-i', '--ip', type=str, required=True,
#              help='The IPv4/IPv6 address of the VM guest OS')
#@click.option('-r', '--rekall', type=click.File('r'), required=True,
#              help='Path to rekall file that describes VM guest memory structures (OS specific)')
def main(conf, loglevel, simulate, outdir, sample):  # , domain, ip, rekall):
    """Main method"""
    global args, config, utils, sock

    args.conf = conf
    args.log_level = loglevel
    args.simulate = simulate
    args.out_dir = outdir
    args.sample = sample

    log.setLevel(args.log_level)
    config = parse_conf(args.conf)
    utils = find_utils()
    sock = init_socket()

    run_sample(args.sample)

    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        log.debug("Socket already disconnected")
    sock.close()

if __name__ == '__main__':
    main()
