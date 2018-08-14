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

import argparse
import logging
import os
import socket
import sys
import tempfile
from datetime import datetime
from hashlib import sha256
from subprocess import Popen, call, check_output
from time import sleep
if sys.version_info.major <= 2:
    from ConfigParser import RawConfigParser, NoOptionError
else:
    from configparser import RawConfigParser, NoOptionError

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
        child = Popen(cmd)

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

def create_xl_config(snapshot):
    """Creates a XL config based on the provided config with the HDD changed
       to the snapshot image."""
    tmp = tempfile.mkstemp(prefix='vmi-xl-')
    ofile = os.fdopen(tmp[0], 'w')
    name = ''

    with open(config['xl_conf']) as ifile:
        for line in ifile:
            if len(line) >= 4 and line[:4] == 'disk':
                continue
            if len(line) >= 4 and line[:4] == 'name':
                name = line.split(' ')[-1]
            ofile.write(line)
    ofile.write("disk = ['tap:qcow2:" + str(snapshot) + ",hda,w']\n")
    ofile.close()

    return (name, tmp[1])

def kill_vm(name):
    """Checks XL and if a VM by the provided name is running, it's destroyed.

    This process is special, so it doesn't use the run_cmd wrapper, but it's
    still simulate safe.
    """
    cmd = [utils['xl'], 'list']
    if config['use_sudo']:
        cmd = ['sudo'] + cmd

    res = check_output(cmd).split("\n")

    running = False
    for line in res:
        log.debug(line)
        if line.split(' ')[0] == name:
            running = True
            break

    if not running:
        return

    cmd = cmd[:-1] + ['destroy', name]
    log.debug('Command: ' + ' '.join(cmd))
    call(cmd)

def run_sample(filepath):
    """Run this sample through VMI-Unpack"""
    if not args.force:
        log.warning('Checking file type not implemented!')  # TODO - Implement

    shasum = sha256(open(filepath, 'rb').read()).hexdigest()
    res_dir = os.path.join(args.out_dir, shasum)
    if os.path.exists(res_dir):
        log.warning("Output directory for " + shasum + " already exists, skipping")
        return

    log.info("Preparing VM")
    log.debug("Creating snapshot image")
    snapshot = create_snapshot()
    log.debug("Creating snapshot XL config")
    vm_name, xl_conf = create_xl_config(snapshot)

    log.info("Starting VM")
    xl_cmd = [utils['xl'], xl_conf]
    if config['use_sudo']:
        res = run_cmd(xl_cmd, sudo=True)
    else:
        res = run_cmd(xl_cmd, sudo=False)
    if res != 0:
        log.debug("xl returned " + str(res))
        log.info("Failed to start VM")
        os.remove(xl_conf)
        os.remove(snapshot)
        sys.exit(1)

    if not args.simulate:  # Cannot simulate socket I/O
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(60)

        sock.bind(config['host_ip'], 52174)
        log.info("Waiting for VM to startup")
        try:
            sock.listen(0)
        except socket.timeout:
            log.error("VM did not startup within timeout, aborting")
            kill_vm(vm_name)
            if os.path.isfile(xl_conf):
                os.remove(xl_conf)
            if os.path.isfile(snapshot):
                os.remove(snapshot)

        log.info("Connection from " + str(addr))
        conn, addr = sock.accept()

    log.info("Starting unpacker")
    unpack_dir = tempfile.mkdtemp(prefix='vmi-output-')
    unpack_cmd = [utils['unpack'], '-d', vm_name, '-r', config['rekall'], '-o', unpack_dir, '-n', 'sample.exe', '-f']
    if config['use_sudo']:
        unpacker = run_cmd(unpack_cmd, sudo=True, async=True)
    else:
        unpacker = run_cmd(unpack_cmd, sudo=False, async=True)

    start = datetime.now()  # Mark the beginning of unpacking time

    if not args.simulate:  # Cannot simulate socket I/O
        log.info("Sending sample to client")
        with open(filepath, 'rb') as ifile:
            conn.send(ifile.read())
        conn.close()
        sock.close()

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
        log.info("Stopping unpack")
        unpacker.terminate()  # Sends SIGTERM, will exit gracefully
    kill_vm(vm_name)

    log.info("Storing results")
    if not args.simulate:  # There are no results if commands were simulated
        os.rename(unpack_dir, res_dir)
    else:
        os.rmdir(unpack_dir)

    if os.path.isfile(xl_conf):
        os.remove(xl_conf)
    if os.path.isfile(snapshot):
        os.remove(snapshot)

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

    for bin in ['xl', 'qemu-img']:
        res = lookup_bin(bin)
        if not res:
            log.error('Cannot find required program: ' + str(bin))
            sys.exit(1)
        utils[bin] = res

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

def parse_conf(conf_path):
    """Parse configuration file"""
    config = RawConfigParser()
    config.read(conf_path)

    try:
        settings = {
            'host_ip':  config.get('main', 'host_ip'),
            'runtime':  config.getint('main', 'runtime'),
            'use_sudo': config.getboolean('main', 'use_sudo'),
            'rekall':   config.get('main', 'rekall'),
            'xl_conf':  config.get('main', 'xl_conf'),
            'vm_img':   config.get('main', 'vm_img'),
        }
    except NoOptionError, ValueError:
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

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--conf', type=str, default='./example.conf',
                        help='Path to configuration (default: ./example.conf)')
    parser.add_argument('-f', '--force', action='store_true', default=False,
                        help='Disable checking the type of submitted samples')
    parser.add_argument('-l', '--log-level', type=int, default=20,
                        help='Logging level (10: Debug, 20: Info, 30: Warning, 40: Error, 50: Critical) (default: Info)')
    parser.add_argument('-s', '--simulate', action='store_true', default=False,
                        help='Show commands that would run (logged at debug level) instead of actually running them')
    parser.add_argument('sample', type=str,
                        help='Path to sample file or directory of samples to unpack')
    parser.add_argument('out_dir', type=str,
                        help='Directory to save results in')

    args = parser.parse_args()

    errors = False
    if not os.path.isfile(args.conf):
        log.error('Cannot find file: ' + str(args.conf))
        errors = True
    if not os.path.exists(args.sample):
        log.error('Does not exist: ' + str(args.sample))
        errors = True
    if not os.path.isdir(args.out_dir):
        log.error("Cannot find directory: " + str(args.out_dir))
        errors = True
    if errors:
        sys.exit(1)

    return args

def main():
    """Main method"""
    global log, args, config, utils

    log = init_log(30)
    args = parse_args()
    log.setLevel(args.log_level)
    utils = find_utils()
    config = parse_conf(args.conf)

    if os.path.isfile(args.sample):
        run_sample(args.sample)
    else:
        run_dir(args.sample)

if __name__ == '__main__':
    main()
