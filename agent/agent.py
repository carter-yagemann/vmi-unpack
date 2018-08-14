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

import os
import socket
import sys
from subprocess import check_output, Popen

def default_gateway():
    """Gets the default gateway in Windows"""
    res = check_output(['ipconfig']).split('\n')
    gateway = None
    for line in res:
        if 'Default Gateway' in line:
            gateway = line.split(' ')[-1]
            break

    return str(gateway).strip()

def main():
    os.chdir(os.path.dirname(os.path.realpath(__file__)))

    gateway = default_gateway()
    if not gateway:
        sys.exit(1)  # Failed to find default gateway

    # Connect to server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    try:
        sock.connect((gateway, 52174))
    except socket.timeout:
        sys.exit(2)  # Failed to connect to server

    # Get sample from server
    with open('sample.exe', 'wb') as ofile:
        while True:
            data = sock.recv(4096)
            if not data: break
            ofile.write(data)

    # Run sample
    Popen(['sample.exe'])

if __name__ == '__main__':
    main()
