# Copyright (c) 2017 Carter Yagemann
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

CC=gcc
FLAGS=-std=gnu11 -Wall

main:
	mkdir -p bin
	$(CC) src/*.c src/process/*.c $(FLAGS) -I include -o bin/unpack `pkg-config --cflags --libs libvmi glib-2.0 json-glib-1.0 openssl`

debug:
	mkdir -p bin
	$(CC) src/*.c src/process/*.c $(FLAGS) -g3 -I include -o bin/unpack -L/usr/lib64 `pkg-config --cflags --libs libvmi glib-2.0 json-glib-1.0 openssl`

# export PATH=/home/linuxbrew/.linuxbrew/bin:$PATH
# export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/home/linuxbrew/.linuxbrew/opt/glib/lib/pkgconfig
debug-linuxbrew:
	mkdir -p bin
	$(CC) src/*.c src/process/*.c $(FLAGS) -g3 -fsanitize=address -fno-omit-frame-pointer -I include -o bin/unpack -L/usr/local/lib64 `pkg-config --cflags --libs libvmi glib-2.0 json-glib-1.0 openssl` -Wl,-rpath="/home/linuxbrew/.linuxbrew/opt/glib/lib64:/home/linuxbrew/.linuxbrew/lib:/usr/local/lib64"

.PHONY: tools

tools:
	mkdir -p bin
	$(CC) tools/vmi_table_walk.c $(FLAGS) -I include -o bin/vmi-table-walk `pkg-config --cflags --libs libvmi`
	$(CC) tools/table_monitor.c src/monitor.c src/rekall_parser.c src/process/*.c $(FLAGS) -I include -o bin/table-monitor `pkg-config --cflags --libs libvmi glib-2.0 json-glib-1.0`
	$(CC) tools/rekall_linux.c src/rekall_parser.c $(FLAGS) -I include -o bin/rekall-linux `pkg-config --cflags --libs json-glib-1.0`
	$(CC) tools/rekall_windows.c src/rekall_parser.c $(FLAGS) -I include -o bin/rekall-windows `pkg-config --cflags --libs json-glib-1.0`
	$(CC) tools/cr3_tracker.c src/rekall_parser.c src/process/*.c $(FLAGS) -I include -o bin/cr3-tracker `pkg-config --cflags --libs libvmi glib-2.0 json-glib-1.0`

.PHONY: astyle

astyle:
	tools/astyle/run.sh

clean:
	rm -f bin/* test/unit

.PHONY: test

test:
	$(CC) test/unit.c src/rekall_parser.c src/dump.c $(FLAGS) -I include -o test/unit -l cunit `pkg-config --cflags --libs json-glib-1.0 openssl`
