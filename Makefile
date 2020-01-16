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

ifeq ($(CC),cc)
CC := gcc
endif
ifeq ($(CXX),g++)
CXX := g++
endif

LIBVMI_LIBS := $(shell pkg-config --libs libvmi)
ALL_LIBS += $(LIBVMI_LIBS)
GLIB_LIBS := $(shell pkg-config --libs glib-2.0)
ALL_LIBS += $(GLIB_LIBS)
JSON_LIBS := $(shell pkg-config --libs json-glib-1.0)
ALL_LIBS += $(JSON_LIBS)
CRYPTO_LIBS := $(shell pkg-config --libs openssl)
ALL_LIBS += $(CRYPTO_LIBS)

#CXX_LIBS := -lstdc++
#ALL_LIBS += $(CXX_LIBS)

LIBVMI_CFLAGS := $(shell pkg-config --cflags libvmi)
ALL_CFLAGS += $(LIBVMI_CFLAGS)
GLIB_CFLAGS := $(shell pkg-config --cflags glib-2.0)
ALL_CFLAGS += $(GLIB_CFLAGS)
JSON_CFLAGS := $(shell pkg-config --cflags json-glib-1.0)
ALL_CFLAGS += $(JSON_CFLAGS)
CRYPTO_CFLAGS := $(shell pkg-config --cflags openssl)
ALL_CFLAGS += $(CRYPTO_CFLAGS)

UNPACK_CFLAGS := -Iinclude -Wall
UNPACK_CFLAGS += -fdata-sections -ffunction-sections
ALL_CFLAGS += $(UNPACK_CFLAGS)
CXX_CFLAGS := -I/usr/local/include -std=c++11

DEBUG_CFLAGS_COMMON := -g3 -Werror
DEBUG_CFLAGS_LEAK := -fsanitize=address -fno-omit-frame-pointer
DEBUG_CFLAGS_COVERAGE := --coverage

#https://stackoverflow.com/questions/9551416/gnu-make-how-to-join-list-and-separate-it-with-separator
LITERAL_SPACE :=
LITERAL_SPACE +=
# Joins elements of the list in arg 2 with the given separator.
#   1. Element separator.
#   2. The list.
join-with = $(subst $(LITERAL_SPACE),$1,$(strip $2))

#order is important. rpath entries are searched first to last.
RPATH_DIRS := \
	/home/linuxbrew/.linuxbrew/opt/glib/lib64 \
	/home/linuxbrew/.linuxbrew/lib \
	/usr/local/lib64 \

RPATH := $(call join-with,:,$(RPATH_DIRS))
UNPACK_LDFLAGS := -Wl,-rpath="$(RPATH)"
UNPACK_LDFLAGS += -Wl,--gc-sections
UNPACK_LDFLAGS += -L/usr/local/lib64

SOURCES_PROCESS := $(wildcard src/process/*.c)
SOURCES := $(wildcard src/*.c)
SOURCES += $(SOURCES_PROCESS)
CXX_SOURCES := $(wildcard src/*.cpp)
CXX_SOURCES += $(wildcard src/process/*.cpp)

##TOOLS_SOURCES_TABLE_MONITOR += $(filter-out src/main.c,$(SOURCES))
TOOLS_SOURCES_TABLE_MONITOR := tools/table_monitor.c
TOOLS_SOURCES_TABLE_MONITOR += src/monitor.c
TOOLS_SOURCES_TABLE_MONITOR += src/rekall_parser.c
TOOLS_SOURCES_TABLE_MONITOR += $(SOURCES_PROCESS)
TOOLS_SOURCES_REKALL_LINUX := tools/rekall_linux.c
TOOLS_SOURCES_REKALL_LINUX += src/rekall_parser.c
TOOLS_SOURCES_REKALL_WINDOWS := tools/rekall_windows.c
TOOLS_SOURCES_REKALL_WINDOWS += src/rekall_parser.c
TOOLS_SOURCES_CR3_TRACKER := tools/cr3_tracker.c
TOOLS_SOURCES_CR3_TRACKER += src/rekall_parser.c
TOOLS_SOURCES_CR3_TRACKER += $(SOURCES_PROCESS)
TOOLS_SOURCES_VMI_TABLE_WALK := tools/vmi_table_walk.c

TEST_SOURCES := test/unit.c
TEST_SOURCES += src/rekall_parser.c
TEST_SOURCES += src/dump.c

TABLE_MONITOR_OBJS := $(TOOLS_SOURCES_TABLE_MONITOR:.c=.o)
REKALL_LINUX_OBJS := $(TOOLS_SOURCES_REKALL_LINUX:.c=.o)
REKALL_WINDOWS_OBJS := $(TOOLS_SOURCES_REKALL_WINDOWS:.c=.o)
CR3_TRACKER_OBJS := $(TOOLS_SOURCES_CR3_TRACKER:.c=.o)
VMI_TABLE_WALK_OBJS := $(TOOLS_SOURCES_VMI_TABLE_WALK:.c=.o)

TEST_OBJS := $(TEST_SOURCES:.c=.o)

C_OBJS := $(SOURCES:.c=.o)
CXX_OBJS := $(CXX_SOURCES:.cpp=.o)

#used in 'make clean'
ALL_OBJS += $(TABLE_MONITOR_OBJS)
ALL_OBJS += $(REKALL_LINUX_OBJS)
ALL_OBJS += $(REKALL_WINDOWS_OBJS)
ALL_OBJS += $(CR3_TRACKER_OBJS)
ALL_OBJS += $(VMI_TABLE_WALK_OBJS)
ALL_OBJS += $(TEST_OBJS)
ALL_OBJS += $(C_OBJS)
ALL_OBJS += $(CXX_OBJS)

TARGET := bin/unpack
TARGET_TEST := bin/unit_tests

TARGET_TABLE_MONITOR := bin/table-monitor
TARGET_REKALL_LINUX := bin/rekall-linux
TARGET_REKALL_WINDOWS := bin/rekall-windows
TARGET_CR3_TRACKER := bin/cr3-tracker
TARGET_VMI_TABLE_WALK := bin/vmi-table-walk
#table-monitor is broken because src/monitor.o depends on global variables in src/main.o
#TARGET_TOOLS += $(TARGET_TABLE_MONITOR)
TARGET_TOOLS += $(TARGET_REKALL_LINUX)
TARGET_TOOLS += $(TARGET_REKALL_WINDOWS)
TARGET_TOOLS += $(TARGET_CR3_TRACKER)
TARGET_TOOLS += $(TARGET_VMI_TABLE_WALK)

#setting these last, just to be sure
CXXFLAGS = $(CXX_CFLAGS) $(ALL_CFLAGS)
CFLAGS = $(ALL_CFLAGS)
LDFLAGS = $(UNPACK_LDFLAGS)

.PHONY: all tools test astyle clean release common_deps debug_common debug debug_leak debug_coverage

all: debug

bin:
	@mkdir -p bin

common_deps: bin
release debug_common tools: common_deps
debug debug_leak debug_coverage: debug_common

debug: CXXFLAGS += $(DEBUG_CFLAGS_COMMON)
debug: CFLAGS += $(DEBUG_CFLAGS_COMMON)
debug: $(TARGET)

debug_leak: CXXFLAGS += $(DEBUG_CFLAGS_COMMON) $(DEBUG_CFLAGS_LEAK)
debug_leak: CFLAGS += $(DEBUG_CFLAGS_COMMON) $(DEBUG_CFLAGS_LEAK)
debug_leak: $(TARGET)

debug_coverage: CXXFLAGS += $(DEBUG_CFLAGS_COMMON) $(DEBUG_CFLAGS_COVERAGE)
debug_coverage: CFLAGS += $(DEBUG_CFLAGS_COMMON) $(DEBUG_CFLAGS_COVERAGE)
debug_coverage: $(TARGET)

release: $(TARGET)

tools: $(TARGET_TOOLS)

test: $(TARGET_TEST)

astyle:
	tools/astyle/run.sh

clean:
	rm -f $(ALL_OBJS)
	rm -f bin/*

$(TARGET): $(CXX_OBJS) $(C_OBJS)
	${CC} ${CFLAGS} ${LDFLAGS} -o $@ $^ ${ALL_LIBS}

$(TARGET_TEST): LDFLAGS_HACK = -Wl,--unresolved-symbols=ignore-in-object-files
$(TARGET_TEST): $(TEST_OBJS)
	${CC} ${CFLAGS} ${LDFLAGS} ${LDFLAGS_HACK} -o $@ $^ ${ALL_LIBS} -lcunit

$(TARGET_TABLE_MONITOR): TOOLS_CFLAGS = $(UNPACK_CFLAGS) $(LIBVMI_CFLAGS) $(GLIB_CFLAGS) $(JSON_CFLAGS)
$(TARGET_TABLE_MONITOR): $(TABLE_MONITOR_OBJS)
	${CC} ${TOOLS_CFLAGS} ${LDFLAGS} -o $@ $^ ${LIBVMI_LIBS} ${GLIB_LIBS} ${JSON_LIBS}

$(TARGET_VMI_TABLE_WALK): TOOLS_CFLAGS = $(UNPACK_CFLAGS) $(LIBVMI_CFLAGS)
$(TARGET_VMI_TABLE_WALK): $(VMI_TABLE_WALK_OBJS)
	${CC} ${TOOLS_CFLAGS} ${LDFLAGS} -o $@ $^ ${LIBVMI_LIBS}

$(TARGET_REKALL_LINUX): TOOLS_CFLAGS = $(UNPACK_CFLAGS) $(JSON_CFLAGS)
$(TARGET_REKALL_LINUX): $(REKALL_LINUX_OBJS)
	${CC} ${TOOLS_CFLAGS} ${LDFLAGS} -o $@ $^ ${JSON_LIBS}

$(TARGET_REKALL_WINDOWS): TOOLS_CFLAGS = $(UNPACK_CFLAGS) $(JSON_CFLAGS)
$(TARGET_REKALL_WINDOWS): $(REKALL_WINDOWS_OBJS)
	${CC} ${TOOLS_CFLAGS} ${LDFLAGS} -o $@ $^ ${JSON_LIBS}

$(TARGET_CR3_TRACKER): TOOLS_CFLAGS = $(UNPACK_CFLAGS) $(LIBVMI_CFLAGS) $(JSON_CFLAGS)
$(TARGET_CR3_TRACKER): $(CR3_TRACKER_OBJS)
	${CC} ${TOOLS_CFLAGS} ${LDFLAGS} -o $@ $^ ${LIBVMI_LIBS} ${JSON_LIBS}
