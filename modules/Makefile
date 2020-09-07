# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2020 Brett Sheffield <bacs@librecast.net>
SHELL = /bin/sh
.SUFFIXES:
.SUFFIXES: .c .o
CFLAGS += -shared -fPIC
MODULES := echo.so http.so
NOTOBJS := ../src/lsd.o
COMMON_OBJECTS := $(filter-out $(NOTOBJS), $(wildcard ../src/*.o)) librecast.o websocket.o
LIBS := -lsodium
INSTALL := install
INSTALL_PROGRAM := $(INSTALL)
INSTALL_DATA := $(INSTALL) -m 644
prefix ?= /usr/local
exec_prefix := $(prefix)
bindir := $(exec_prefix)/bin
libdir := $(exec_prefix)/lib
datarootdir := $(prefix)/share/lsd
includedir := $(prefix)/include

all: $(MODULES) https.so

https.so: http.so
	ln -sf http.so https.so

http.so: http.o $(COMMON_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) -lwolfssl

echo.so: echo.o $(COMMON_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

%.o: %.h

install: all
	$(INSTALL) -d $(datarootdir)
	$(INSTALL) -d $(includedir)
	$(INSTALL) $(MODULES) $(libdir)
	cd $(libdir) && ln -s http.so https.so
	$(INSTALL_DATA) mime.types $(datarootdir)

.PHONY: clean

clean:
	rm -f *.o $(MODULES)

realclean: clean
