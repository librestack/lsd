# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2020 Brett Sheffield <bacs@librecast.net>

CFLAGS += -shared -fPIC
MODULES := echo.so https.so
NOTOBJS := ../src/lsd.o
COMMON_OBJECTS := $(filter-out $(NOTOBJS), $(wildcard ../src/*.o))
LIBS := -lsodium

all: $(MODULES)

https.so: http.so
	ln -sf http.so https.so

http.so: http.o $(COMMON_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) -lwolfssl

echo.so: echo.o $(COMMON_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

%.o: %.h

install: all
	install -d $(LIB_PATH)
	install -d $(SHARE_PATH)
	install $(MODULES) $(LIB_PATH)
	install mime.types $(SHARE_PATH)

.PHONY: clean

clean:
	rm -f *.o $(MODULES)

realclean: clean
