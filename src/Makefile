# SPDX-License-Identifier: GPL-3.0-or-later
#
# this file is part of LIBRESTACK
#
# Copyright (c) 2012-2019 Brett Sheffield <bacs@librecast.net>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program (see the file COPYING in the distribution).
# If not, see <http://www.gnu.org/licenses/>.


OBJECTS:=$(PROGRAM).o config.o db.o err.o handler.o log.o
MODULES:=echo.so http.so

LDFLAGS:=-ldl -lrt -llmdb

.PHONY:		all clean

all:		$(PROGRAM) $(MODULES)

lsd:		$(OBJECTS)
		$(CC) $(LDFLAGS) -o $(PROGRAM) $(OBJECTS)

$(PROGRAM).o:	$(PROGRAM).c $(PROGRAM).h

echo.so:	echo.o
		$(CC) -shared -fPIC -o $@  $^

echo.o:		echo.c
		$(CC) -fPIC -c $^

http.so:	http.o
		$(CC) -shared -fPIC -o $@  $^

http.o:		http.c http.h
		$(CC) -fPIC -c http.c

config.o:	config.c config.h

db.o:		db.c db.h

err.o:		err.c err.h

handler.o:	handler.c handler.h

log.o:		log.c log.h

clean:
		rm -f *.o $(PROGRAM)
