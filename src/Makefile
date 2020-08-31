# SPDX-License-Identifier: GPL-3.0-or-later
#
# this file is part of LIBRESTACK
#
# Copyright (c) 2012-2020 Brett Sheffield <bacs@librecast.net>
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


COMMON_OBJECTS = config.o db.o err.o iov.o log.o str.o wire.o
OBJECTS = $(PROGRAM).o handler.o $(COMMON_OBJECTS)

CFLAGS += -fPIC -Wno-unused-parameter

LDLIBS = -ldl -lrt -llmdb -pthread -llibrecast -llsdb -llcdb -lsodium

.PHONY:		all clean

all:		$(PROGRAM) $(MODULES)

lsd:		$(OBJECTS)

clean:
		rm -f *.o $(PROGRAM)

install:	all
		install -d $(BIN_PATH)
		install -d $(DB_PATH)
		install $(PROGRAM) $(BIN_PATH)/
