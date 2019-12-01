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


OBJECTS:=$(PROGRAM).o config.o err.o log.o misc.o

.PHONY:		all clean

all:		$(PROGRAM)

lsd:		$(OBJECTS)
		$(CC) $(LDFLAGS) -o $(PROGRAM) $(OBJECTS)

$(PROGRAM).o:	$(PROGRAM).c $(PROGRAM).h

config.o:	config.c config.h

err.o:		err.c err.h

log.o:		log.c log.h

misc.o:		misc.c misc.h

clean:
		rm -f *.o $(PROGRAM)
