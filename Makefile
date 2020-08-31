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

PROGRAM = lsd
export PROGRAM

PREFIX = /usr/local
export PREFIX

SHARE_PATH = $(PREFIX)/share/lsd
export SHARE_PATH

LIB_PATH = $(PREFIX)/lib
export LIB_PATH

LD_LIBRARY_PATH += $(LIB_PATH)
export LD_LIBRARY_PATH

BIN_PATH = $(PREFIX)/sbin
export BIN_PATH

DB_PATH = /var/local/lib/lsd/
export DB_PATH

COVERITY_DIR := cov-int
COVERITY_TGZ := $(PROGRAM).tgz

CFLAGS += -Wall -Wextra -Wpedantic -Wvla -g
export CFLAGS

.PHONY: all clean realclean src modules

all:	src

clean realclean:
	@$(MAKE) -C src $@
	@$(MAKE) -C modules $@
	@$(MAKE) -C test $@
	rm -rf ./$(COVERITY_DIR)
	rm -f $(COVERITY_TGZ)

install:
	@$(MAKE) -C src $@
	@$(MAKE) -C modules $@

src modules:
	@$(MAKE) -C $@ all

sparse: clean
	CC=cgcc $(MAKE) src

check test sanitize: src
	@$(MAKE) -C test $@

%.test %.check:
	@$(MAKE) -B $@ -C test

coverity: clean
	PATH=$(PATH):../cov-analysis-linux64-2019.03/bin/ cov-build --dir cov-int $(MAKE) src
	tar czvf $(COVERITY_TGZ) $(COVERITY_DIR)
