/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * log.c
 *
 * this file is part of LIBRESTACK
 *
 * Copyright (c) 2012-2019 Brett Sheffield <brett@gladserv.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (see the file COPYING in the distribution).
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include "log.h"
#include "misc.h"

void logmsg(unsigned int level, const char *fmt, ...)
{
	va_list argp;
	char *b;

	va_start(argp, fmt);
	b = malloc(_vscprintf(fmt, argp) + 1);
	assert(b != NULL);
	vsprintf(b, fmt, argp);
	va_end(argp);
	fprintf(stderr, "%s\n", b);
	free(b);
}

