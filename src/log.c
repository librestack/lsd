/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * log.c
 *
 * this file is part of LIBRESTACK
 *
 * Copyright (c) 2012-2019 Brett Sheffield <bacs@librecast.net>
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
#include "config.h"
#include "log.h"

#define LOG_BUFSIZE 128

void logmsg(unsigned int level, const char *fmt, ...)
{
	va_list argp;
	char *mbuf = NULL;
	char buf[LOG_BUFSIZE];
	char *b = buf;
	int len;

	va_start(argp, fmt);
	len = vsnprintf(buf, LOG_BUFSIZE, fmt, argp);
	if (len > LOG_BUFSIZE) {
		/* need a bigger buffer, resort to malloc */
		mbuf = malloc(len + 1);
		vsprintf(mbuf, fmt, argp);
		b = mbuf;
	}
	va_end(argp);
	fprintf(stderr, "%s\n", b);
	free(mbuf);
}
