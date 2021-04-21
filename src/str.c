/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only
 *
 * str.c
 *
 * this file is part of LIBRESTACK
 *
 * Copyright (c) 2012-2020 Brett Sheffield <bacs@librecast.net>
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

#include "str.h"
#include <ctype.h>
#include <string.h>

#ifndef memmem
void *memmem(const void *h, size_t hlen, const void *n, size_t nlen)
{
	char *p;
	while ((p = memchr(h, ((char *)n)[0], hlen))) {
		if ((size_t)(p + nlen) > hlen) return NULL;
		/* found start, check for rest of needle */
		if (!memcmp(p, n, nlen)) return p;
		h = p + 1;
	}
	return NULL;
}
#endif

/* advance ptr to end of word, return length */
size_t wordend(char **ptr, size_t ptrmax, size_t maxlen)
{
	size_t i;
	maxlen = (ptrmax < maxlen) ? ptrmax : maxlen; /* lowest limit */
	for (i = 0; i < maxlen && !isspace((*ptr)[i]); i++);
	return (int)i;
}

/* advance ptr to next word, return offset */
size_t skipspace(char **ptr, size_t i, size_t maxlen)
{
	*ptr += i;
	for (i = 0; i < maxlen && isblank((*ptr)[i]); i++);
	*ptr += i;
	return i;
}
