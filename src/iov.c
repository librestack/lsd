/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * iov.c
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

#include "iov.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int iovcmp(struct iovec *k, void *ptr)
{
	return memcmp(k->iov_base, ptr, k->iov_len);
}

struct iovec *iovset(struct iovec *iov, void *base, size_t len)
{
	iov->iov_base = base;
	iov->iov_len = len;
	return iov;
}

struct iovec *iovcpy(struct iovec *dst, struct iovec *src)
{
	return iovset(dst, src->iov_base, src->iov_len);
}

int iov_push(iovstack_t *iovs, void *base, size_t len)
{
	int err = 0;
	if (iovs->idx == iovs->len) { /* extend iovec array if needed */
		if (iovs->nmemb == 0) iovs->nmemb = 1;
		iovs->len += iovs->nmemb;
		if (!(iovs->iov = realloc(iovs->iov, iovs->len * sizeof(iovstack_t))))
			return ENOMEM;
	}
	iovset(&iovs->iov[iovs->idx], base, len);
	iovs->idx++;
	return err;
}
