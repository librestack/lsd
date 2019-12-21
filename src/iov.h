/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * iov.h
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

#ifndef __IOV_H
#define __IOV_H 1

#include <sys/uio.h>

typedef struct iovstack_s iovstack_t;
struct iovstack_s {
	struct iovec *iov;		/* iovec array */
	size_t idx;			/* current element in stack */
	size_t len;			/* size of allocated stack */
	size_t nmemb;			/* min amount to extend stack by each time */
};

int iovcmp(struct iovec *k, void *ptr);
struct iovec *iovset(struct iovec *iov, void *base, size_t len);
int iov_push(iovstack_t *iovs, void *base, size_t len);

#endif /* __IOV_H */
