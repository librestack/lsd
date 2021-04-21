/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only
 *
 * lsd.h
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

#ifndef __LSD_H
#define __LSD_H 1

#include <sys/types.h>

typedef struct LSD_val {
	size_t   size;
	void    *data;
} LSD_val;

#define HANDLER_MAX 100	/* maximum number of handler processes */
#define HANDLER_MIN 5   /* minimum number of handlers to keep ready */
#define HANDLER_RDY 0   /* semapahore to track ready handlers */
#define HANDLER_BSY 1   /* semapahore to track busy handlers */
#define PROGRAM_NAME "lsd"

#endif /* __LSD_H */
