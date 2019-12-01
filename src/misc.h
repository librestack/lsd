/* SPDX-License-Identifier: GPL-3.0-or-later 
 *
 * misc.h
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

#ifndef __LSD_MISC_H__
#define __LSD_MISC_H__ 1

#include <stdarg.h>
#include <sys/types.h>
#include "lsd.h"

/* return size of buffer to allocate for vsnprintf() */
int _vscprintf (const char * format, va_list argp);

#endif /* __LSD_MISC_H__ */
