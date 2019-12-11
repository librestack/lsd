/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * db.h
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

#ifndef __LSD_DB
#define __LSD_DB

#include <lmdb.h>

#define DB_MAX 32 /* max number of named lmdb databases */
#define DB_PATH "/var/cache/lsd/"

typedef enum {
	DB_GLOBAL,
	DB_PROTO,
	DB_URI,
} config_db_idx_t;

extern MDB_env *env;

#endif /* __LSD_DB */
