/* SPDX-License-Identifier: GPL-3.0-or-later 
 *
 * err.c - error handling function definitions
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

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include "err.h"
#include "log.h"

int err_log(unsigned int level, int e)
{
	LOG(level, "%s", err_msg(e));
	return e;
}

char *err_msg(int e)
{
	switch (e) {
		LSD_ERROR_CODES(LSD_ERROR_MSG)
	}
	return "Unknown error";
}

void err_print(int e, int errsv, char *errstr)
{
	char buf[LINE_MAX];
	if (errsv != 0) {
		strerror_r(errsv, buf, sizeof(buf));
		LOG(LOG_SEVERE, "%s: %s", errstr, buf);
	}
	else if (e != 0) {
		LOG(LOG_SEVERE, "%s: %s", errstr, err_msg(e));
	}
}
