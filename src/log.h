/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * log.h
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

#ifndef __LSD_LOG
#define __LSD_LOG 1

#include "config.h"

#define LOG_LEVELS(X) \
	X(0,    LOG_NONE,       "none")                                 \
	X(1,    LOG_SEVERE,     "severe")                               \
	X(2,    LOG_ERROR,      "error")                                \
	X(4,    LOG_WARNING,    "warning")                              \
	X(8,    LOG_INFO,       "info")                                 \
	X(16,   LOG_TRACE,      "trace")                                \
	X(32,   LOG_FULLTRACE,  "fulltrace")                            \
	X(64,   LOG_DEBUG,      "debug")
#undef X

#define LOG_ENUM(id, name, desc) name = id,
enum {
	LOG_LEVELS(LOG_ENUM)
};

#define LOG_LOGLEVEL_DEFAULT 63
extern unsigned int loglevel;

#define LOG(lvl, fmt, ...) if ((lvl & loglevel) == lvl) logmsg(lvl, fmt __VA_OPT__(,) __VA_ARGS__)
#define BREAK(lvl, fmt, ...) {LOG(lvl, fmt __VA_OPT__(,) __VA_ARGS__); break;}
#define CONTINUE(lvl, fmt, ...) {LOG(lvl, fmt __VA_OPT__(,) __VA_ARGS__); continue;}
#define DIE(fmt, ...) {LOG(LOG_SEVERE, fmt __VA_OPT__(,) __VA_ARGS__);  _exit(EXIT_FAILURE);}
#define DEBUG(fmt, ...) LOG(LOG_DEBUG, fmt __VA_OPT__(,) __VA_ARGS__)
#define ERROR(fmt, ...) LOG(LOG_ERROR, fmt __VA_OPT__(,) __VA_ARGS__)
#define ERRMSG(err) {LOG(LOG_ERROR, err_msg(err));}
#define FAIL(err) {LOG(LOG_ERROR, err_msg(err));  return err;}
#define FAILMSG(err, fmt, ...) {LOG(LOG_ERROR, fmt __VA_OPT__(,) __VA_ARGS__);  return err;}
#define INFO(fmt, ...) LOG(LOG_INFO, fmt __VA_OPT__(,) __VA_ARGS__)

void logmsg(unsigned int level, const char *fmt, ...);

#endif /* __LSD_LOG */
