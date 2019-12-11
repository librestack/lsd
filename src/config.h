/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * config.h
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

#ifndef __LSD_CONFIG
#define __LSD_CONFIG

#include <lmdb.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

typedef enum {
	CONFIG_TYPE_INVALID,
	CONFIG_TYPE_BOOL,
	CONFIG_TYPE_INT,
	CONFIG_TYPE_STRING
} config_type_t;

/* key, short, long, type, var, value, helptext */
#define CONFIG_ITEMS(X) \
	X(filename, "-C", "--config", CONFIG_TYPE_STRING, char *, NULL, "path to config file") \
	X(loglevel, "-l", "--loglevel", CONFIG_TYPE_INT, int, 15, "logging level") \
	X(daemon, "-d", "--daemon", CONFIG_TYPE_BOOL, int, 0, "daemonize")
#undef X

/* lower and upper bounds on numeric config types */
#define CONFIG_LIMITS(X) \
	X("loglevel", 0, 127) \
	X("port", 1, 65535)
#undef X

typedef struct proto_s proto_t;
struct proto_s {
	proto_t	*	next;
	char *		module;
	char *		addr;
	char *		proto;
	size_t		module_len;
	size_t		addr_len;
	size_t		proto_len;
	unsigned short	port;
};

typedef struct uri_s uri_t;
struct uri_s {
	uri_t *		next;
	char *		uri;
	size_t		uri_len;
};

#define X(key, ks, kl, type, var, value, helptxt) var key;
typedef struct config_s config_t;
struct config_s {
	struct stat sb;
	char *map;
	int fd;
	CONFIG_ITEMS(X)
	proto_t *protocols;
	uri_t	*uris;
};
#undef X

#define CONFIG_DEFAULTS(key, ks, kl, type, var, value, helptxt) config.key = value;
#define CONFIG_MIN(k, min, max) if (strcmp(key, k) == 0) return min;
#define CONFIG_MAX(k, min, max) if (strcmp(key, k) == 0) return max;
#define CONFIG_DB_MAX 32 /* max number of named lmdb databases */
#define CONFIG_DB_PATH "/var/cache/lsd/"
#define CONFIG_SHM "/lsd.conf" /* name of shared memory link for config map */

extern config_t config;
extern MDB_env *env;

/* pack key into MDB_val. If len is NULL, use strlen() */
#define K(key) KV(key, NULL);
MDB_val V(char *key, size_t *len);

void	config_close(config_t *c);
int	config_init(int argc, char **argv, config_t *c);
void	config_init_db();

#endif /* __LSD_CONFIG */
