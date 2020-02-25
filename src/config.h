/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * config.h
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

#ifndef __LSD_CONFIG
#define __LSD_CONFIG

#define WC_NO_HARDEN /* FIXME: stop wolfssl warning */
#include <wolfssl/ssl.h>

#include "db.h"
#include <netdb.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define DEFAULT_LISTEN_ADDR "::"

typedef enum {
	CONFIG_TYPE_INVALID,
	CONFIG_TYPE_BOOL,
	CONFIG_TYPE_INT,
	CONFIG_TYPE_STR
} config_type_t;

typedef enum {
	CONFIG_INIT,
	CONFIG_NEXT,
	CONFIG_FINAL,
} config_state_t;

/* key, long, short, type, default,
 * helptext */
#define CONFIG_STRINGS(X) \
	X("config",	"--config",	"-C", NULL, \
	  "path to config file") \
	X("cert",	"--cert",	"-c", NULL, \
	  "path to TLS certificate") \
	X("key",	"--key",	"-k", NULL, \
	  "path to TLS key")
#define CONFIG_BOOLEANS(X) \
	X("daemon",	"--daemon",	"-d", 0, \
	  "daemonize? 1=yes, 0=no")
#define CONFIG_INTEGERS(X) \
	X("loglevel",	"--loglevel",	"-l", LOG_LOGLEVEL_DEFAULT, \
	  "logging level")

/* lower and upper bounds on numeric config types */
#define CONFIG_LIMITS(X) \
	X("loglevel", 0, 127) \
	X("port", 1, 65535)
#undef X

typedef struct module_s module_t;
struct module_s {
	char *		name;
	void *		ptr;
};

typedef struct proto_s proto_t;
struct proto_s {
	uint16_t	port;
	uint8_t		protocol;
	uint8_t		socktype;
	char		addr[INET6_ADDRSTRLEN];
	char		module[];
};
typedef struct conn_s conn_t;
struct conn_s {
	proto_t		*proto;
	char		addr[INET6_ADDRSTRLEN];
	int		sock;
	WOLFSSL		*ssl;
};

typedef struct uri_s uri_t;
struct uri_s {
	size_t		uri_len;
	char		uri[];
};
#define CONFIG_IN(k, lng, shrt, deflt, helptxt) \
	if (strcmp(key, k) == 0) return 1;
#define CONFIG_KEY(k, lng, shrt, deflt, helptxt) \
	if ((!strcmp(key, lng)) || (!strcmp(key, shrt))) return k;
#define CONFIG_MIN(k, min, max) if (strcmp(key, k) == 0) return min;
#define CONFIG_MAX(k, min, max) if (strcmp(key, k) == 0) return max;
#define CONFIG_SET(k, lng, shrt, deflt, helptxt) \
	config_set_s(db, k, deflt, txn, dbi);
#define CONFIG_SET_INT(k, lng, shrt, deflt, helptxt) \
	config_set_int(db, k, deflt, txn, dbi);

extern int debug;
extern char yield;
extern module_t *mods;

void	config_close();
char *	config_db(char db, char name[2]);
int	config_get(char *key, MDB_val *val, MDB_txn *txn, MDB_dbi dbi);
int	config_get_copy(const char *db, char *key, MDB_val *val, MDB_txn *txn, MDB_dbi dbi);
int	config_get_s(const char *db, char *key, char **val, MDB_txn *txn, MDB_dbi dbi);
int	config_del(const char *db, char *key, char *val, MDB_txn *txn, MDB_dbi dbi);
int	config_init(int argc, char **argv);
void	config_init_db();
int	config_mime_load();
module_t *config_module(char *name, size_t len);
int config_set(const char *db, MDB_val *key, MDB_val *val, MDB_txn *txn, MDB_dbi dbi, int flags);
int	config_set_s(const char *db, char *key, char *val, MDB_txn *txn, MDB_dbi dbi);
int	config_set_int(const char *db, char *key, int val, MDB_txn *txn, MDB_dbi dbi);
int	config_load_modules();
void	config_unload_modules();
int config_yield(const char *dbname, MDB_val *key, MDB_val *val);
int	config_yield_s(char db, char *key, MDB_val *val);
void	config_yield_free();

#endif /* __LSD_CONFIG */
