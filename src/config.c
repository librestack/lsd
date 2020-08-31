/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * config.c
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

#include "config.h"
#include "db.h"
#include "err.h"
#include "lsd.h"
#include "log.h"
#include <assert.h>
#include <ctype.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int debug;
static int mods_loaded;
module_t *mods;	/* dlopen handles for modules */
int run;
char yield; /* need to do cleanup call to config_yield() */
int handlers;
int pid;
int semid;
int *socks = NULL;

/* process mime.types into database */
int config_mime_load(void)
{
	MDB_txn *txn;
	MDB_dbi dbi;
	MDB_val k,v;
	char line[BUFSIZ];
	char *type, *ext;
	size_t len;
	size_t mimes = 0;
	int err = 0;
	FILE *fd;

	if ((err = mdb_txn_begin(env, NULL, 0, &txn)) != 0)
		FAILMSG(LSD_ERROR_DB, "%s(): %s", __func__, mdb_strerror(err));

	if ((err = mdb_dbi_open(txn, "mime", MDB_CREATE, &dbi)) != 0) {
		ERROR("%s(): %s", __func__, mdb_strerror(err));
		mdb_txn_abort(txn);
		return LSD_ERROR_DB;
	}
	fd = fopen("/usr/local/share/lsd/mime.types", "r");
	if (!fd) {
		ERROR("unable to open mime.types");
		mdb_txn_abort(txn);
		return LSD_ERROR_CONFIG_READ;
	}
	while (fgets(line, BUFSIZ, fd)) {
		len = strlen(line) - 1;
		if (line[0] == '#') continue;
		line[len] = '\0';
		type = strtok(line, " \t");
		v.mv_size = strlen(type);
		v.mv_data = type;
		while ((ext = strtok(NULL, " \t"))) {
			k.mv_size = strlen(ext);
			k.mv_data = ext;
			if ((err = mdb_put(txn, dbi, &k, &v, 0))) {
				ERROR("%s(): %s", __func__, mdb_strerror(err));
				break;
			}
		}
		if (err) break;
		mimes++;
	}
	fclose(fd);
	if (err) {
		mdb_txn_abort(txn);
		DEBUG("mime processing aborted");
	}
	else {
		mdb_txn_commit(txn);
		DEBUG("loaded %zu mime types", mimes);
	}

	return err;
}

char * config_db(char db, char name[2])
{
	TRACE("%s()", __func__);
	name[0] = db + '0';
	name[1] = 0;
	return name;
}

static int config_bool_convert(char *val, int *ival)
{
	TRACE("%s()", __func__);
	int i;
	char *truth[] = { "1", "true", "yes", "on", "y", "aye" };
	char *falsy[] = { "0", "false", "no", "off", "n", "nae" };
	for (i = 0; i < (int)sizeof(truth) / (int)sizeof(char *); i++) {
		if (strcmp(val, truth[i]) == 0) {
			*ival = 1;
			return 1;
		}
	}
	for (i = 0; i <(int) sizeof(falsy) / (int)sizeof(char *); i++) {
		if (strcmp(val, falsy[i]) == 0) {
			*ival = 0;
			return 1;
		}
	}
	return 0;
}

/* boolean to yes/no */
static char * btos(int b)
{
	TRACE("%s()", __func__);
	return (b) ? "yes" : "no";
}

static int config_isbool(char *key)
{
	TRACE("%s()", __func__);
	CONFIG_BOOLEANS(CONFIG_IN)
	return 0;
}

static int config_isint(char *key)
{
	TRACE("%s()", __func__);
	CONFIG_INTEGERS(CONFIG_IN)
	return 0;
}

static int config_isstr(char *key)
{
	TRACE("%s()", __func__);
	CONFIG_STRINGS(CONFIG_IN)
	return 0;
}

static int config_isopt(char *key)
{
	TRACE("%s()", __func__);
	CONFIG_BOOLEANS(CONFIG_IN)
	CONFIG_INTEGERS(CONFIG_IN)
	CONFIG_STRINGS(CONFIG_IN)
	return 0;
}

static int config_min(char *key)
{
	TRACE("%s()", __func__);
	CONFIG_LIMITS(CONFIG_MIN)
	return INT_MIN;
}

static int config_max(char *key)
{
	TRACE("%s()", __func__);
	CONFIG_LIMITS(CONFIG_MAX)
	return INT_MAX;
}

static char * config_key(char *key)
{
	TRACE("%s()", __func__);
	CONFIG_BOOLEANS(CONFIG_KEY)
	CONFIG_INTEGERS(CONFIG_KEY)
	CONFIG_STRINGS(CONFIG_KEY)
	return NULL;
}

/* return false if string contains any non-numeric characters */
static int isnumeric(char *v)
{
	TRACE("%s()", __func__);
	for (int i = 0; i < (int)strlen(v); i++) {
		if (!isdigit(v[i])) return 0;
	}
	return 1;
}

/* set key to val if numeric and within limits */
int config_int_set(char *klong, int *key, char *val)
{
	TRACE("%s()", __func__);
	int min, max, i;

	if (!isnumeric(val)) return 0;
	i = atoi(val);
	min = config_min(klong);
	max = config_max(klong);
	if (i < min || i > max) {
		ERROR("%s value must be between %i and %i", klong, min, max);
		return 0;
	}
	*key = i;

	return 1;
}

/* find module handle by name
 * TODO: if not loaded, load it */
module_t *config_module(char *name, size_t len)
{
	TRACE("%s()", __func__);
	module_t *mod = mods;
	DEBUG("seaching %i modules for '%.*s'", mods_loaded, len, name);
	for (int i = 0; i < mods_loaded; i++) {
		if (!mod) break;
		DEBUG("trying '%s'=='%.*s'", mod->name, len, name);
		if (!strncmp(mod->name, name, len)) {
			DEBUG("found '%.*s'", len, name);
			return mod;
		}
		mod++;
	}
	return NULL;
}

/* load a single module */
static int config_load_module(module_t *mod, char *name, size_t len)
{
	TRACE("%s()", __func__);
	int err = 0;
	char modpath[] = "/usr/local/lib:/usr/lib:/usr/local/sbin:./src/"; /* FIXME - configurable */
	char *module = NULL;
	char *path;
	size_t size;

	path = strtok(modpath, ":");
	while (path) {
		DEBUG("searching modpath: '%s'", path);
		size = snprintf(NULL, 0, "%s/%.*s.so", path, (int)len, name);
		module = malloc(size + 1);
		snprintf(module, size + 1, "%s/%.*s.so", path, (int)len, name);
		DEBUG("trying '%s'", module);
		/* first, check if we have it loaded already */
		if (config_module(name, len)) return 0;
		/* FIXME: allocate memory dynamically */
		if (!mods) {
			mods = calloc(32, sizeof(module_t));
		}
		mod = mods;
		for (int i = 0; i < mods_loaded; i++) { mod++; } /* find last */
		mod->ptr = dlopen(module, RTLD_LAZY);
		if (mod->ptr) {
			mod->name = strndup(name, len);
			DEBUG("module '%s' loaded successfully", mod->name);
			int (* init)(); int (* conf)();
			if ((*(void **)(&init) = dlsym(mod->ptr, "init")))
				if ((err = init())) goto err_load;
			if ((*(void **)(&conf) = dlsym(mod->ptr, "conf")))
				if ((err = conf())) goto err_load;
			mods_loaded++;
			break;
		}
		free(module); module = NULL;
		path = strtok(NULL, ":");
	}
	if (module) free(module);
	else FAILMSG(LSD_ERROR_LOAD_MODULE, "Failed to load module: %.*s", len, name);

	return err;
err_load:
	ERROR("%s", dlerror());
	dlclose(mod->ptr);
	return err;
}

void config_unload_modules(void)
{
	TRACE("%s()", __func__);
	if (mods) {
		module_t *mod = mods;
		while (mods_loaded--) {
			DEBUG("freeing module [%i] %s", mods_loaded, mod->name);
			int (* finit)();
			if ((*(void **)(&finit) = dlsym(mod->ptr, "finit")))
				finit();
			dlclose(mod->ptr);
			free(mod->name);
			mod++;
		}
		free(mods);
	}
}

int config_load_modules(void)
{
	TRACE("%s()", __func__);
	MDB_txn *txn;
	MDB_cursor *cur;
	MDB_dbi dbi;
	MDB_val key;
	MDB_val val;
	size_t size;
	char dbname[2];
	int err = 0;

	config_db(DB_PROTO, dbname);
	if ((err = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn)) != 0)
		goto config_load_modules_err;
	if((err = mdb_dbi_open(txn, dbname, MDB_INTEGERKEY, &dbi)) != 0)
		goto config_load_modules_err;
	if ((err = mdb_cursor_open(txn, dbi, &cur)) != 0)
		goto config_load_modules_err;
	key.mv_data = "proto";
	key.mv_size = strlen(key.mv_data);
	if ((err = mdb_cursor_get(cur, &key, &val, MDB_FIRST)))
		goto cur_close;
	if ((err = mdb_cursor_count(cur, &size)))
		goto cur_close;
	/* TODO: check size */
	DEBUG("loading %u modules", size);
	mods = calloc(size, sizeof(module_t));
	module_t *mod = mods;
	do {
		if ((err = config_load_module(mod, ((proto_t *)(val.mv_data))->module,
					    strlen(((proto_t *)(val.mv_data))->module))))
			break;
		mod++;
	}
	while (!(err = mdb_cursor_get(cur, &key, &val, MDB_NEXT)));
	if (err != MDB_NOTFOUND) goto config_load_modules_err;
cur_close:
	mdb_cursor_close(cur);
txn_close:
	mdb_txn_abort(txn);

	return err;
config_load_modules_err:
	ERROR("%s()[%i]: %s", __func__,  __LINE__,mdb_strerror(err));
	if (cur) goto cur_close;
	if (txn) goto txn_close;
	return err;
}

static int config_process_proto(char *line, size_t len, MDB_txn *txn, MDB_dbi dbi)
{
	TRACE("%s()", __func__);
	proto_t *p;
	struct servent *service = NULL;
	MDB_val k,v;
	char *ptr = NULL;
	char *proto = NULL;
	char socktype[LINE_MAX + 1];
	size_t n = 0;
	int err = 0;
	static unsigned int protos = 0;

	/* module (eg. https) */
	ptr = line;
	while (len > 0 && len-- && !isspace(*line++));		/* find end */
	n = line - ptr - 1;
	v.mv_size = sizeof(proto_t) + n + 1;
	p = calloc(1, v.mv_size);
	memcpy(p->module, ptr, n);
	while (len > 0 && isblank(*line)){line++;len--;}	/* skip whitespace */

	/* port */
	if (isdigit(line[0])) {
		for (; isdigit(line[0]); len--) {
			p->port *= 10;
			p->port += (unsigned char)*line++ - '0';
		}
		if (line[0] == '/') {
			line++; len--; /* skip slash */
		}
	}
	else {	/* port not provided, look it up */
		service = getservbyname(p->module, NULL);
		if (service) {
			p->port = ntohs(service->s_port);
			proto = service->s_proto;
		}
		else {
			ERROR("Unable to find port for service '%s'", p->module);
			err = LSD_ERROR_CONFIG_INVALID;
		}
	}

	/* socktype */
	if ((!err && len) || service) {
		if (!service) {
			ptr = line;
			while (len > 0 && len-- && !isspace(*line++));	/* find end */
			n = line - ptr - 1;
			memcpy(socktype, ptr, n);
			socktype[n] = '\0';
			if (strlen(socktype) > 0)
				proto = socktype;
		}
		if (!proto && !service) { /* lookup protocol for service */
			service = getservbyname(p->module, NULL);
			if (service) {
				proto = service->s_proto;
			}
			else {
				ERROR("Unable to find protocol for service '%s'", p->module);
				err = LSD_ERROR_CONFIG_INVALID;
			}
		}
		if (proto) {
			if (!strncmp(proto, "tcp", 3)) {
				p->socktype = SOCK_STREAM;
			}
			else if (!strncmp(proto, "udp", 3)) {
				p->socktype = SOCK_DGRAM;
			}
			else if (!strncmp(proto, "raw", 3)) {
				p->socktype = SOCK_RAW;
			}
			else if (!strncmp(proto, "rdm", 3)) {
				p->socktype = SOCK_RDM;
			}
			else {
				ERROR("Invalid protocol '%s'", proto);
				err = LSD_ERROR_CONFIG_INVALID;
			}
		}
		while (len > 0 && isblank(*line)){line++;len--;} /* skip whitespace */
	}

	/* address */
	if (!err) {
		if (len) {
			ptr = line;
			while (len > 0 && len-- && !isspace(*line++));	/* find end */
			n = line - ptr - 1;
			memcpy(p->addr, ptr, n);
			/* TODO: verify address is valid */
		}
		else {
			snprintf(p->addr, strlen(DEFAULT_LISTEN_ADDR) + 1, DEFAULT_LISTEN_ADDR);
		}
	}

	DEBUG("[%s][%u][%u][%s]", p->module, p->port, p->socktype, p->addr);

	if (!err) {
		/* write to db */
		k.mv_size = sizeof(unsigned int);
		k.mv_data = &protos;
		v.mv_data = p;
		err = mdb_put(txn, dbi, &k, &v, 0);
		if (err) {
			ERROR("%s(): %s", __func__, mdb_strerror(err));
		}
		protos++;
	}

	endservent();
	free(p);

	return err;
}

static int config_process_uri(char *line, size_t len, MDB_txn *txn, MDB_dbi dbi)
{
	TRACE("%s()", __func__);
	module_t *mod;
	char *ptr;
	int err = 0;
	static size_t uris = 0;

	DEBUG("processing uri");

	/* store a raw copy of the uris for config dump */
	/* to preserve ordering, using integer keys */
	MDB_val k, v;
	k.mv_size = sizeof(size_t);
	k.mv_data = &uris;
	v.mv_size = len;
	v.mv_data = line;
	config_set(NULL, &k, &v, txn, dbi, 0);
	uris++;

	ptr = strchr(line, ':');
	len = (size_t)(ptr-line);
	DEBUG("uri proto: %.*s", len, line);

	/* find or load module for this uri */
	if (!(mod = config_module(line, len)))
		if (!(config_load_module(mod, line, len)))
			if (!(mod = config_module(line, len)))
				return LSD_ERROR_LOAD_MODULE;

	if (mod) {
		int (* load_uri)(char *, MDB_txn *);
		*(void **)(&load_uri) = dlsym(mod->ptr, "load_uri");
		if (!dlerror()) err = load_uri(line, txn);
	}
	else {
		DEBUG("unable to find module");
		return LSD_ERROR_LOAD_MODULE;
	}

	return err;
}

void config_close(void)
{
	TRACE("%s()", __func__);
	mdb_env_close(env);
	env = NULL;
}

/* fetch and return a copy */
int config_get_copy(const char *db, char *key, MDB_val *val, MDB_txn *txn, MDB_dbi dbi)
{
	TRACE("%s()", __func__);
	int err = 0;
	char txn_close = 0;
	char dbi_close = 0;
	MDB_val k;
	MDB_val v;

	k.mv_size = strlen(key) + 1;
	k.mv_data = key;

	/* create new transaction and dbi handle if none */
	if (!txn) {
		DEBUG("new txn");
		if ((err = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn)) != 0) {
			ERROR("%s(): %s", __func__, mdb_strerror(err));
		}
		txn_close = 1;
	}
	if (!dbi) {
		DEBUG("new dbi");
		if ((err = mdb_dbi_open(txn, db, 0, &dbi)) != 0) {
			ERROR("%s: %s", __func__, mdb_strerror(err));
		}
		dbi_close = 1;
	}

	err = mdb_get(txn, dbi, &k, &v);
	if ((err != 0) && (err != MDB_NOTFOUND)) {
		ERROR("%s: %s", __func__, mdb_strerror(err));
	}
	else {	/* return a copy of the data */
		val->mv_size = v.mv_size;
		memcpy(val->mv_data, &v.mv_data, v.mv_size);
	}

	/* close handles that were opened here */
	if (dbi_close) mdb_dbi_close(env, dbi);
	if (txn_close) mdb_txn_abort(txn);

	return err;
}

int config_get(char *key, MDB_val *val, MDB_txn *txn, MDB_dbi dbi)
{
	TRACE("%s()", __func__);
	int err = 0;
	MDB_val k;

	k.mv_size = strlen(key) + 1;
	k.mv_data = key;
	err = mdb_get(txn, dbi, &k, val);
	if ((err != 0) && (err != MDB_NOTFOUND))
		ERROR("%s: %s", __func__, mdb_strerror(err));

	return err;
}

/* allocate and copy string value */
int config_get_s(const char *db, char *key, char **val, MDB_txn *txn, MDB_dbi dbi)
{
	TRACE("%s()", __func__);
	int err = 0;
	char txn_close = 0;
	char dbi_close = 0;
	MDB_val k;
	MDB_val v;

	k.mv_size = strlen(key) + 1;
	k.mv_data = key;

	/* create new transaction and dbi handle if none */
	if (!txn) {
		DEBUG("new txn");
		if ((err = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn)) != 0) {
			ERROR("%s(): %s", __func__, mdb_strerror(err));
		}
		txn_close = 1;
	}
	if (!dbi) {
		DEBUG("new dbi");
		if ((err = mdb_dbi_open(txn, db, 0, &dbi)) != 0) {
			ERROR("%s: %s", __func__, mdb_strerror(err));
		}
		dbi_close = 1;
	}
	err = mdb_get(txn, dbi, &k, &v);
	if ((err != 0) && (err != MDB_NOTFOUND)) {
		ERROR("%s: %s", __func__, mdb_strerror(err));
	}
	else {	/* return a copy of the data */
		*val = malloc(v.mv_size + 1);
		strncpy(*val, v.mv_data, v.mv_size);
		(*val)[v.mv_size] = '\0';
	}
	/* close handles that were opened here */
	if (dbi_close) mdb_dbi_close(env, dbi);
	if (txn_close) mdb_txn_abort(txn);

	return err;

}

int config_del(const char *db, char *key, char *val, MDB_txn *txn, MDB_dbi dbi)
{
	TRACE("%s()", __func__);
	char commit = 0;
	int err = 0;
	MDB_val k,v;

	k.mv_size = strlen(key) + 1;
	k.mv_data = key;

	/* create new transaction and dbi handle if none */
	if (!txn) {
		if ((err = mdb_txn_begin(env, NULL, 0, &txn)) != 0) {
			ERROR("%s(): %s", __func__, mdb_strerror(err));
		}
		commit = 1;
	}
	if (!dbi) {
		if ((err = mdb_dbi_open(txn, db, MDB_CREATE, &dbi)) != 0) {
			ERROR("%s(): %s", __func__, mdb_strerror(err));
		}
	}
	if (val) { /* have value, delete matching key+val only */
		v.mv_size = strlen(val) + 1;
		v.mv_data = val;
		err = mdb_del(txn, dbi, &k, &v);
	}
	else { /* no value, delete key */
		err = mdb_del(txn, dbi, &k, NULL);
	}
	if ((err != 0) && (err != MDB_NOTFOUND))
		ERROR("%s(): %s", __func__, mdb_strerror(err));

	/* do not commit existing transactions */
	if (commit)
		err = mdb_txn_commit(txn);

	return err;
}

int config_set(const char *db, MDB_val *key, MDB_val *val, MDB_txn *txn, MDB_dbi dbi, int flags)
{
	TRACE("%s()", __func__);
	char commit = 0;
	int err = 0;

	if (!val) return 0;

	/* create new transaction and dbi handle if none */
	if (!txn) {
		assert(env);
		if ((err = mdb_txn_begin(env, NULL, 0, &txn)) != 0) {
			ERROR("%s(): %s", __func__, mdb_strerror(err));
			return err;
		}
		commit = 1;
	}
	if (!dbi) {
		if ((err = mdb_dbi_open(txn, db, MDB_CREATE | flags, &dbi)) != 0) {
			ERROR("%s(): %s", __func__, mdb_strerror(err));
			return err;
		}
	}

	/* save key/val */
	if ((err = mdb_put(txn, dbi, key, val, 0)) != 0) {
		ERROR("%s(): %s", __func__, mdb_strerror(err));
	}

	/* do not commit existing transactions */
	if (commit) {
		if ((err = mdb_txn_commit(txn))) {
			ERROR("%s(): %s", __func__, mdb_strerror(err));
		}
	}

	return err;
}

/* string wrapper for config_set */
int config_set_s(const char *db, char *key, char *val, MDB_txn *txn, MDB_dbi dbi)
{
	TRACE("%s()", __func__);
	MDB_val k,v;

	if (!val) return 0;

	/* prepare key + value */
	k.mv_size = strlen(key) + 1; /* include NUL byte */
	k.mv_data = key;
	v.mv_size = strlen(val) + 1; /* include NUL byte */
	v.mv_data = val;

	return config_set(db, &k, &v, txn, dbi, 0);
}

int config_set_int(const char *db, char *key, int val, MDB_txn *txn, MDB_dbi dbi)
{
	TRACE("%s()", __func__);
	char commit = 0;
	int err = 0;
	MDB_val k,v;

	INFO("config_set_int(): '%s'='%i'", key, val); /* FIXME */

	/* prepare key + value */
	k.mv_size = strlen(key) + 1;
	k.mv_data = key;
	v.mv_size = sizeof(int);
	v.mv_data = &val;

	/* create new transaction and dbi handle if none */
	if (!txn) {
		if ((err = mdb_txn_begin(env, NULL, 0, &txn)) != 0) {
			ERROR("%s(%i): %s", __func__, __LINE__, mdb_strerror(err));
			return err;
		}
		commit = 1;
	}
	if (!dbi) {
		if ((err = mdb_dbi_open(txn, db, MDB_CREATE, &dbi)) != 0) {
			ERROR("%s(%i): %s", __func__, __LINE__, mdb_strerror(err));
			return err;
		}
	}

	/* save key/val */
	if ((err = mdb_put(txn, dbi, &k, &v, 0)) != 0) {
		ERROR("%s(%i): %s", __func__, __LINE__, mdb_strerror(err));
	}
	if (!(debug) && !strcmp(key, "loglevel")) loglevel = val;

	/* do not commit existing transactions */
	if (commit)
		err = mdb_txn_commit(txn);

	return err;
}

int config_yield(const char *dbname, MDB_val *key, MDB_val *val)
{
	TRACE("%s()", __func__);
	/* FIXME: for this function to be reentrant, we need to store all this
	 * state and pass it back to the caller */
	static config_state_t state = CONFIG_INIT;
	static MDB_txn *txn;
	static MDB_dbi dbi;
	static MDB_cursor *cur;
	static MDB_cursor_op op = MDB_FIRST;
	int err = 0;

	if (!dbname)
		state = CONFIG_FINAL;
	switch (state) {
	case CONFIG_INIT:
		yield = 1;
		if ((err = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn)) != 0) 
			FAILMSG(LSD_ERROR_DB, "%s()[%i]: %s", __func__, \
						__LINE__, mdb_strerror(err));
		if((err = mdb_dbi_open(txn, dbname, MDB_INTEGERKEY, &dbi)) != 0) {
			FAILMSG(LSD_ERROR_DB, "%s()[%i]: %s", __func__, \
						__LINE__,mdb_strerror(err));
		}
		if ((err = mdb_cursor_open(txn, dbi, &cur)) != 0)
			FAILMSG(LSD_ERROR_DB, "%s()[%i]: %s", __func__, \
						__LINE__,mdb_strerror(err));
		state = CONFIG_NEXT;
		break;
	case CONFIG_NEXT:
		op = MDB_NEXT;
		break;
	case CONFIG_FINAL:
		state = CONFIG_INIT;
		op = MDB_FIRST;
		mdb_cursor_close(cur);
		mdb_txn_abort(txn);
		return 0;
	}

	if (state != CONFIG_FINAL) {
		err = mdb_cursor_get(cur, key, val, op);
	}

	if (err) {
		if (err == MDB_NOTFOUND) {
			state = CONFIG_FINAL;
			return state;
		}
		FAILMSG(LSD_ERROR_DB, "%s(%i): %s", __func__, __LINE__, \
							mdb_strerror(err));
	}

	return (err == 0) ? state : 0;
}

/* return one value at a time. Call with key == NULL to skip to final state clean up */
int config_yield_s(char db, char *key, MDB_val *val)
{
	TRACE("%s()", __func__);
	/* FIXME: for this function to be reentrant, we need to store all this
	 * state and pass it back to the caller */
	static MDB_val k;
	static char dbname[2];

	config_db(db, dbname);
	if (key) {
		k.mv_size = strlen(key) + 1;
		k.mv_data = key;
		return config_yield(dbname, &k, val);
	}
	return config_yield(dbname, NULL, val);
}

void config_yield_free(void)
{
	TRACE("%s()", __func__);
	config_yield(NULL, NULL, NULL);
	yield = 0;
}

void config_init_db(void)
{
	TRACE("%s()", __func__);
	if (env) return;
	if (mdb_env_create(&env)) DIE ("mdb_env_create() failed");
	if (mdb_env_set_maxreaders(env, HANDLER_MAX + 1)) DIE("mdb_env_set_maxreaders failed");
	/* TODO: how big a map do we need? */
	if (mdb_env_set_mapsize(env, 10485760)) DIE("mdb_env_set_mapsize failed");
	if (mdb_env_set_maxdbs(env, DB_MAX)) DIE("mdb_env_set_maxdbs failed");
	/* TODO: set ownership on dropprivs */
	switch (mdb_env_open(env, DB_PATH, MDB_NOTLS, 0600)) {
		case 0:
			break;
		case EACCES:
			ERROR("cannot write to '%s'", DB_PATH);
			goto err_exit;
		case MDB_VERSION_MISMATCH:
			ERROR("the version of the LMDB library doesn't match the version that created the database environment");
			goto err_exit;
		case MDB_INVALID:
			ERROR("the environment file headers are corrupted");
			goto err_exit;
		case ENOENT:
			ERROR("directory '%s' does not exist", DB_PATH);
			goto err_exit;
		case EAGAIN:
	err_exit:
		default:
			mdb_env_close(env);
			DIE("mdb_env_open failed");
	}
}

static int config_defaults(MDB_txn *txn, MDB_dbi dbi)
{
	TRACE("%s()", __func__);
	int err = 0;
	char db[2];

	config_db(DB_GLOBAL, db);
	CONFIG_STRINGS(CONFIG_SET)
	CONFIG_INTEGERS(CONFIG_SET_INT)
	CONFIG_BOOLEANS(CONFIG_SET_INT)

	return err;
}

static int config_dump(FILE *fd, MDB_txn *txn, MDB_dbi dbi[])
{
	TRACE("%s()", __func__);
	int err = 0;
	MDB_cursor *cur;
	MDB_cursor_op op;
	MDB_val key;
	MDB_val data;

	for (int i = 0; i < 80; i++) { fputc('#', fd); }
	fprintf(fd, "\n## globals\n");
	err = mdb_cursor_open(txn, dbi[DB_GLOBAL], &cur);
	if (err) goto config_dump_err;
	for (op = MDB_FIRST; (err = mdb_cursor_get(cur, &key, &data, op)) == 0; op = MDB_NEXT) {
		if (config_isint((char *)key.mv_data))
			fprintf(fd, "%s %i\n", (char *)key.mv_data, *(int *)data.mv_data);
		else if (config_isbool((char *)key.mv_data))
			fprintf(fd, "%s %s\n", (char *)key.mv_data, btos(*(int *)data.mv_data));
		else
			fprintf(fd, "%s %s\n", (char *)key.mv_data, (char *)data.mv_data);
	}
	mdb_cursor_close(cur);

	for (int i = 0; i < 80; i++) { fputc('#', fd); }
	fprintf(fd, "\n## protocols\n");
	err = mdb_cursor_open(txn, dbi[DB_PROTO], &cur);
	if (err) goto config_dump_err;
	for (op = MDB_FIRST; (err = mdb_cursor_get(cur, &key, &data, op)) == 0; op = MDB_NEXT) {
		if (!err) {
			proto_t *p;
			p = data.mv_data;
			fprintf(fd, "proto\t%s\t%u", p->module, p->port);
			switch (p->socktype) {
			case SOCK_STREAM:
				fprintf(fd, "/tcp");
				break;
			case SOCK_DGRAM:
				fprintf(fd, "/udp");
				break;
			case SOCK_RAW:
				fprintf(fd, "/raw");
				break;
			case SOCK_RDM:
				fprintf(fd, "/rdm");
				break;
			case SOCK_DCCP:
				fprintf(fd, "/dccp");
				break;
			}
			if (strcmp(p->addr, DEFAULT_LISTEN_ADDR))
				fprintf(fd, "\t%s", p->addr);
			fputc('\n', fd);
		}
	}
	mdb_cursor_close(cur);

	for (int i = 0; i < 80; i++) { fputc('#', fd); }
	fprintf(fd, "\n## uris\n");
	err = mdb_cursor_open(txn, dbi[DB_URI], &cur);
	if (err) goto config_dump_err;
	for (op = MDB_FIRST; (err = mdb_cursor_get(cur, &key, &data, op)) == 0; op = MDB_NEXT) {
		if (!err) {
			fprintf(fd, "uri\t%.*s\n", (int)data.mv_size, (char *)data.mv_data);
		}
	}
	mdb_cursor_close(cur);

	return err;
config_dump_err:
	ERROR("%s(): %s", __func__, mdb_strerror(err));
	return LSD_ERROR_CONFIG_READ;
}

static void config_drop(MDB_txn *txn, MDB_dbi dbi[])
{
	TRACE("%s()", __func__);
	int err = 0;
	int flags = 0;
	char db[2];

	/* close & reopen txn in case of previous writes */
	mdb_txn_abort(txn);
	if ((err = mdb_txn_begin(env, NULL, 0, &txn))) {
		ERROR("%s(): %s", __func__, mdb_strerror(err));
		DIE("Failed to reopen tansaction");
	}
	for (int i = 0; i <= DB_URI; i++) {
		flags = 0;
		if (i > 0) flags |= MDB_INTEGERKEY;
		config_db(i, db);;
		if ((err = mdb_dbi_open(txn, db, flags, &dbi[i]))
		|| ((err = mdb_drop(txn, dbi[i], 1)) != 0))
		{
			if (err != MDB_NOTFOUND)
				ERROR("%s(): %s", __func__, mdb_strerror(err));
		}
	}
}

static int config_cmds(int *argc, char **argv, MDB_txn *txn, MDB_dbi dbi[])
{
	TRACE("%s()", __func__);
	if (!(*argc)) return 0;
	/* commands must be last argument */
	char *last = argv[*argc - 1];
	if (!strcmp(last, "dump")) {
		DEBUG("dumping config");
		(*argc)--;
		config_dump(stdout, txn, dbi);
		return LSD_ERROR_CONFIG_ABORT;
	}
	else if (!strcmp(last, "reset")) {
		DEBUG("resetting database");
		config_drop(txn, dbi);
		config_defaults(txn, dbi[DB_GLOBAL]);
		return LSD_ERROR_CONFIG_COMMIT;
	}
	else if (!strcmp(last, "start")) {
		DEBUG("starting");
		(*argc)--;
		run = 1;
		return 0;
	}
	return 0;
}

static int config_opt_set(char *k, char *v, MDB_txn *txn, MDB_dbi dbi)
{
	TRACE("%s()", __func__);
	int err = 0;
	int ival = 0;
	char db[2];

	config_db(DB_GLOBAL, db);
	if (config_isstr(k)) {
		DEBUG("%s is str", k);
		if (!v) FAILMSG(LSD_ERROR_INVALID_OPTS, "%s missing value", k);
		err = config_set_s(db, k, v, txn, dbi);
	}
	else if (config_isint(k)) {
		DEBUG("%s is int", k);
		if (!v) FAILMSG(LSD_ERROR_INVALID_OPTS, "%s missing value", k);
		if (!isnumeric(v))
			FAILMSG(LSD_ERROR_INVALID_OPTS, "%s requires integer", k);
		ival = atoi(v);
		err = config_set_int(db, k, ival, txn, dbi);
	}
	else if (config_isbool(k)) {
		DEBUG("%s is bool", k);
		ival = 1; /* default true */
		if (v) {
			if (!config_bool_convert(v, &ival)) {
				FAILMSG(LSD_ERROR_INVALID_OPTS,
					"%s requires boolean", k);
			}
		}
		err = config_set_int(db, k, ival, txn, dbi);
	}
	return err;
}

static int config_opts(int *argc, char **argv, MDB_txn *txn, MDB_dbi dbi)
{
	TRACE("%s()", __func__);
	int err = 0;
	char *k, *v;
	char db[2];
	config_db(DB_GLOBAL, db);

	for (int i = 1; i < *argc; i++) {
		if (!(strcmp(argv[i], "--debug"))) continue;
		v = argv[i+1];
		k = config_key(argv[i]);
		if (!k) {
			k = argv[i] + 2;
			if (strlen(argv[i]) > 4 && !strncmp(k, "no", 2 ) && config_isstr(k + 2)) {
				/* --no<option> */
				if ((err = config_del(db, k + 2, NULL, txn, dbi))
				&& (err != MDB_NOTFOUND))
				{
					break;
				}
				continue;
			}
			else {
				FAILMSG(LSD_ERROR_INVALID_OPTS, "Invalid option '%s'", argv[i]);
			}
		}
		if ((err = config_opt_set(k, v, txn, dbi))) break;
		i++;
	}

	return err;
}

static int config_process_line(char *line, size_t len, MDB_txn *txn, MDB_dbi dbi[])
{
	TRACE("%s()", __func__);
	int err = 0;
	char word[LINE_MAX + 1];

	if (len == 0) return 0;			/* skip blank lines */
	while (isblank(*line)){line++;len--;}	/* strip leading whitespace */
	if (line[0] == '#') return 0;		/* ignore comments */

	/* grab first word */
	for (int i = 0; i < (int)len && !isspace(*line);) {
		word[i] = *(line++);
		word[++i] = '\0';
	}
	/* strip leading whitespace from remaining line */
	while (isblank(*line)){line++;len--;}

	if (config_isopt(word))
		err = config_opt_set(word, line, txn, dbi[DB_GLOBAL]);
	else if (!strcmp(word, "proto")) {
		err = config_process_proto(line, len, txn, dbi[DB_PROTO]);
	}
	else if (!strcmp(word, "uri")) {
		err = config_process_uri(line, len, txn, dbi[DB_URI]);
	}
	else
		return LSD_ERROR_CONFIG_READ;

	return err;
}

static int config_create_dbs(MDB_txn *txn, MDB_dbi *dbi)
{
	TRACE("%s()", __func__);
	int flags = 0;
	int err = 0;
	char db[2];
	/* try to open database, else create it */
	for (int i = 0; i <= DB_URI; i++) {
		if (i == 1) flags |= MDB_INTEGERKEY;
		config_db(i, db);
		while ((err = mdb_dbi_open(txn, db, flags, &dbi[i]))) {
			if (err == MDB_NOTFOUND) {
				flags |= MDB_CREATE;
				DEBUG("creating db '%s'", db);
				continue;
			}
			FAILMSG(LSD_ERROR_CONFIG_WRITE, "config_init(): %s", mdb_strerror(err));
		}
		if (err)
			FAILMSG(LSD_ERROR_CONFIG_WRITE, "config_init(): %s", mdb_strerror(err));
	}

	/* set defaults for new database */
	if (((flags & MDB_CREATE) == MDB_CREATE)
	&& ((err = config_defaults(txn, dbi[DB_GLOBAL])) != 0))
	{
		FAILMSG(LSD_ERROR_CONFIG_WRITE, "Unable to set default config values");
	}

	return 0;
}

static int config_read(FILE *fd, MDB_txn *txn, MDB_dbi dbi[])
{
	TRACE("%s()", __func__);
	int err = 0;
	int line = 1;
	int p = 0;
	size_t len = 0;
	char buf[LINE_MAX + 1] = "";

	config_drop(txn, dbi);			/* drop old config */
	if ((err = config_create_dbs(txn, dbi))) return err;
	while (fgets(buf + p, LINE_MAX, fd)) {
		len = strlen(buf) - 1;
		buf[len] = '\0'; /* chop newline */
		p = (buf[len - 1] == '\\') ? len: 0;
		if (p) continue; /* line continuation */
		if ((err = config_process_line(buf, len, txn, dbi)) != 0) break;
		line++;
	}
	if (err)
		ERROR("Error %i in config, line %i:\n%s", err, line, buf);

	return err;
}

int config_init(int argc, char **argv)
{
	TRACE("%s()", __func__);
	int err = 0;
	char *filename = NULL;
	FILE *fd = NULL;
	MDB_txn *txn = NULL;
	MDB_dbi dbi[sizeof(config_db_idx_t)];
	MDB_val val;

	/* first, check if we're in debug mode */
	for (int i = 1; i < argc; i++) {
		if (!(strcmp(argv[i], "--debug"))) {
			loglevel = config_max("loglevel");
			DEBUG("Debugging mode enabled");
			break;
		}
	}

	config_init_db();	/* initialize lmdb */
	config_mime_load();	/* load mime.types */

	/* wrap config write in single transaction */
	if ((err = mdb_txn_begin(env, NULL, 0, &txn)) != 0)
		FAILMSG(LSD_ERROR_CONFIG_WRITE, "config_init(): %s", mdb_strerror(err));

	if ((err = config_create_dbs(txn, dbi))) goto config_init_done;

	/* process commands and options */
	if ((err = config_cmds(&argc, argv, txn, dbi))) goto config_init_done;
	if ((err = config_opts(&argc, argv, txn, dbi[DB_GLOBAL]))) goto config_init_done;

	/* process config file, if we have one */
	if (config_get("config", &val, txn, dbi[DB_GLOBAL]) == 0) {
		filename = (char *)val.mv_data;
		DEBUG("Loading config: '%s'", filename);
		if ((fd = fopen(filename, "r")) == NULL) FAIL(LSD_ERROR_CONFIG_READ);
		err = config_read(fd, txn, dbi);
		fclose(fd);
		if (err) goto config_init_done;
		/* commandline options must override config, so do this again */
		if ((err = config_opts(&argc, argv, txn, dbi[DB_GLOBAL])))
			goto config_init_done;
	}
	else if (!isatty(0)) { /* attempt to read config from stdin */
		DEBUG("Reading config from stdin");
		err = config_read(stdin, txn, dbi);
		/* commandline options must override config, so do this again */
		if ((err = config_opts(&argc, argv, txn, dbi[DB_GLOBAL])))
			goto config_init_done;
	}
	else {
		DEBUG("No config file");
	}
	if (!debug && !config_get("loglevel", &val, txn, dbi[DB_GLOBAL]))
		loglevel = *(int *)val.mv_data;
config_init_done:
	if (err && err != LSD_ERROR_CONFIG_COMMIT) {
		DEBUG("config not updated");
		mdb_txn_abort(txn);
		config_close();
	}
	else {
		DEBUG("config saved");
		mdb_txn_commit(txn);
		err = 0;
	}

	return err;
}
