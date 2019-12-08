/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * config.c
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

#include "config.h"
#include "err.h"
#include "log.h"
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

config_t config;

int config_bool_convert(char *val, int *ival)
{
	int i;
	char *truth[] = { "1", "true", "yes", "on" };
	char *falsy[] = { "0", "false", "no", "off" };
	for (i = 0; i < sizeof(truth) / sizeof(char *); i++) {
		if (strcmp(val, truth[i]) == 0) {
			*ival = 1;
			return 1;
		}
	}
	for (i = 0; i < sizeof(falsy) / sizeof(char *); i++) {
		if (strcmp(val, falsy[i]) == 0) {
			*ival = 0;
			return 1;
		}
	}
	return 0;
}

int config_min(char *key)
{
	CONFIG_LIMITS(CONFIG_MIN)
	return INT_MIN;
}

int config_max(char *key)
{
	CONFIG_LIMITS(CONFIG_MAX)
	return INT_MAX;
}

/* return false if string contains any non-numeric characters */
int isnumeric(char *v)
{
	for (int i = 0; i < strlen(v); i++) {
		if (!isdigit(v[i])) return 0;
	}
	return 1;
}

/* set key to val if numeric and within limits */
int config_int_set(char *klong, int *key, char *val)
{
	int min, max, i;

	if (!isnumeric(val)) return 0;
	i = atoi(val);

	/* check within limits */
	min = config_min(klong);
	max = config_max(klong);
	if (i < min || i > max)
		DIE("%s value must be between %i and %i", klong, min, max);
	
	*key = i;

	return (*key);
}

/* I'd like to have an argument please */
int argue(int *i, int argc, char **argv, void **key, char *kshort, char *klong, config_type_t typ)
{
	if (strcmp(argv[*i], klong) && strcmp(argv[*i], kshort))
		return 1;
	
	if (*i < argc - 1) {
		switch (typ) {
		case CONFIG_TYPE_BOOL:
			if (!config_bool_convert(argv[++(*i)], (int *)key))
				DIE("non boolean argument to %s/%s", kshort, klong);
			break;
		case CONFIG_TYPE_INT:
			if (!config_int_set(klong, (int *)key, argv[++(*i)]))
				DIE("non numeric argument to %s/%s", kshort, klong);
			break;
		case CONFIG_TYPE_STRING:
			*key = argv[++(*i)];
			break;
		case CONFIG_TYPE_INVALID:
			break;
		}
	}
	else {
		DIE("%s/%s missing value", kshort, klong);
	}

	return 0;
}

int config_process_line(char *line, size_t len)
{
	/* ignore blank lines */
	if (len == 0) return 0;

	/* ignore comments */
	if (line[0] == '#') return 0;

	/* print anything else */
	DEBUG("%s", line);

	return 0;
}

int config_read(char *map, size_t maplen)
{
	char buf[LINE_MAX];
	size_t len = 0;
	for (int i = 0; i < maplen; i++) {
		buf[len] = *(map++);
		if (buf[len] == '\n') {
			buf[len] = '\0';
			config_process_line(buf, len);
			len = 0;
		}
		else
			len++;
	}
	return 0;
}

void config_close(config_t c)
{
	munmap(c.map, c.sb.st_size);
	close(c.fd);
	shm_unlink(CONFIG_SHM);
}

int config_init(int argc, char **argv, config_t *c)
{
	int err = 0;
	static int fd;
	char *map;
	static struct stat sb;

	memset(c, 0, sizeof(config_t));

	/* set defaults */
	CONFIG_ITEMS(CONFIG_DEFAULTS)

	/* args first */
	for (int i = 1; i < argc; i++) {
#define X(key, ks, kl, type, var, value, helptxt) \
		if (!argue(&i, argc, argv, (void **)(&(c->key)), ks, kl, type)) continue;
		CONFIG_ITEMS(X)
#undef X
		FAILMSG(LSD_ERROR_INVALID_ARGS, "Unknown option '%s'", argv[i]);
	}

	/* process config file, if we have one */
	if (c->filename) {
		DEBUG("Loading config: '%s'", c->filename);

		/* mmap() gives us no guarantees about whether or not we'll see
		 * changes to the underlying file, so we need to take a copy */

		/* open & map config file */
		if ((fd = open(c->filename, O_RDONLY)) == -1) FAIL(LSD_ERROR_CONFIG_READ);
		if (fstat(fd, &sb) == -1) FAIL(LSD_ERROR_FILE_STAT_FAIL);
		DEBUG("Mapping file '%s' with %lld bytes", c->filename, (long long)sb.st_size);
		map = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);

		/* copy data into new map */
		if ((c->fd = shm_open(CONFIG_SHM, O_RDWR|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR)) == -1) {
			ERROR(strerror(errno));
			err = LSD_ERROR_CONFIG_SHM_FAIL;
		}
		if ((err == 0) && (ftruncate(c->fd, sb.st_size) != 0))
			err = LSD_ERROR_CONFIG_TRUNC_FAIL;
		if ((err == 0) && (fstat(c->fd, &c->sb) == -1)) FAIL(LSD_ERROR_FILE_STAT_FAIL);

		if (err == 0) {
			c->map = mmap(NULL, c->sb.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, c->fd, 0);
			if (c->map == MAP_FAILED) FAIL(LSD_ERROR_CONFIG_MMAP_FAIL);
		}
		if (err == 0)
			memcpy(c->map, map, sb.st_size);

		/* unmap & close config file */
		munmap(map, sb.st_size);
		close(fd);

		err = config_read(c->map, sb.st_size);
	}

	return err;
}
