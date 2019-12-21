/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * handler.c
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
#include "handler.h"
#include "log.h"
#include "lsd.h"
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/types.h>
#include <sys/sem.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netdb.h>
#include <unistd.h>

int handle_connection(int idx, int sock)
{
	MDB_val val = { 0, NULL };
	proto_t *p;
	int err = 0;

	DEBUG("connection received on socket %i", idx);
	for (int i = 0; config_yield(DB_PROTO, "proto", &val) == CONFIG_NEXT; i++) {
		if (idx == i) break;
	}
	if (val.mv_size > 0) {
		/* call handler module */
		p = (proto_t *)val.mv_data;
		char modname[128];
		snprintf(modname, 127, "src/%s.so", p->module); /* FIXME: module path */
		DEBUG("loading module '%s'", modname);
		void *mod = dlopen(modname, RTLD_LAZY);
		if (!mod) goto handle_connection_err;
		int (* conn)(int, proto_t*);
		conn = dlsym(mod, "conn");
		if (conn) {
		/* TODO: handle return codes - provide different facilities to different plugins */
			err = conn(sock, p);
			/* TODO if (err == NEW_LINE_PLEASE) etc. */
			dlclose(mod);
			goto handle_connection_exit;
		}
		else goto handle_connection_err;
	}
	config_yield(0, NULL, NULL);
	FAIL(LSD_ERROR_NOHANDLER);
handle_connection_exit:
	config_yield(0, NULL, NULL);
	return err;

handle_connection_err:
	config_yield(0, NULL, NULL);
	ERRMSG(LSD_ERROR_NOHANDLER);
	FAILMSG(LSD_ERROR_NOHANDLER, "%s", dlerror());
}

int handler_get_socket(int n, fd_set fds[], int *sock)
{
	for (int i = 0; i < n; i++) {
		for (int j = 0; j < 3; j++) {
			if (FD_ISSET(socks[i], &fds[j])) {
				*sock = accept(socks[i], NULL, NULL); /* TODO: EGAIN */
				if (*sock == -1) {
					switch (errno) {
					case EBADF:
						DEBUG("accept(): BADF");
						break;
					case EINVAL:
						DEBUG("accept(): EINVAL");
						break;
					case ENOTSOCK:
						DEBUG("accept(): ENOTSOCK");
						break;
					case EOPNOTSUPP:
						/* TODO: not SOCK_STREAM */
						DEBUG("accept(): not SOCK_STREAM");
						break;
					default: /* FIXME FIXME FIXME */
						perror("accept()");
					}
				}
				else {
					return i;
				}
			}
		}
	}
	return -1;
}

/* swap ready for busy semaphore so controller knows we're occupied */
static inline void handler_semaphore_release()
{
	struct sembuf sop[2];
	sop[0].sem_num = HANDLER_RDY;
	sop[0].sem_op = 1;
	sop[0].sem_flg = 0;
	sop[1].sem_num = HANDLER_BSY;
	sop[1].sem_op = 1;
	sop[1].sem_flg = SEM_UNDO; /* release semaphore on exit */
	semop(semid, sop, 2);
}

/* handler child process starting */
void handler_start(int n)
{
	int nfds = 0;
	int ret;
	int sock = 0;
	fd_set fds[3];

	/* handler needs own database env */
	mdb_env_close(env); env = NULL;
	config_init_db();
	config_unload_modules();

	/* prepare file descriptors for select() */
	for (int i = 0; i < 3; i++) { FD_ZERO(&fds[i]); }
	for (int i = 0; i < n; i++) {
		for (int j = 0; j < 3; j++) {
			FD_SET(socks[i], &fds[j]);
		}
		if (socks[i] > nfds) nfds = socks[i];
	}
	nfds++; /* highest socket number + 1 */
	ret = select(nfds, &fds[0], &fds[1], &fds[2], NULL);
	if (ret == -1)
		perror("select()");
	else if (ret) {
		ret = handler_get_socket(n, fds, &sock);
		if (ret != -1 && sock > 0) {
			handler_semaphore_release();
			handle_connection(ret, sock);
			close(sock);
		}
	}
	free(socks);
	config_close();
	DEBUG("handler exiting");
	_exit(0);
}
