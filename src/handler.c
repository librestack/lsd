/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * handler.c
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

void handler_close(void)
{
	if (yield) config_yield_free();
	config_unload_modules();
	free(socks);
	config_close();
	DEBUG("handler exiting");
	_exit(0);
}

static void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}
	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

static int handle_connection(int idx, int sock)
{
	MDB_val val = { 0, NULL };
	conn_t c = {0};
	module_t *mod;
	int err = 0;
	struct sockaddr sa = {0};
	socklen_t slen = sizeof(struct sockaddr_in6);

	/* get IP address of peer */
	if (!getpeername(sock, &sa, &slen))
		inet_ntop(sa.sa_family, get_in_addr((struct sockaddr *)&sa),
		          c.addr, INET6_ADDRSTRLEN);

	DEBUG("connection received on socket %i", idx);
	c.sock = sock;
	for (int i = 0; config_yield_s(DB_PROTO, "proto", &val) == CONFIG_NEXT; i++) {
		if (idx == i) break;
	}
	if (val.mv_size > 0) {
		/* call handler module */
		c.proto = (proto_t *)val.mv_data;
		mod = (module_t *)config_module(c.proto->module, strlen(c.proto->module));
		if (!mod) goto handle_connection_err;
		int (* conn)(conn_t*);
		*(void **)(&conn) = dlsym(mod->ptr, "conn");
		if (conn) {
			err = conn(&c);
			goto handle_connection_exit;
		}
		else goto handle_connection_err;
	}
	config_yield_free();
	FAIL(LSD_ERROR_NOHANDLER);
handle_connection_exit:
	config_yield_free();
	return err;

handle_connection_err:
	config_yield_free();
	ERRMSG(LSD_ERROR_NOHANDLER);
	FAILMSG(LSD_ERROR_NOHANDLER, "%s", dlerror());
}

static int handler_get_socket(int n, fd_set fds[], int *sock)
{
	for (int i = 0; i < n; i++) {
		for (int j = 0; j < 3; j++) {
			if (FD_ISSET(socks[i], &fds[j])) {
				*sock = accept(socks[i], NULL, NULL);
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
					default:
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
static inline void handler_semaphore_release(void)
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
	config_init_db(NULL);

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
	handler_close();
}
