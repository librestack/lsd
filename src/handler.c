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
#include "handler.h"
#include "log.h"
#include "lsd.h"
#include <assert.h>
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

void handler_start(int n)
{
	int conn = 0;
	int nfds = 0;
	int ret;
	struct sembuf sop[2];
	fd_set fds[3];

	/* handler needs own database env */
	mdb_env_close(env);
	config_init_db();

	/* prepare file descriptors for select() */
	for (int i = 0; i < 3; i++) { FD_ZERO(&fds[i]); }
	for (int i = 0; i < n; i++) {
		DEBUG("select() on sock %i", socks[i]);
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
		for (int i = 0; i < n; i++) {
			for (int j = 0; j < 3; j++) {
				if (FD_ISSET(socks[i], &fds[j])) {
					conn = accept(socks[i], NULL, NULL); /* TODO: EGAIN */
					if (conn == -1) {
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
				}
			}
		}
		if (conn > 0) {
			DEBUG("handler accepted connection");
			/* swap ready for busy semaphore */
			sop[0].sem_num = HANDLER_RDY;
			sop[0].sem_op = 1;
			sop[0].sem_flg = 0;
			sop[1].sem_num = HANDLER_BSY;
			sop[1].sem_op = 1;
			sop[1].sem_flg = SEM_UNDO; /* release semaphore on exit */
			semop(semid, sop, 2);
			close(conn);
			sleep(2); /* pretend we're doing something */
		}
	}
	free(socks);
	config_close();
	DEBUG("handler exiting");
	_exit(0);
}
