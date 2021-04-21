/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only
 *
 * lsd.c
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
#include "server.h"
#include <arpa/inet.h>
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

static void sigchld_handler(int __attribute__((unused)) signo)
{
	struct sembuf sop;

	TRACE("%s()", __func__);
	while (waitpid(-1, NULL, WNOHANG) > 0) --handlers; /* reap children */

	/* check handler count, in case any were killed */
	if (handlers < HANDLER_MIN) {
		int n = HANDLER_MIN - handlers;
		DEBUG("handler(s) killed, creating %i handlers", n);
		sop.sem_num = HANDLER_RDY;
		sop.sem_op = n;
		sop.sem_flg = 0;
		semop(semid, &sop, 1);
	}
}

static void sighup_handler(int __attribute__((unused)) signo)
{
	TRACE("%s()", __func__);
	if (pid > 0) {
		DEBUG("HUP received by controller");
		/* reload config */
		DEBUG("reloading config");
		config_init(0, NULL);
	}
	else {
		DEBUG("HUP received by handler");
	}
}

static void sigint_handler(int __attribute__((unused)) signo)
{
	TRACE("%s()", __func__);
	if (pid > 0) {
		DEBUG("INT received by controller");
		run = 0;
	}
	else {
		DEBUG("INT received by handler");
		handler_close();
	}
}

int main(int argc, char **argv)
{
	int busy;
	int err;
	struct sembuf sop[2];

	/* process args and config */
	if ((err = config_init(argc, argv)) != 0) return err;

	/* if we've not been told to start, don't */
	if (!run) goto exit_controller;

	INFO("Starting up...");

	config_load_modules();

	/* listen on sockets */
	if (!(run = server_listen())) {
		INFO("No protocols configured");
		goto exit_controller;
	}

	/* TODO: drop privs */

	/* TODO: daemonize? fork */

	/* initialize semaphores */
	semid = semget(IPC_PRIVATE, 2, IPC_CREAT | IPC_EXCL | S_IRUSR | S_IWUSR);
	if (semid == -1) DIE("Unable to create semaphore");
	if ((err = semctl(semid, HANDLER_RDY, SETVAL, HANDLER_MIN)) == -1)
			error_at_line(1, errno, __FILE__, __LINE__-1, "semctl %i", errno);
	if ((err = semctl(semid, HANDLER_BSY, SETVAL, 0)) == -1)
			error_at_line(1, errno, __FILE__, __LINE__-1, "semctl %i", errno);
	sop[0].sem_num = HANDLER_RDY;
	sop[0].sem_op = -1; /* decrement */
	sop[0].sem_flg = 0;

	/* set signal handlers */
	signal(SIGCHLD, sigchld_handler);
	signal(SIGHUP, sighup_handler);
	signal(SIGINT, sigint_handler);

	while (run) {
		/* get HANDLER_RDY semaphore before continuing */
		if ((err = semop(semid, sop, 1)) == -1) {
			if (errno == EINTR) continue;
			break;
		}
		if (handlers >= HANDLER_MAX) continue;
		if ((busy = semctl(semid, HANDLER_BSY, GETVAL)) == -1)
			CONTINUE(LOG_ERROR, "unable to read busy semaphore");
		if ((handlers - busy) >= HANDLER_MIN) continue;
		DEBUG("forking new handler");
		if ((pid = fork()) == -1) {
			ERROR("fork failed");
			sop[0].sem_op = 1; /* increment */
			semop(semid, sop, 1);
			sop[0].sem_op = -1;
			continue;
		}
		handlers++;
		if (pid == 0) { /* child handler process */
			DEBUG("handler %i started", handlers);
			handler_start(run);
		}
	}
exit_controller:
	while (handlers) close(socks[handlers--]);
	config_unload_modules();
	config_close();
	INFO("Controller exiting");

	return 0;
}
