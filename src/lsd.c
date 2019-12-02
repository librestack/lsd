/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * lsd.c
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

#define BACKLOG 100
#define HANDLER_MAX 100 /* maximum number of handler processes */
#define HANDLER_MIN 5	/* minimum number of handlers to keep ready */
#define HANDLER_RDY 0	/* semapahore to track ready handlers */
#define HANDLER_BSY 1	/* semapahore to track busy handlers */

int handlers = 0;
int semid;

struct addrinfo * getaddrs(struct addrinfo **servinfo)
{
	struct addrinfo hints;
	int status;
	const char tcpport[5] = "80";

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if ((status = getaddrinfo(NULL, tcpport, &hints, servinfo)) != 0) {
		LOG(LOG_ERROR, "%s", strerror(status));
		_exit(EXIT_FAILURE);
	}

	return *servinfo;
}

int server_listen()
{
	struct addrinfo *p = NULL;
	struct addrinfo *addr = NULL;
	char h[NI_MAXHOST];
	int sock = -1;
	int yes = 1;

	/* sockets and stuff */
	for (p = getaddrs(&addr); p; p = p->ai_next) {
		/* FIXME: error handling in here */
		getnameinfo(p->ai_addr, p->ai_addrlen, h, NI_MAXHOST, NULL, 0, NI_NUMERICSERV);
		LOG(LOG_DEBUG, "Binding to %s", h);
		sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
		bind(sock, p->ai_addr, p->ai_addrlen);
	} 
	freeaddrinfo(addr);

	listen(sock, BACKLOG); /* FIXME: error handling */

	return sock;
}

void sigchld_handler(int signo)
{
	int ready, busy;
	struct sembuf sop;

	while (waitpid(-1, NULL, WNOHANG) > 0) --handlers;

	ready = semctl(semid, HANDLER_RDY, GETVAL);
	busy = semctl(semid, HANDLER_BSY, GETVAL);
	LOG(LOG_DEBUG, "handler exited, %i remaining (ready: %i, busy: %i)", handlers, HANDLER_MIN - ready, busy);

	/* check that processes haven't been killed */
	if (handlers < HANDLER_MIN) {
		LOG(LOG_DEBUG, "HANDLER KILLED");
		LOG(LOG_DEBUG, "need to create %i handlers", HANDLER_MIN - handlers);
		sop.sem_num = HANDLER_RDY;
		sop.sem_op = HANDLER_MIN - handlers;
		sop.sem_flg = 0;
		semop(semid, &sop, 1);
	}
}

int main(int argc, char **argv)
{
	int sock;
	int pid;
	int err;
	struct sembuf sop[2];

	LOG(LOG_DEBUG, "Starting up...");

	sock = server_listen();
	assert(sock != -1);

	/* TODO: drop privs */

	/* TODO: daemonize? fork */

	/* semaphores for handler tracking 
	 * our aim is to enaure we always have HANDLER_MIN handlers waiting ready 
	 * while not exceeding HANDLER_MAX handers */
	semid = semget(IPC_PRIVATE, 2, IPC_CREAT | IPC_EXCL | S_IRUSR | S_IWUSR);
	assert(semid != -1); /* FIXME: error handling */

	/* initialize semaphores */
	if ((err = semctl(semid, HANDLER_RDY, SETVAL, HANDLER_MIN)) == -1)
			error_at_line(1, errno, __FILE__, __LINE__-1, "semctl %i", errno);
	if ((err = semctl(semid, HANDLER_BSY, SETVAL, 0)) == -1)
			error_at_line(1, errno, __FILE__, __LINE__-1, "semctl %i", errno);

	sop[0].sem_num = HANDLER_RDY;
	sop[0].sem_op = -1; /* decrement */
	sop[0].sem_flg = 0;

	signal(SIGCHLD, sigchld_handler);

	for (;;) {
		int ready, busy;
		ready = semctl(semid, HANDLER_RDY, GETVAL);
		busy = semctl(semid, HANDLER_BSY, GETVAL);
		LOG(LOG_DEBUG, "PARENT: ready = %i, busy = %i", HANDLER_MIN - ready, busy);

		while ((err = semop(semid, sop, 1)) != 0); /* loop in case of EINTR */

		if (handlers >= HANDLER_MIN) continue;

		LOG(LOG_DEBUG, "PARENT: forking new handler");
		if ((pid = fork()) == -1) {
			LOG(LOG_ERROR, "fork failed");
			sop[0].sem_op = 1; /* increment */
			semop(semid, sop, 1);
			sop[0].sem_op = -1;
			continue;
		}
		handlers++;
		if (pid == 0) {
			/* child handler process */
			LOG(LOG_DEBUG, "handler %i started", handlers);

			int ready, busy;
			ready = semctl(semid, HANDLER_RDY, GETVAL);
			busy = semctl(semid, HANDLER_BSY, GETVAL);
			LOG(LOG_DEBUG, "HANDLER: ready = %i, busy = %i", HANDLER_MIN - ready, busy);

			int conn = accept(sock, NULL, NULL);
			LOG(LOG_DEBUG, "handler accepted connection");

			ready = semctl(semid, HANDLER_RDY, GETVAL);
			busy = semctl(semid, HANDLER_BSY, GETVAL);
			LOG(LOG_DEBUG, "HANDLER: ready = %i, busy = %i", HANDLER_MIN - ready, busy);

			/* swap ready for busy semaphore */
			sop[0].sem_num = HANDLER_RDY;
			sop[0].sem_op = 1;
			sop[0].sem_flg = 0;
			sop[1].sem_num = HANDLER_BSY;
			sop[1].sem_op = 1;
			sop[1].sem_flg = SEM_UNDO; /* release semaphore on exit */
			semop(semid, sop, 2);

			ready = semctl(semid, HANDLER_RDY, GETVAL);
			busy = semctl(semid, HANDLER_BSY, GETVAL);
			LOG(LOG_DEBUG, "HANDLER: sem updated ready = %i, busy = %i", HANDLER_MIN - ready, busy);

			close(conn);
			sleep(2); /* pretend we're doing something */
			LOG(LOG_DEBUG, "handler done processing");

			exit(0);
		}
	}

	return 0;
}
