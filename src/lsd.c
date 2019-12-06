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

#include "config.h"
#include "log.h"
#include "lsd.h"
#include <assert.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <signal.h>
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

/* TODO: listen on 80 + 443 if root, 8080 + 8443 if not */

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

	if ((status = getaddrinfo(NULL, tcpport, &hints, servinfo)) != 0)
		DIE("%s", strerror(status));

	return *servinfo;
}

int server_listen()
{
	struct addrinfo *p = NULL;
	struct addrinfo *addr = NULL;
	char h[NI_MAXHOST];
	int sock = -1;
	int yes = 1;

#define CLEANUP(msg) { \
		ERROR(msg, strerror(errno)); \
		freeaddrinfo(addr); \
		_exit(EXIT_FAILURE); }

	for (p = getaddrs(&addr); p; p = p->ai_next) {
		if (getnameinfo(p->ai_addr, p->ai_addrlen, h, NI_MAXHOST, NULL, 0, NI_NUMERICSERV))
			CLEANUP("getnameinfo() error: %s");
		DEBUG("Binding to %s", h);
		if ((sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
			CLEANUP("socket() error: %s");
		if ((setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int))) == -1)
			CLEANUP("setsockopt() error: %s");
		if ((bind(sock, p->ai_addr, p->ai_addrlen)) == -1)
			CLEANUP("bind() error: %s");
	}
#undef CLEANUP
	freeaddrinfo(addr);

	if ((listen(sock, BACKLOG)) == -1)
		DIE("listen() error: %s", strerror(errno));

	return sock;
}

void sigchld_handler(int signo)
{
	struct sembuf sop;

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

int main(int argc, char **argv)
{
	int busy;
	int err;
	int pid;
	int sock;
	struct sembuf sop[2];

	INFO("Starting up...");

	config_init(argc, argv);

	sock = server_listen();
	assert(sock != -1); /* FIXME */

	/* TODO: drop privs */

	/* TODO: daemonize? fork */

	semid = semget(IPC_PRIVATE, 2, IPC_CREAT | IPC_EXCL | S_IRUSR | S_IWUSR);
	if (semid == -1) DIE("Unable to create semaphore");

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
		while ((err = semop(semid, sop, 1))); /* loop in case of EINTR */

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
		if (pid == 0) {
			/* child handler process */
			DEBUG("handler %i started", handlers);

			int conn = accept(sock, NULL, NULL);
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
			DEBUG("handler exiting");

			_exit(0);
		}
	}

	return 0;
}
