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
int pid;
int run = 1;
int semid;
int *socks = NULL;

struct addrinfo * getaddrs(struct addrinfo **servinfo, struct addrinfo *hints, char *port)
{
	int status;

	if ((status = getaddrinfo(NULL, port, hints, servinfo)) != 0)
		DIE("%s", strerror(status));

	return *servinfo;
}

int server_listen(config_t *c, int **socks)
{
	struct addrinfo hints;
	struct addrinfo *a = NULL;
	struct addrinfo *addr = NULL;
	char h[NI_MAXHOST];
	char cport[6];
	int n = 0;
	int sock = -1;
	int yes = 1;

	proto_t *p;

	/* allocate an array for sockets */
	for (proto_t *p = c->protocols; p; p = p->next) { n++; }
	if (!n) return 0;
	*socks = calloc(n, sizeof(int));
	n = 0;

	/* listen on all ports and protocols listed in config */
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET6;
	hints.ai_flags = AI_PASSIVE;

	for (p = c->protocols; p; p = p->next) {
		DEBUG("Protocol: %s", p->proto);
		if (!strncmp(p->proto, "udp", 3)) {
			DEBUG("listen on %u/udp", p->port);
			hints.ai_socktype = SOCK_DGRAM;
			sprintf(cport, "%u", p->port);
		}
		else if (!strncmp(p->proto, "tcp", 3)) {
			DEBUG("listen on %u/tcp", p->port);
			hints.ai_socktype = SOCK_STREAM;
			sprintf(cport, "%u", p->port);
		}
		else {
			DEBUG("listen on %u/wtf", p->port);
			sprintf(cport, "%u", p->port);
		}

#define CLEANUP(msg) { \
		ERROR(msg, strerror(errno)); \
		freeaddrinfo(addr); \
		return -1; }

		for (a = getaddrs(&addr, &hints, cport); a; a = a->ai_next) {
			if (getnameinfo(a->ai_addr, a->ai_addrlen, h, NI_MAXHOST, NULL, 0, NI_NUMERICSERV))
				CLEANUP("getnameinfo() error: %s");
			DEBUG("Binding to %s", h);
			if ((sock = socket(a->ai_family, a->ai_socktype, a->ai_protocol)) == -1)
				CLEANUP("socket() error: %s");
			if ((setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int))) == -1)
				CLEANUP("setsockopt() error: %s");
			if ((bind(sock, a->ai_addr, a->ai_addrlen)) == -1)
				CLEANUP("bind() error: %s");
		}
#undef CLEANUP
		freeaddrinfo(addr);
		(*socks)[n] = sock;
		DEBUG("listening on socket %i", sock);
		if ((listen((sock), BACKLOG)) == -1)
			DIE("listen() error: %s", strerror(errno));
		n++;
	}

	return n;
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

void sighup_handler(int signo)
{
	if (pid > 0) {
		DEBUG("HUP received by controller");
		/* TODO: load/process and switch to new config and signal
		 * handlers */
	}
	else {
		DEBUG("HUP received by handler");
		/* TODO: switch to new config */
	}
}

void sigint_handler(int signo)
{
	if (pid > 0) {
		DEBUG("INT received by controller");
		run = 0;
	}
	else {
		DEBUG("INT received by handler");
		free(socks);
		config_close(&config);
		_exit(EXIT_SUCCESS);
	}
}

int main(int argc, char **argv)
{
	int busy;
	int err;
	int n;
	struct sembuf sop[2];

	if ((err = config_init(argc, argv, &config)) != 0) return err;

	INFO("Starting up...");

	if (!(n = server_listen(&config, &socks)))
		goto exit_controller;

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
	signal(SIGHUP, sighup_handler);
	signal(SIGINT, sigint_handler);

	if (!socks[0]) run = 0; /* no sockets, give up */

	while (run) {
		if ((err = semop(semid, sop, 1)) == -1) {
			if (errno == EINTR) continue;
			break;
		}

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
			int conn = 0;
			int nfds = 0;
			int ret;
			fd_set rfds, wfds, efds;

			/* child handler process */
			DEBUG("handler %i started", handlers);

			/* prepare file descriptors for select() */
			FD_ZERO(&rfds);
			FD_ZERO(&wfds);
			FD_ZERO(&efds);
			for (int i = 0; i < n; i++) {
				DEBUG("select() on sock %i", socks[i]);
				FD_SET(socks[i], &rfds);
				FD_SET(socks[i], &wfds);
				FD_SET(socks[i], &efds);
				if (socks[i] > nfds) nfds = socks[i];
			}
			nfds++; /* highest socket number + 1 */
			ret = select(nfds, &rfds, &wfds, &efds, NULL);
			if (ret == -1)
				perror("select()");
			else if (ret) {
				for (int i = 0; i < n; i++) {
					if (FD_ISSET(socks[i], &rfds)) {
						conn = accept(socks[i], NULL, NULL); /* TODO: EGAIN */
						if (conn == -1) perror("accept()");
					}
					if (FD_ISSET(socks[i], &wfds)) {
						conn = accept(socks[i], NULL, NULL); /* TODO: EGAIN */
						if (conn == -1) perror("accept()");
					}
					if (FD_ISSET(socks[i], &efds)) {
						conn = accept(socks[i], NULL, NULL); /* TODO: EGAIN */
						if (conn == -1) perror("accept()");
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
			DEBUG("handler exiting");
			_exit(0);
		}
	}
exit_controller:
	free(socks);
	config_close(&config);

	DEBUG("controller exiting");

	return 0;
}
