/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * server.c
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

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "config.h"
#include "err.h"
#include "log.h"

#define BACKLOG 100

int server_listen(void)
{
	struct addrinfo hints = {0};
	struct addrinfo *a = NULL;
	struct addrinfo *ai = NULL;
	char cport[6];
	int n = 0;
	int sock = -1;
	int yes = 1;
	proto_t *p;
	MDB_val val;

	TRACE("%s()", __func__);

	/* allocate an array for sockets */
	while (config_yield_s(DB_PROTO, "proto", &val) == CONFIG_NEXT) { n++; }
	config_yield_free();
	DEBUG("n = %i", n);

	if (!n) return 0;
	socks = calloc(n, sizeof(int));
	n = 0;

	/* listen on all ports and protocols listed in config */
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = AI_PASSIVE;
	while (config_yield_s(DB_PROTO, "proto", &val) == CONFIG_NEXT) {
		p = val.mv_data;
		hints.ai_socktype = p->socktype;
		hints.ai_protocol = p->protocol; /* optional */
		sprintf(cport, "%u", p->port);
		for (int e = getaddrinfo(p->addr, cport, &hints, &a); a; a = a->ai_next) {
			if (e) FAILMSG(LSD_ERROR_GETADDRINFO, strerror(e));
			if (!ai) ai = a;
			if ((sock = socket(a->ai_family, a->ai_socktype, a->ai_protocol)) == -1)
				continue;
			if ((setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int))) == -1)
				continue;
			if ((bind(sock, a->ai_addr, a->ai_addrlen)) == -1)
				continue;
			break;
		}
		freeaddrinfo(ai); ai = NULL;
		if (sock != -1) {
			if (p->socktype == SOCK_STREAM) {
				(socks)[n] = sock;
				INFO("Listening on [%s]:%s", p->addr, cport);
				if ((listen((sock), BACKLOG)) == -1)
					DIE("listen() error: %s", strerror(errno));
			}
			n++;
		}
	}
	config_yield_free();

	return n;
}
