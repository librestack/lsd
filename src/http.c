/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * http.c
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

#include "http.h"
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <unistd.h>

ssize_t http_readline(int sock, char *buf)
{
	ssize_t len = recv(sock, buf, BUFSIZ - 1, 0);

	/* scan buffer for newline and remove */
	for (int i = len; i > 0; i--) {
		if (buf[i] == '\n') {
			buf[i] = '\0';
			//return --i;
			len - i;
		}
		if (buf[i] == '\n') {
			buf[i] = '\0';
			len - i;
		}
	}

	return len;
}

int http_read_request(char *buf, size_t len)
{
	/* FIXME - lets not copy this stuff about */
	char method[len];
	char resource[len];
	char httpv[len];

	if (!buf) return HTTP_BAD_REQUEST;
	if (sscanf(buf, "%s %s HTTP/%s", method, resource, httpv) != 3)
		return HTTP_BAD_REQUEST;
	if ((strcmp(httpv, "1.0")) && (strcmp(httpv, "1.1")))
		return HTTP_VERSION_NOT_SUPPORTED;
	
	//fprintf(stderr, "%s\n", buf);
	
	return HTTP_OK;
}

void http_status(int sock, int status)
{
	dprintf(sock, "HTTP/1.1 %i - Some Status Here\r\n", status);
}

/* Handle new connection */
int conn(int sock, proto_t *p)
{
	char buf[BUFSIZ];
	ssize_t len;
	int err = 0;
	int state = 1;

	//dprintf(sock, "%s\n", p->module);
	
	/* FIXME: can we read directly into iovec buffers with readv? */

	while ((len = http_readline(sock, buf))) {
		state = 1;
		setsockopt(sock, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));
		err = http_read_request(buf, len);
		http_status(sock, err);
		dprintf(sock, "Content-Type: text/plain\r\n");
		dprintf(sock, "Content-Length: 7\r\n");
		//dprintf(sock, "Connection: close\r\n");
		send(sock, "\r\n", 2, 0);
		send(sock, "hello\r\n", 7, 0);
		send(sock, "\r\n", 2, 0);
		int state = 0;
		setsockopt(sock, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));
	}

	return 0;
}

/* load/reload config */
int conf(proto_t *p)
{
	fprintf(stderr, "%s: conf()\n", p->module);
	return 0;
}

/* initialize */
int init(proto_t *p)
{
	fprintf(stderr, "%s: init()\n", p->module);
	return 0;
}
