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

#include "err.h"
#include "http.h"
#include "iov.h"
#include "log.h"
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <sys/uio.h>
#include <unistd.h>

char buf[BUFSIZ];
struct iovec *msg_iov;

int setcork(int sock, int state)
{
	return setsockopt(sock, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));
}

size_t http_status(char *status, http_status_code_t code)
{
	/* TODO: actually look up codes */
	return sprintf(status, "HTTP/1.1 %i - Some Status Here\r\n", code);
}

/* advance ptr to end of word, return length */
size_t wordend(char **ptr, size_t ptrmax, size_t maxlen)
{
	size_t i;
	maxlen = (ptrmax < maxlen) ? ptrmax : maxlen; /* lowest limit */
	for (i = 0; i < maxlen && !isspace((*ptr)[i]); i++);
	return i;
}

/* advance ptr to next word, return offset */
size_t skipspace(char **ptr, size_t i, size_t maxlen)
{
	*ptr += i;
	for (i = 0; i < maxlen && isblank((*ptr)[i]); i++);
	*ptr += i;
	return i;
}

/*
 * first pass processing request headers
 * 1. ignore everything we can
 * 2. process anything of immediate importance
 * 3. defer processing of everything else
 * return 0 for success, or http_status_code_t for error
 */
int http_header_process(http_request_t *req, http_response_t *res,
			struct iovec *k, struct iovec *v)
{
	(void) req; /* FIXME - unused */
	(void) res; /* FIXME - unused */
	if (!iovcmp(k, "Host")) {
		iovcpy(&req->host, v);
	}
	else if (!iovcmp(k, "Accept")) {
		iovcpy(&req->accept, v);
	}
	else if (!iovcmp(k, "Accept-Encoding")) {
		iovcpy(&req->encoding, v);
	}
	else if (!iovcmp(k, "Accept-Language")) {
		iovcpy(&req->lang, v);
	}
	else if (!iovcmp(k, "Connection")) {
		req->close = !iovcmp(v, "close");
	}
	else if (!iovcmp(k, "Upgrade-Insecure-Requests")) {
		req->upsec = !iovcmp(v, "1");
	}
	else if (!iovcmp(k, "Cache-Control")) {
		iovcpy(&req->cache, v);
	}
	return 0;
}

static inline http_status_code_t
http_headers_read(char *buf, http_request_t *req, http_response_t *res)
{
	char *ptr, *crlf;
	struct iovec header, val;
	size_t i;
	int err;

	ptr = buf;
	while (ptr < buf + req->len) {
		i = wordend(&ptr, BUFSIZ, req->len);
		if (i == 0 || i == req->len) break;
		iovset(&header, ptr, i - 1);
		ptr += i + 1;
		crlf = strstr(ptr, "\r\n");
		iovset(&val, ptr, crlf - ptr);
		if ((err = http_header_process(req, res, &header, &val)))
			return err;
		ptr = crlf + 2;
	}
	return HTTP_OK;
}

http_status_code_t
http_request_read(int sock, http_request_t *req, http_response_t *res)
{
	size_t i;
	char *ptr;

	req->len = recv(sock, buf, BUFSIZ, 0);
	ptr = buf;

	i = wordend(&ptr, HTTP_METHOD_MAX, req->len);	/* HTTP method */
	if (i == 0 || i == req->len)
		return HTTP_BAD_REQUEST;
	iovset(&req->method, buf, i);

	if (skipspace(&ptr, i, req->len) == req->len)
		return HTTP_BAD_REQUEST;

	i = wordend(&ptr, HTTP_URI_MAX, req->len);	/* URI */
	if (i == 0 || i == req->len)
		return HTTP_BAD_REQUEST;
	iovset(&req->uri, ptr, i);

	if (skipspace(&ptr, i, req->len) == req->len)
		return HTTP_BAD_REQUEST;

	i = wordend(&ptr, HTTP_VERSION_MAX, req->len);	/* HTTP version */
	if (i == 0 || i == req->len)
		return HTTP_BAD_REQUEST;
	iovset(&req->httpv, ptr, i);

	ptr += i;
	if (memcmp(ptr, "\r\n", 2))			/* CRLF */
		return HTTP_BAD_REQUEST;
	ptr += 2;

	return http_headers_read(ptr, req, res);
}

int http_response_send(int sock, http_request_t *req, http_response_t *res)
{
	(void) req; /* FIXME - unused */
	(void) res; /* FIXME - unused */

	setcork(sock, 1);
	writev(sock, res->iovs.iov, res->iovs.idx);
	setcork(sock, 0);
	return 0;
}

http_status_code_t
http_request_handle(http_request_t *req, http_response_t *res)
{
	(void) req; /* FIXME - unused */
	(void) res; /* FIXME - unused */
	DEBUG("%s()", __func__);
	MDB_val val = { 0, NULL };

/*TODO TODO TODO TODO TODO TODO TODO TODO */

	for (int i = 0; config_yield(HTTP_DB_URI, NULL, &val) == CONFIG_NEXT; i++) {
		DEBUG("checking uri");
	}
	config_yield_free();

	return HTTP_OK;
}

/* Handle new connection */
int conn(int sock, proto_t *p)
{
	(void) p; /* FIXME - unused */
	loglevel = 127; /* FIXME */
	http_response_t res = {};
	http_request_t req = {};
	char status[128];
	char clen[128];
	char ctyp[128];
	int err = 0;

	/* we need to do this here, so the env is created in this process
	 * at init() time, the module is being called by the controller, and we
	 * can't share the env from a different process */
	env = NULL; config_init_db();

	err = http_request_read(sock, &req, &res);

	DEBUG("Host requested: %.*s", (int)req.host.iov_len,
				   (char *)req.host.iov_base);

	DEBUG("Upsec: %i", req.upsec);
	DEBUG("Close: %i", req.close);

	if (err == HTTP_OK)
		err = http_request_handle(&req, &res);

	/* prepare response */
	res.iovs.nmemb = 5; /* number of iov structs to allocate at once */
	iov_push(&res.iovs, status, http_status(status, err));
	iov_push(&res.iovs, clen, sprintf(clen, "Content-Length: %zu\r\n", req.len));
	iov_push(&res.iovs, ctyp, sprintf(ctyp, "Content-type: text-plain\r\n"));
	iov_push(&res.iovs, "\r\n", 2);
	iov_push(&res.iovs, buf, req.len);

	err = http_response_send(sock, &req, &res);
	free(res.iovs.iov);
	mdb_env_close(env); env = NULL;

	return err;
}

/* pack (length) size_t and string into ptr, return new ptr */
char * packstr(char *ptr, char *str)
{
	size_t len = (str) ? strlen(str) : 0;
	memcpy(ptr, &len, sizeof(size_t));
	ptr += sizeof(size_t);
	if (len) memcpy(ptr, str, len);
	return ptr;
}

int load_uri(char *line, MDB_txn *txn)
{
	MDB_val k,v;
	static size_t uris = 0;
	size_t len = strlen(line);
	int c;
	char proto = 0; /* default: http */
	char uri[len + 1];
	char method[len + 1];
	char action[len + 1];
	char args[len + 1];
	char *path;
	char *host = NULL;
	char *port = NULL; /* FIXME: port -> unsigned short */
	char pack[len + sizeof(size_t) * 4];
	char * ptr;
	char * pp = pack;

	memset(pack, 0, sizeof(pack));

	loglevel = 127; /* FIXME - remove */

	/* protocol must be http:// or https:// */
	if (memcmp(line, "http", 4)) return LSD_ERROR_CONFIG_INVALID;
	line += 4;
	if (!memcmp(line, "s://", 4)) {
		proto = 1; /* https */
		line++;
	}
	else if (memcmp(line, "://", 3))
		return LSD_ERROR_CONFIG_INVALID;
	line += 3;
	pp[0] = proto;
	ptr = pp + 1;

	/* split remaining line on whitespace */
	c = sscanf(line, "%s %s %s %[^\n]", uri, method, action, args);
	if (c < 3) return LSD_ERROR_CONFIG_INVALID;
	if (c == 3) args[0] = '\0';
	DEBUG("uri: '%s'", uri);
	DEBUG("method: '%s'", method);
	DEBUG("action: '%s'", action);
	DEBUG("args: '%s'", args);

	/* split up the uri to get host, port and path */
	path = strchr(uri, '/');
	if (!path) return LSD_ERROR_CONFIG_INVALID;
	if (path == uri) {
		DEBUG("No host");
	}
	else {
		path[0] = '\0';
		host = uri;
		if ((!memcmp(host, "[", 1)) && (port = strstr(uri, "]:"))) {
			/* IPv6 address with port */
			host++;
			port[0] = '\0';
			port += 2;
		}
		else if ((port = strchr(uri, ':'))) {
			/* host and port */
			port[0] = '\0';
			port++;
		}
	}
	path++;
	DEBUG("Host: '%s'", host);
	DEBUG("Port: '%s'", port);
	DEBUG("Path: '%s'", path);

	ptr = packstr(ptr, method);
	ptr = packstr(ptr, action);
	ptr = packstr(ptr, args);
	ptr = packstr(ptr, host);
	ptr = packstr(ptr, port);
	ptr = packstr(ptr, path);
	k.mv_data = &uris;
	k.mv_size = sizeof(size_t);
	v.mv_data = pack;
	v.mv_size = sizeof(pack);
	config_set(HTTP_DB_URI, &k, &v, txn, 0, MDB_INTEGERKEY | MDB_CREATE);
	uris++;

	return 0;
}
void finit()
{
	config_close();
}

/* load/reload config */
int conf()
{
	return 0;
}

/* initialize */
int init()
{
	return 0;
}
