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

#define IOVSIZE 5 /* number of iov structures to allocate at once */

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
	if (!iovstrcmp(k, "Host")) {
		iovcpy(&req->host, v);
	}
	else if (!iovstrcmp(k, "Accept")) {
		iovcpy(&req->accept, v);
	}
	else if (!iovstrcmp(k, "Accept-Encoding")) {
		iovcpy(&req->encoding, v);
	}
	else if (!iovstrcmp(k, "Accept-Language")) {
		iovcpy(&req->lang, v);
	}
	else if (!iovstrcmp(k, "Connection")) {
		req->close = !iovstrcmp(v, "close");
	}
	else if (!iovstrcmp(k, "Upgrade-Insecure-Requests")) {
		req->upsec = !iovstrcmp(v, "1");
	}
	else if (!iovstrcmp(k, "Cache-Control")) {
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
	return 0;
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

char * unpackiov(char *ptr, struct iovec *iov)
{
	size_t len = *(size_t *)ptr;
	iov->iov_len = len;
	ptr += sizeof(size_t);
	iov->iov_base = (len) ? ptr : NULL;
	return ptr + len;
}

int http_match_uri(http_request_t *req, struct iovec uri[HTTP_PARTS])
{
	if (iovcmp(&req->method, &uri[HTTP_METHOD]))
		return 0;
	
	/* Host: header */
	if (uri[HTTP_DOMAIN].iov_len != 0) {
		if ((iovcmp(&req->host, &uri[HTTP_DOMAIN])) 
		&&  (iovcmp(&req->host, &uri[HTTP_HOST])))
			return 0;
	}

	/* path */
	if (!iovmatch(&uri[HTTP_PATH], &req->uri, 0))
		return 1;

	return 0;
}

http_status_code_t
http_request_handle(http_request_t *req, http_response_t *res)
{
	DEBUG("%s()", __func__);
	MDB_val val = { 0, NULL };

	/* protocol, method, action, args, host, port, path */
	char *ptr;
	char tls;
	char found = 0;
	struct iovec uri[HTTP_PARTS];

	for (int i = 0; config_yield(HTTP_DB_URI, NULL, &val) == CONFIG_NEXT; i++) {
		ptr = (char *)val.mv_data;
		tls = ptr[0];
		ptr++;

		/* https requests only match https uris */
		if ((tls && strcmp(req->proto->module, "https")) 
		|| (!tls && !strcmp(req->proto->module, "https")))
			continue;

		for (int j = 0; j < HTTP_PARTS; j++) {
			ptr = unpackiov(ptr, &uri[j]);
		}

		/* http_match_uri */
		if (http_match_uri(req, uri)) {
			memcpy(res->uri, uri, sizeof(struct iovec) * HTTP_PARTS);
			found++;
			break;
		}
	}
	config_yield_free();
	if (!found) return HTTP_NOT_FOUND;

	return 0;
}

int http_response_code(struct iovec *uri, size_t len)
{
	int code;
	void * ptr;
	len++;
	/* find closing bracket */
	if (!(ptr = memchr(uri->iov_base, ')', uri->iov_len)))
		return HTTP_INTERNAL_SERVER_ERROR;
	/* response code must be 3 bytes */
	if (ptr - uri->iov_base - len != 3)
		return HTTP_INTERNAL_SERVER_ERROR;
	/* extract the code */
	code = (int)strtol(uri->iov_base + len, NULL, 10);
	return code;
}

http_status_code_t
http_response_static(int sock, http_request_t *req, http_response_t *res)
{
	(void)sock;
	(void)req;
	(void)res;
	/* TODO TODO TODO TODO TODO TODO TODO TODO TODO */
	return HTTP_NOT_IMPLEMENTED;
}

/* returning nonzero means the response has already been sent by the handler */
http_status_code_t
http_response(int sock, http_request_t *req, http_response_t *res)
{
	http_status_code_t code = 0;

	/* response(code) - return status, with args as body */
	if (!iovstrncmp(&res->uri[HTTP_ACTION], "response", 8)) {
		DEBUG("RESPONSE: response");
		code = http_response_code(&res->uri[HTTP_ACTION], 8);
		res->body = res->uri[HTTP_ARGS];
	}
	/* redirect(code) - HTTP redirect */
	else if (!iovstrncmp(&res->uri[HTTP_ACTION], "redirect", 8)) {
		code = http_response_code(&res->uri[HTTP_ACTION], 8);
		DEBUG("RESPONSE: redirect (%i)", code);
		if ((code < HTTP_MOVED_PERMANENTLY) || (code > HTTP_SEE_OTHER))
			return HTTP_INTERNAL_SERVER_ERROR;
		iov_pushs(&res->head, "Location: ");
		iov_pushv(&res->head, &res->uri[HTTP_ARGS]);
	}
	/* serve static file */
	else if (!iovstrcmp(&res->uri[HTTP_ACTION], "static")) {
		DEBUG("RESPONSE: static");
		code = http_response_static(sock, req, res);
	}
	else if (!iovstrcmp(&res->uri[HTTP_ACTION], "echo")) {
		DEBUG("RESPONSE: echo");
		iovset(&res->body, buf, req->len);
		iov_pushs(&res->head, "Content-type: text-plain\r\n");
		code = HTTP_OK;
	}
	else return HTTP_INTERNAL_SERVER_ERROR;
	return code;
}

/* Handle new connection */
int conn(int sock, proto_t *p)
{
	http_response_t res = {};
	http_request_t req = {};
	char status[128];
	char clen[128];
	int err = 0;

	req.proto = p;
	res.iovs.nmemb = IOVSIZE;
	res.head.nmemb = IOVSIZE;

	/* we need to do this here, so the env is created in this process
	 * at init() time, the module is being called by the controller, and we
	 * can't share the env from a different process */
	env = NULL; config_init_db();

	err = http_request_read(sock, &req, &res);

	DEBUG("Host requested: %.*s", (int)req.host.iov_len,
				   (char *)req.host.iov_base);

	DEBUG("Upsec: %i", req.upsec);
	DEBUG("Close: %i", req.close);

	/* as soon as we have a code (err != 0), we are ready to respond */
	if (!err) err = http_request_handle(&req, &res);
	if (!err) err = http_response(sock, &req, &res);
	if (err) {
		/* status */
		iov_push(&res.iovs, status, http_status(status, err));

		/* headers */
		iov_push(&res.iovs, clen,
			sprintf(clen, "Content-Length: %zu\r\n", res.body.iov_len));

		/* push additional headers */
		for (size_t i = 0; i < res.head.idx; i++) {
			iov_pushv(&res.iovs, &res.head.iov[i]);
		}

		/* blank line */
		iov_push(&res.iovs, "\r\n", 2);

		/* body */
		if (res.body.iov_len)
			iov_pushv(&res.iovs, &res.body);

		err = http_response_send(sock, &req, &res);
	}
	free(res.iovs.iov);
	free(res.head.iov);
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
	return ptr + len;
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
	char *domain = NULL;
	char *port = NULL; /* FIXME: port -> unsigned short */
	char pack[len + sizeof(size_t) * 4];
	char * ptr;
	char * pp = pack;

	memset(pack, 0, sizeof(pack));

	loglevel = 79; /* FIXME - remove */

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
		port = path;
		path = strdup(path);
		port[0] = '\0';
		host = strdup(uri);
		domain = uri;
		if ((!memcmp(domain, "[", 1)) && (port = strstr(uri, "]:"))) {
			/* IPv6 address with port */
			domain++;
			port[0] = '\0';
			port += 2;
		}
		else if ((port = strchr(uri, ':'))) {
			/* host and port */
			port[0] = '\0';
			port++;
		}
	}
	DEBUG("Host: '%s'", host);
	DEBUG("Domain: '%s'", domain);
	DEBUG("Port: '%s'", port);
	DEBUG("Path: '%s'", path);

	ptr = packstr(ptr, method);
	ptr = packstr(ptr, action);
	ptr = packstr(ptr, args);
	ptr = packstr(ptr, host);
	ptr = packstr(ptr, domain);
	ptr = packstr(ptr, port);
	ptr = packstr(ptr, path);
	k.mv_data = &uris;
	k.mv_size = sizeof(size_t);
	v.mv_data = pack;
	v.mv_size = ptr - pack;
	config_set(HTTP_DB_URI, &k, &v, txn, 0, MDB_INTEGERKEY | MDB_CREATE);
	uris++;
	free(host);
	if (path != uri) free(path);

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
