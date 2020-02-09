/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * http.c
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

#include "err.h"
#include "http.h"
#include "iov.h"
#include "log.h"
#include "str.h"
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
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
	ssize_t len;
	char *ptr;

	if (res->ssl) {
		if ((len = wolfSSL_read(res->ssl, buf, BUFSIZ-1)) < 0) {
			req->close = 1;
			return HTTP_BAD_REQUEST;
		}
		req->len = (size_t)len;
	}
	else {
		req->len = recv(sock, buf, BUFSIZ, 0);
	}
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

	setcork(sock, 1);
	if (res->ssl) {
		if (!wolfSSL_writev(res->ssl, res->iovs.iov, res->iovs.idx)) {
			FAIL(LSD_ERROR_TLS_WRITE);
		}
	}
	else {
		writev(sock, res->iovs.iov, res->iovs.idx); /* TODO: check errors */
	}
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

char *http_mimetype(char *ext)
{
	MDB_txn *txn;
	MDB_dbi dbi;
	MDB_val k,v;
	char *mime = NULL;
	int err = 0;

	if (!ext) return NULL;
	DEBUG("searching for mime type of '%s'", ext);
	if ((err = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn)) != 0) {
		ERROR("%s(): %s", __func__, mdb_strerror(err));
		return NULL;
	}
	if ((err = mdb_dbi_open(txn, "mime", 0, &dbi)) != 0) {
		ERROR("%s(): %s", __func__, mdb_strerror(err));
	}
	if (!err) {
		k.mv_size = strlen(ext);
		k.mv_data = ext;
		if ((err = mdb_get(txn, dbi, &k, &v))) {
			if (err != MDB_NOTFOUND)
				ERROR("%s(): %s", __func__, mdb_strerror(err));
		}
		else {
			mime = strndup(v.mv_data, v.mv_size);
		}
	}
	mdb_txn_abort(txn);
	return mime;
}

char *fileext(char *filename)
{
	for (int i = strlen(filename) - 1; i >= 0; i--) {
		if (filename[i] == '.') {
			return filename + i + 1;
		}
	}
	return NULL;
}

int http_sendfile(int sock, char *filename)
{
	struct stat sb;
	char status[128];
	char *mime;
	ssize_t ret = 0;
	int f;

	if ((f = open(filename, O_RDONLY)) == -1) {
		ERROR("unable to open '%s': %s\n", filename, strerror(errno));
		return HTTP_NOT_FOUND;
	}
	fstat(f, &sb);
	if (! S_ISREG(sb.st_mode)) {
		ERROR("'%s' is not a regular file", filename);
		return HTTP_NOT_FOUND;
	}
	DEBUG("Sending %zu bytes", sb.st_size);
	setcork(sock, 1);
	http_status(status, HTTP_OK);
	dprintf(sock, "%s", status);
	mime = http_mimetype(fileext(filename));
	if (mime) {
		dprintf(sock, "Content-Type: %s\r\n", mime);
		free(mime);
	}
	else
		dprintf(sock, "Content-Type: text/plain\r\n");
	dprintf(sock, "Content-Length: %zu\r\n", sb.st_size);
	write(sock, "\r\n", 2);
	while ((ret = sendfile(sock, f, &ret, sb.st_size)) < sb.st_size) {
		if (ret == -1) {
			ERROR("error sending file '%s': %s", filename, strerror(errno));
			break;
		}
	}
	if (ret != -1) setcork(sock, 0);

	return ret;
}

http_status_code_t
http_response_static(int sock, http_request_t *req, http_response_t *res)
{
	char *filename = NULL;
	char *ptr;
	size_t len;
	int err = 0;

	/* config missing args */
	if (!res->uri[HTTP_ARGS].iov_len) return HTTP_INTERNAL_SERVER_ERROR;

	DEBUG("requested: '%.*s'", req->uri.iov_len, req->uri.iov_base);
	DEBUG("compareto: '%.*s'", res->uri[HTTP_PATH].iov_len, res->uri[HTTP_PATH].iov_base);
	if (!iovcmp(&req->uri, &res->uri[HTTP_PATH])) {
		/* exact match */
		DEBUG("exact match: '%.*s'", req->uri.iov_len, req->uri.iov_base);
		if (iovidx(res->uri[HTTP_ARGS], -1) == '/') /* directory */
			return HTTP_INTERNAL_SERVER_ERROR;
		filename = iovdup(&res->uri[HTTP_ARGS]);
	}
	else if (!iovmatch(&res->uri[HTTP_PATH], &req->uri, 0)) {
		/* wildcard match */
		DEBUG("wildcard match: '%.*s'", req->uri.iov_len, req->uri.iov_base);
		if (iovidx(res->uri[HTTP_ARGS], -1) != '/') {
			/* wildcard, but path points to file. Just serve the file */
			filename = iovdup(&res->uri[HTTP_ARGS]);
			goto sendnow;
		}
		/* concatenate path and filename */
		ptr = iovrchr(req->uri, '/', &len);
		len = req->uri.iov_len - len - 1;
		if (!ptr) return HTTP_NOT_FOUND;
		++ptr;
		len = snprintf(NULL, 0, "%.*s%.*s",
			(int)res->uri[HTTP_ARGS].iov_len, (char *)res->uri[HTTP_ARGS].iov_base,
			(int)len, ptr);
		filename = malloc(len + 1);
		snprintf(filename, len + 1, "%.*s%.*s",
			(int)res->uri[HTTP_ARGS].iov_len, (char *)res->uri[HTTP_ARGS].iov_base,
			(int)len, ptr);
	}
	else return HTTP_NOT_FOUND;
	if (filename) {
sendnow:
		DEBUG("sending file '%s'", filename);
		err = http_sendfile(sock, filename);
		free(filename);
	}

	return err;
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

int http_ready(int sock)
{
	return (recv(sock, buf, 1, MSG_PEEK | MSG_WAITALL) > 0);
}

/* Handle new connection */
int conn(int sock, proto_t *p)
{
	http_response_t res = {};
	http_request_t req = {};
	char status[128];
	char clen[128];
	int err = 0;
	WOLFSSL_CTX *ctx = NULL;

	req.proto = p;
	res.iovs.nmemb = IOVSIZE;
	res.head.nmemb = IOVSIZE;

	/* we need to do this here, so the env is created in this process
	 * at init() time, the module is being called by the controller, and we
	 * can't share the env from a different process */
	env = NULL; config_init_db();

	/* handle TLS connection */
	if (!strcmp(p->module, "https")) {
		/* Initialize wolfSSL */
		wolfSSL_Init();
		if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method())) == NULL) {
			ERROR("failed to create WOLFSSL_CTX");
			goto conn_cleanup;
		}
		/* load certificate */
		if (wolfSSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
			ERROR("failed to load %s", CERT_FILE);
			goto conn_cleanup;
		}
		/* load private key */
		if (wolfSSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
			ERROR("failed to load %s", KEY_FILE);
			goto conn_cleanup;
		}
		/* create new session */
		if ((res.ssl = wolfSSL_new(ctx)) == NULL) {
			ERROR("failed to create WOLFSSL object");
			goto conn_cleanup;
		}
		wolfSSL_set_fd(res.ssl, sock);
	}

	while (!req.close && http_ready(sock)) {
		err = http_request_read(sock, &req, &res);
		if (!err) err = http_request_handle(&req, &res);
		if (!err) err = http_response(sock, &req, &res);
		if (err) {
			iov_push(&res.iovs, status, http_status(status, err));
			iov_push(&res.iovs, clen,
			    sprintf(clen, "Content-Length: %zu\r\n",
			            res.body.iov_len)
			);
			for (size_t i = 0; i < res.head.idx; i++) {
				iov_pushv(&res.iovs, &res.head.iov[i]);
			}
			iov_push(&res.iovs, "\r\n", 2);
			if (res.body.iov_len) iov_pushv(&res.iovs, &res.body);
			err = http_response_send(sock, &req, &res);
		}
		iovs_clear(&res.iovs);
		iovs_clear(&res.head);
		DEBUG("request finished");
		DEBUG("req.close=%i", req.close);
	}
conn_cleanup:
	iovs_free(&res.iovs);
	iovs_free(&res.head);
	mdb_env_close(env); env = NULL;

	if (!strcmp(p->module, "https")) {
		if (res.ssl) wolfSSL_free(res.ssl);
		if (ctx) wolfSSL_CTX_free(ctx);
		wolfSSL_Cleanup();
	}

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
