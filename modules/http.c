/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only
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

#define _GNU_SOURCE

#include "http.h"
#include "websocket.h"
#include "../src/err.h"
#include "../src/iov.h"
#include "../src/log.h"
#include "../src/str.h"
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <sys/uio.h>
#include <unistd.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/sha.h>

#define IOVSIZE 5 /* number of iov structures to allocate at once */
#define BUFLEN BUFSIZ

static char buf[BUFLEN];

int setcork(int sock, int state)
{
	return setsockopt(sock, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));
}

char *http_phrase(http_status_code_t code)
{
	switch (code) {
		HTTP_CODES(HTTP_CODE_PHRASE)
	}
	return "Unknown";
}

static size_t http_status(char *status, http_status_code_t code)
{
	return sprintf(status, "HTTP/1.1 %i - %s\r\n", code, http_phrase(code));
}

/*
 * first pass processing request headers
 * 1. ignore everything we can
 * 2. process anything of immediate importance
 * 3. defer processing of everything else
 * return 0 for success, or http_status_code_t for error
 */
static int http_header_process(http_request_t *req, http_response_t *res,
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
	else if (!iovstrcmp(k, "Cache-Control")) {
		iovcpy(&req->cache, v);
	}
	else if (!iovstrcmp(k, "Connection")) {
		req->conn_upgrade = !iovstrtokmatch(v, "upgrade", ", ");
		req->conn_keepalive = !iovstrtokmatch(v, "keep-alive", ", ");
		req->close = !iovstrtokmatch(v, "close", ", ");
	}
	else if (!iovstrcmp(k, "Referrer")) {
		iovcpy(&req->referrer, v);
	}
	else if (!iovstrcmp(k, "Sec-WebSocket-Extensions")) {
		iovcpy(&req->secwebsocketextensions, v);
	}
	else if (!iovstrcmp(k, "Sec-WebSocket-Key")) {
		iovcpy(&req->secwebsocketkey, v);
	}
	else if (!iovstrcmp(k, "Sec-WebSocket-Protocol")) {
		iovcpy(&req->secwebsocketprotocol, v);
	}
	else if (!iovstrcmp(k, "Sec-WebSocket-Version")) {
		iovcpy(&req->secwebsocketversion, v);
	}
	else if (!iovstrcmp(k, "Upgrade")) {
		iovcpy(&req->upgrade, v);
	}
	else if (!iovstrcmp(k, "Upgrade-Insecure-Requests")) {
		req->upsec = !iovstrcmp(v, "1");
	}
	else if (!iovstrcmp(k, "User-Agent")) {
		iovcpy(&req->useragent, v);
	}
	return 0;
}

static int http_ready(int sock)
{
	return (recv(sock, buf, 1, MSG_PEEK | MSG_WAITALL) > 0);
}

/* top up http buffer, returning number of bytes read or -1 on error
 * lclen = value of Content-Length header, or -1 */
static ssize_t http_fill_buffer(conn_t *c, void *ptr, size_t len)
{
	ssize_t byt = 0;

	TRACE("%s()", __func__);
	if (c->ssl) {
		if ((byt = wolfSSL_read(c->ssl, ptr, len)) < 0) {
			return -1;
		}
	}
	else {
		if ((byt = recv(c->sock, ptr, len, 0)) == -1) {
			ERROR("recv() error '%s'", strerror(errno));
			return -1;
		}
	}
	DEBUG("%lu bytes read", byt);

	return byt;
}

/* return one line at a time, reading from socket as we go */
static ssize_t http_read_line(conn_t *c, char **line, http_request_t *req)
{
	static char *ptr = buf;		/* ptr to empty buffer */
	static char *nxt = buf;		/* ptr to unprocessed bytes */
	static size_t byt = 0;		/* unprocessed bytes */
	char *nl = NULL;		/* ptr to newline */
	ssize_t len = 0;		/* length of line */

	TRACE("%s()", __func__);

	if (!req->len) {
		ptr = nxt = buf;
		byt = 0;
	}

	do {
		if (byt) { /* have unprocessed bytes */

			/* check for newline */
			nl = memchr(nxt, '\n', byt);
			if (nl) {
				*line = nxt;
				len = nl - nxt;
				nxt = nl + 1;
				req->len += len;
				byt -= len;

				/* chop CRLF */
				len--;
				if ((*line)[len - 1] == '\r') len--;

				return len;
			}
		}
		/* either we have no bytes, or they don't contain a LF */

		len = BUFLEN - ((char *)ptr - buf); /* remaining buffer space */

		/* we're near the end of the buffer */
		/* FIXME - this doesn't actually work ... */
		if (byt && len < LINE_MAX) {
			/* move unprocessed bytes to beginning of buffer */
			DEBUG("shifting unprocessed bytes");
			memmove(buf, nxt, len);
			len = BUFLEN;
			nxt = ptr = buf;
		}

		/* read some bytes */
		len = http_fill_buffer(c, ptr, len);
		if (len > 0) {
			if (byt + len < BUFLEN) {
				ptr += len;
				byt += len;
			}
			else return -1;
		}
	} while (len > 0);

	return len;
}

static inline http_status_code_t
http_headers_read(conn_t *c, http_request_t *req, http_response_t *res)
{
	char *ptr;
	struct iovec header, val;
	size_t i;
	ssize_t len;
	int err;

	/* read headers until we find a blank line */
	while ((len = http_read_line(c, &ptr, req)) > 0) {
		i = wordend(&ptr, len, req->len);
		if (i == 0 || i == req->len) break;
		iovset(&header, ptr, i - 1);
		ptr += i + 1;
		iovset(&val, ptr, len - i - 1);
		if ((err = http_header_process(req, res, &header, &val)))
			return err;
	}
	if (len == -1) {
		req->close = 1;
		return HTTP_BAD_REQUEST;
	}
	return 0;
}


static http_status_code_t
http_request_read(conn_t *c, http_request_t *req, http_response_t *res)
{
	size_t i, metlen, urilen, htvlen;
	ssize_t len = 0;
	char *ptr, *met, *uri, *htv;

	TRACE("%s()", __func__);
	memset(req, 0, sizeof(http_request_t));

	/* set request time so we have consist timestamp when needed */
	req->t = time(NULL);

	/* read first request line */
	if ((len = http_read_line(c, &ptr, req)) == -1) {
		req->close = 1;
		return HTTP_BAD_REQUEST;
	}
	DEBUG("%.*s", (int)len, ptr);

	i = wordend(&ptr, HTTP_METHOD_MAX, req->len);	/* HTTP method */
	if (i == 0 || i == req->len)
		return HTTP_BAD_REQUEST;
	met = buf; metlen = i;

	if (skipspace(&ptr, i, req->len) == req->len)
		return HTTP_BAD_REQUEST;

	i = wordend(&ptr, HTTP_URI_MAX, req->len);	/* URI */
	if (i == 0 || i == req->len)
		return HTTP_BAD_REQUEST;
	uri = ptr; urilen = i;

	if (skipspace(&ptr, i, req->len) == req->len)
		return HTTP_BAD_REQUEST;

	i = wordend(&ptr, HTTP_VERSION_MAX, req->len);	/* HTTP version */
	if (i == 0 || i == req->len)
		return HTTP_BAD_REQUEST;
	if (strncmp(ptr, "HTTP/", 5)) {
		return HTTP_BAD_REQUEST;
	}
	ptr += 5; i -= 5;
	htv = ptr; htvlen = i;
	DEBUG("HTTP_VERSION: %.*s", (int)i, ptr);
	if (strncmp(ptr, "1.1", i)) {
		if (!strncmp(ptr, "1.0", i)) {
			req->close = 1;
		}
		else {
			return HTTP_VERSION_NOT_SUPPORTED;
		}
	}
	iovset(&req->method, met, metlen);
	iovset(&req->uri, uri, urilen);
	iovset(&req->httpv, htv, htvlen);

	return http_headers_read(c, req, res);
}

size_t rcv(conn_t *c, void *data, size_t len, int flags)
{
	if (c->ssl) {
		return wolfSSL_read(c->ssl, data, (int)len);
	}
	else {
		return recv(c->sock, data, len, flags);
	}
}

ssize_t snd(conn_t *c, void *data, size_t len, int flags)
{
	if (c->ssl) {
		assert(len <= INT_MAX); /* FIXME - deal with wolfssl limit */
		return wolfSSL_write(c->ssl, data, (int)len);
	}
	else {
		return send(c->sock, data, len, flags);
	}
}

ssize_t snd_blank_line(conn_t *c)
{
	return snd(c, "\r\n", 2, 0);
}

ssize_t snd_string(conn_t *c, char *str, ...)
{
	ssize_t len = 0;
	char *data = NULL;
	va_list argp;
	int ret;

	va_start(argp, str);
	ret = vasprintf(&data, str, argp);
	va_end(argp);
	if (ret == -1) return -1;
	len = snd(c, data, strlen(data), 0);
	free(data);

	return len;
}

static int http_response_send(conn_t *c, http_request_t *req, http_response_t *res)
{
	(void) req;

	setcork(c->sock, 1);
	if (c->ssl) {
		if (!wolfSSL_writev(c->ssl, res->iovs.iov, res->iovs.idx)) {
			FAIL(LSD_ERROR_TLS_WRITE);
		}
	}
	else {
		if (writev(c->sock, res->iovs.iov, res->iovs.idx) == -1)
			return -1;
	}
	setcork(c->sock, 0);
	return 0;
}

static int handler_upgrade_connection_check(http_request_t *r)
{
	char *h;
	int proto = WS_PROTOCOL_NONE;

	TRACE("%s()", __func__);

	/* RFC 6455 */
	if (iovstrcmp(&r->method, "GET")) {
		DEBUG("Invalid method '%.*s' for client upgrade", 
			(int)r->method.iov_len, (char *)r->method.iov_base);
		return HANDLER_UPGRADE_INVALID_METHOD;
	}
	if (iovstrcmp(&r->httpv, "1.1")) {
		DEBUG("Upgrade unsupported in HTTP version '%.*s'", FMTV(r->httpv));
		return HANDLER_UPGRADE_INVALID_HTTP_VERSION;
	}
	if (!(r->host.iov_len)) {
		DEBUG("Host header required for client upgrade");
		return HANDLER_UPGRADE_NO_HOST_HEADER;
	}
	if (iovstrcmp(&r->upgrade, "websocket")) {
		DEBUG("Unknown upgrade type '%.*s' requested", FMTV(r->upgrade));
		return HANDLER_UPGRADE_INVALID_UPGRADE;
	}
	if (!r->conn_upgrade) {
		DEBUG("'Connection: upgrade' required");
		return HANDLER_UPGRADE_INVALID_CONN;
	}
	if (!(r->secwebsocketkey.iov_len)) {
		DEBUG("Sec-WebSocket-Key required");
		return HANDLER_UPGRADE_MISSING_KEY;
	}
	if (iovstrcmp(&r->secwebsocketversion, "13")) {
		DEBUG("Sec-WebSocket-Version != 13");
		return HANDLER_UPGRADE_INVALID_WEBSOCKET_VERSION;
	}
	if ((r->secwebsocketprotocol.iov_len)) {
		DEBUG("Sec-WebSocket-Protocol: '%.*s' requested", FMTV(r->secwebsocketprotocol));
		h = strndup(r->secwebsocketprotocol.iov_base, r->secwebsocketprotocol.iov_len);
		proto = ws_select_protocol(h);
		free(h);
		if (proto == WS_PROTOCOL_INVALID) {
			DEBUG("Unsupported websocket protocol requested");
			return HANDLER_INVALID_WEBSOCKET_PROTOCOL;
		}
	}
	DEBUG("protocol selected: %s", ws_protocol_name(proto));
	ws_proto = proto;
	if (!(r->secwebsocketextensions.iov_len)) {
		DEBUG("Sec-WebSocket-Extensions: '%.*s' requested",
			FMTV(r->secwebsocketextensions));
	}

	TRACE("%s() done", __func__);

	return 0;
}

static http_status_code_t response_upgrade(conn_t *c, http_request_t *req)
{
	word32 outLen = (SHA_DIGEST_SIZE + 3 - 1) / 3 * 4;
	byte b64[(SHA_DIGEST_SIZE + 3 - 1) / 3 * 4 + 1];
	unsigned char md[SHA_DIGEST_SIZE] = "";
	Sha sha;
	char *header = NULL;
	char *stok = NULL;

	TRACE("%s()", __func__);

	if (asprintf(&stok, "%.*s258EAFA5-E914-47DA-95CA-C5AB0DC85B11",
				FMTV(req->secwebsocketkey)) == -1) return -1;

	/* SHA1 hash, then base64 encode */
	wc_InitSha(&sha);
	wc_ShaUpdate(&sha, (byte *)stok, strlen(stok));
	wc_ShaFinal(&sha, md);
	free(stok);
	memset(b64, 0, outLen + 1);
	Base64_Encode_NoNl(md, SHA_DIGEST_SIZE, b64, &outLen);
	if (asprintf(&header, "Sec-WebSocket-Accept: %s\r\n", b64) == -1)
		return -1;

	setcork(c->sock, 1);
	snd_string(c, "HTTP/1.1 %i %s\r\n", HTTP_SWITCHING_PROTOCOLS, http_phrase(HTTP_SWITCHING_PROTOCOLS));
	snd_string(c, "Upgrade: websocket\r\n");
	snd_string(c, "Connection: Upgrade\r\n");
	if (ws_proto > 0)
		snd_string(c, "Sec-WebSocket-Protocol: %s\r\n", ws_protocol_name(ws_proto));
	snd_string(c, header);
	free(header);
	snd_blank_line(c);
	setcork(c->sock, 0);

	TRACE("%s() done", __func__);

	return HTTP_SWITCHING_PROTOCOLS;
}

static char * unpackiov(char *ptr, struct iovec *iov)
{
	size_t len = *(size_t *)ptr;
	iov->iov_len = len;
	ptr += sizeof(size_t);
	iov->iov_base = (len) ? ptr : NULL;
	return ptr + len;
}

static int http_match_uri(http_request_t *req, struct iovec uri[HTTP_PARTS])
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

/* output NCSA Common log format */
static void http_request_log(conn_t *c, http_request_t *req, http_response_t *res)
{
	char ts[27];
	struct iovec dash = { "-", 1 };
	char httpv[9] = "-";

	if (!req->method.iov_len) iovcpy(&req->method, &dash);
	if (!req->uri.iov_len) iovcpy(&req->uri, &dash);
	if (req->httpv.iov_len)
		snprintf(httpv, 9, "HTTP/%.*s", (int)req->httpv.iov_len, (char *)req->httpv.iov_base);
	if (!req->referrer.iov_len) iovcpy(&req->referrer, &dash);
	if (!req->useragent.iov_len) iovcpy(&req->useragent, &dash);

	strftime(ts, 27, "%d/%b/%Y:%T %z", localtime(&req->t));
	INFO("%s - - [%s] \"%.*s %.*s %s\" %i %zu \"%.*s\" \"%.*s\"",
		c->addr,
		ts,
		FMTV(req->method),
		FMTV(req->uri),
		httpv,
		res->code,
		res->len,
		FMTV(req->referrer),
		FMTV(req->useragent)
	);
	/* TODO: referrer */
}

static http_status_code_t
http_request_handle(conn_t *c, http_request_t *req, http_response_t *res)
{
	MDB_val val = { 0, NULL };

	TRACE("%s()", __func__);

	/* protocol, method, action, args, host, port, path */
	char *ptr;
	char found = 0;
	char db_uri[16];
	struct iovec uri[HTTP_PARTS];
	size_t len = strlen(c->proto->module);
	strncpy(db_uri, c->proto->module, len);
	strcpy(db_uri + len, "_uri");

	for (int i = 0; config_yield(db_uri, NULL, &val) == CONFIG_NEXT; i++) {
		ptr = (char *)val.mv_data;
		ptr++;
		for (int j = 0; j < HTTP_PARTS; j++) {
			ptr = unpackiov(ptr, &uri[j]);
		}
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

static int http_response_code(struct iovec *uri, size_t len)
{
	int code;
	char * ptr;

	len++;
	/* find closing bracket */
	if (!(ptr = memchr(uri->iov_base, ')', uri->iov_len)))
		return HTTP_INTERNAL_SERVER_ERROR;
	/* response code must be 3 bytes */
	if (ptr - (char *)uri->iov_base - len != 3)
		return HTTP_INTERNAL_SERVER_ERROR;
	/* extract the code */
	code = (int)strtol((char *)uri->iov_base + len, NULL, 10);
	return code;
}

static char *http_mimetype(char *ext)
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

static char *fileext(char *filename)
{
	for (int i = strlen(filename) - 1; i >= 0; i--) {
		if (filename[i] == '.') {
			return filename + i + 1;
		}
	}
	return NULL;
}

static int http_sendfile(conn_t *c, char *filename, http_request_t *req, http_response_t *res)
{
	struct stat sb;
	char status[128];
	char *clen = NULL;
	char *ctyp = NULL;
	char *mime = NULL;
	char *map = NULL;
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
	setcork(c->sock, 1);
	iov_push(&res->iovs, status, http_status(status, HTTP_OK));
	mime = http_mimetype(fileext(filename));
	if (mime)
		iov_pushf(&res->iovs, ctyp, "Content-Type: %s\r\n", mime);
	else
		iov_pushs(&res->iovs, "Content-Type: text/plain\r\n");
	iov_pushf(&res->iovs, clen, "Content-Length: %zu\r\n", sb.st_size);
	iov_pushs(&res->iovs, "\r\n");

	if (c->ssl) {
		DEBUG("TLS ENABLED");

		map = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, f, 0);
		iov_push(&res->iovs, map, sb.st_size);

		DEBUG("iovs_size = %zu", iovs_size(&res->iovs));

		/* FIXME: wolfssl casts size_t to int, imposing a 2GB filesize limit */
		assert(iovs_size(&res->iovs) <= INT_MAX);

		if (!(ret = wolfSSL_writev(c->ssl, res->iovs.iov, res->iovs.idx))) {
			ERRMSG(LSD_ERROR_TLS_WRITE);
			req->close = 1;
		}
		setcork(c->sock, 0);
	}
	else {
		if ((ret = writev(c->sock, res->iovs.iov, res->iovs.idx)) == -1) {
			ERROR("error writing headers");
			req->close = 1;
			goto http_sendfile_free;
		}
		res->len += (size_t)ret;
		ret = 0;
		while ((ret = sendfile(c->sock, f, &ret, sb.st_size)) < sb.st_size) {
			if (ret == -1) {
				ERROR("error sending file '%s': %s", filename, strerror(errno));
				req->close = 1;
				break;
			}
		}
		setcork(c->sock, 0);
	}
	if (ret > 0) {
		res->len += (size_t)ret;
		res->code = HTTP_OK;
		ret = 0;
	}
http_sendfile_free:
	if (map) munmap(map, sb.st_size);
	close(f);
	free(clen);
	free(ctyp);
	free(mime);

	return ret;
}

static http_status_code_t
http_response_static(conn_t *c, http_request_t *req, http_response_t *res)
{
	char *filename = NULL;
	struct iovec trail;
	size_t len;
	size_t i;
	int err = 0;

	/* config missing args */
	if (!res->uri[HTTP_ARGS].iov_len) return HTTP_INTERNAL_SERVER_ERROR;

	DEBUG("requested: '%.*s'", FMTV(req->uri));
	DEBUG("compareto: '%.*s'", FMTV(res->uri[HTTP_PATH]));
	if (!iovcmp(&req->uri, &res->uri[HTTP_PATH])) {
		/* exact match */
		DEBUG("exact match: '%.*s'", FMTV(req->uri));
		if (iovidx(res->uri[HTTP_ARGS], -1) == '/') /* directory */
			return HTTP_INTERNAL_SERVER_ERROR;
		filename = iovdup(&res->uri[HTTP_ARGS]);
	}
	else if (!iovmatch(&res->uri[HTTP_PATH], &req->uri, 0)) {
		/* wildcard match */
		DEBUG("wildcard match: '%.*s'", FMTV(req->uri));
		if (iovidx(res->uri[HTTP_ARGS], -1) != '/') {
			/* wildcard, but path points to file. Just serve the file */
			filename = iovdup(&res->uri[HTTP_ARGS]);
			goto sendnow;
		}
		/* wildcard match & path is a directory, append trailing chars */
		i = iov_matchlen(&req->uri, &res->uri[HTTP_PATH]);
		trail.iov_base = (char *)req->uri.iov_base + i;
		trail.iov_len = req->uri.iov_len - i;
		len = snprintf(NULL, 0, "%.*s%.*s", FMTV(res->uri[HTTP_ARGS]), FMTV(trail));
		filename = malloc(len + 1);
		snprintf(filename, len + 1, "%.*s%.*s", FMTV(res->uri[HTTP_ARGS]), FMTV(trail));
	}
	else return HTTP_NOT_FOUND;
	if (filename) {
sendnow:
		DEBUG("sending file '%s'", filename);
		err = http_sendfile(c, filename, req, res);
		free(filename);
	}

	return err;
}

/* returning nonzero means the response has already been sent by the handler */
static http_status_code_t
http_response(conn_t *c, http_request_t *req, http_response_t *res)
{
	http_status_code_t code = 0;
	char *ptr;
	size_t len;
	if (!iovstrncmp(&res->uri[HTTP_ACTION], "response", 8)) {
		DEBUG("RESPONSE: response");
		code = http_response_code(&res->uri[HTTP_ACTION], 8);
		res->body = res->uri[HTTP_ARGS];
	}
	else if (!iovstrncmp(&res->uri[HTTP_ACTION], "redirect", 8)) {
		code = http_response_code(&res->uri[HTTP_ACTION], 8);
		DEBUG("RESPONSE: redirect (%i)", code);
		if ((code < HTTP_MOVED_PERMANENTLY) || (code > HTTP_SEE_OTHER))
			return HTTP_INTERNAL_SERVER_ERROR;
		iov_pushs(&res->head, "Location: ");
		if (iovidx(res->uri[HTTP_PATH], -1) == '*') {
			/* wildcard: append request path to redirect url */
			iov_push(&res->head, res->uri[HTTP_ARGS].iov_base,
				             res->uri[HTTP_ARGS].iov_len);
			ptr = iovchr(req->uri, '/');
			if (!ptr) return HTTP_BAD_REQUEST;
			ptr++;
			len = req->uri.iov_len + ptr - (char *)req->uri.iov_base - 2;
			iov_push(&res->head, ptr, len);
		}
		else {
			iov_pushv(&res->head, &res->uri[HTTP_ARGS]);
		}
		iov_push(&res->head, CRLF, 2);
	}
	else if (!iovstrcmp(&res->uri[HTTP_ACTION], "static")) {
		DEBUG("RESPONSE: static");
		code = http_response_static(c, req, res);
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
int conn(conn_t *c)
{
	http_response_t res = {0};
	http_request_t req = {0};
	char status[128];
	char clen[128];
	char db[2];
	char *cert = NULL;
	char *key = NULL;
	int err = 0;
	WOLFSSL_CTX *ctx = NULL;

	res.iovs.nmemb = IOVSIZE;
	res.head.nmemb = IOVSIZE;
	env = NULL; config_init_db(dbdir);

	/* handle TLS connection */
	if (!strcmp(c->proto->module, "https")) {
		/* Initialize wolfSSL */
		wolfSSL_Init();
		if ((ctx = wolfSSL_CTX_new(wolfSSLv23_server_method())) == NULL) {
			ERROR("failed to create WOLFSSL_CTX");
			goto conn_cleanup;
		}
		/* load certificate */
		config_db(DB_GLOBAL, db);
		config_get_s(db, "cert", &cert, NULL, 0);
		config_get_s(db, "key", &key, NULL, 0);
		if (wolfSSL_CTX_use_certificate_chain_file(ctx, cert) != SSL_SUCCESS) {
			ERROR("failed to load cert: %s", cert);
			goto conn_cleanup;
		}
		/* load private key */
		if (wolfSSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
			ERROR("failed to load key: %s", key);
			goto conn_cleanup;
		}
		/* create new session */
		if ((c->ssl = wolfSSL_new(ctx)) == NULL) {
			ERROR("failed to create WOLFSSL object");
			goto conn_cleanup;
		}
		wolfSSL_set_fd(c->ssl, c->sock);
	}

	loglevel = 127;

	while (!req.close && http_ready(c->sock)) {
		DEBUG("ws_proto = %i", ws_proto);
		if (ws_proto != WS_PROTOCOL_INVALID) {
			DEBUG("Request on established websocket");
			if (ws_handle_request(c)) req.close = 1;
			continue;
		}
		memset(&req, 0, sizeof(http_request_t));
		memset(&res, 0, sizeof(http_response_t));
		err = http_request_read(c, &req, &res);
		if (!err && req.upgrade.iov_len && !handler_upgrade_connection_check(&req)) {
			err = response_upgrade(c, &req);
			continue;
		}
		if (!err) err = http_request_handle(c, &req, &res);
		if (!err) err = http_response(c, &req, &res);
		if (err) {
			res.code = err;
			iov_push(&res.iovs, status, http_status(status, err));
			iov_push(&res.iovs, clen,
			    sprintf(clen, "Content-Length: %zu\r\n",
			            res.body.iov_len)
			);
			for (size_t i = 0; i < res.head.idx; i++) {
				iov_pushv(&res.iovs, &res.head.iov[i]);
			}
			iov_push(&res.iovs, CRLF, 2);
			if (res.body.iov_len) iov_pushv(&res.iovs, &res.body);
			err = http_response_send(c, &req, &res);
		}
		if (err > 0) res.code = err;
		http_request_log(c, &req, &res);
		iovs_clear(&res.iovs);
		iovs_clear(&res.head);
		DEBUG("request finished");
		DEBUG("req.close=%i", req.close);
	}
conn_cleanup:
	free(key);
	free(cert);
	iovs_free(&res.iovs);
	iovs_free(&res.head);
	mdb_env_close(env); env = NULL;

	if (!strcmp(c->proto->module, "https")) {
		if (c->ssl) wolfSSL_free(c->ssl);
		if (ctx) wolfSSL_CTX_free(ctx);
		wolfSSL_Cleanup();
	}

	return err;
}

/* pack (length) size_t and string into ptr, return new ptr */
static char * packstr(char *ptr, char *str)
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
	int c;
	char proto = 0; /* default: http */
	char uri[LINE_MAX + 1];
	char method[LINE_MAX + 1];
	char action[LINE_MAX + 1];
	char args[LINE_MAX + 1];
	char *path;
	char *host = NULL;
	char *domain = NULL;
	char *port = NULL; /* FIXME: port -> unsigned short */
	char pack[LINE_MAX + sizeof(size_t) * 4 + 1];
	char * ptr;
	char * pp = pack;
	char db_uri[16];

	memset(pack, 0, sizeof(pack));

	/* protocol must be http:// or https:// */
	if (memcmp(line, "http", 4)) return LSD_ERROR_CONFIG_INVALID;
	memcpy(db_uri, line, 5);
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
	strcpy(db_uri + 4 + proto, "_uri"); /* http(s)_uri */

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
	config_set(db_uri, &k, &v, txn, 0, MDB_INTEGERKEY | MDB_CREATE);
	uris++;
	free(host);
	if (path != uri) free(path);

	return 0;
}
void finit(void)
{
}

/* load/reload config */
int conf(void)
{
	return 0;
}

/* initialize */
int init(char *dbname)
{
	dbdir = dbname;
	return 0;
}
