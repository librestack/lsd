/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * http.h
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

#define WC_NO_HARDEN /* FIXME: stop wolfssl warning */
#define CERT_FILE "server-cert.pem" /* FIXME */
#define KEY_FILE  "server-key.pem"  /* FIXME */

#include "config.h"
#include "iov.h"
#include <wolfssl/ssl.h>

#define HTTP_DB_URI "http_uri"
#define HTTP_METHOD_MAX 8	/* maximum length of HTTP method */
#define HTTP_URI_MAX 4096	/* maximum length of HTTP uri */
#define HTTP_VERSION_MAX 9	/* maximum length of HTTP uri */

typedef enum {
	HTTP_SWITCHING_PROTOCOLS        = 101,
	HTTP_OK                         = 200,
	HTTP_CREATED                    = 201,
	HTTP_MOVED_PERMANENTLY		= 301,
	HTTP_FOUND			= 302,
	HTTP_SEE_OTHER			= 303,
	HTTP_BAD_REQUEST                = 400,
	HTTP_UNAUTHORIZED               = 401,
	HTTP_FORBIDDEN                  = 403,
	HTTP_NOT_FOUND                  = 404,
	HTTP_METHOD_NOT_ALLOWED         = 405,
	HTTP_LENGTH_REQUIRED            = 411,
	HTTP_UNSUPPORTED_MEDIA_TYPE     = 415,
	HTTP_TEAPOT                     = 418,
	HTTP_UNAVAILABLE_LEGAL		= 451,
	HTTP_INTERNAL_SERVER_ERROR      = 500,
	HTTP_NOT_IMPLEMENTED            = 501,
	HTTP_VERSION_NOT_SUPPORTED      = 505,
} http_status_code_t;

typedef enum {
	HTTP_ENCODING_NONE		= 0,
	HTTP_ENCODING_GZIP		= 1,
	HTTP_ENCODING_DEFLATE		= 2,
} http_encoding_t;

enum {
	HTTP_METHOD,
	HTTP_ACTION,
	HTTP_ARGS,
	HTTP_HOST,
	HTTP_DOMAIN,
	HTTP_PORT,
	HTTP_PATH,
	HTTP_PARTS,	/* count items in enum */
};

typedef struct http_request_s http_request_t;
struct http_request_s {
	proto_t *proto;			/* protocol details */
	struct iovec httpv;             /* HTTP version */
	struct iovec method;            /* HTTP request method (GET, POST etc.) */
	struct iovec uri;               /* resource (url) requested */
	struct iovec host;              /* Host */
	struct iovec accept;		/* Accept */
	struct iovec encoding;		/* Accept-Encoding */
	struct iovec lang;		/* Accept-Language */
	struct iovec cache;		/* Cache-Control */
	size_t len;                     /* bytes recv()'d */
	char upsec;			/* Upgrade-Insecure-Requests */
	char close;                     /* Connection: close */
};

typedef struct http_response_s http_response_t;
struct http_response_s {
	WOLFSSL *ssl;			/* WOLFSSL object */
	iovstack_t iovs;		/* iovec response array */
	iovstack_t head;		/* iovec header array */
	struct iovec uri[HTTP_PARTS];	/* matched config uri */
	struct iovec body;		/* Response body */
	http_encoding_t encoding;	/* gzip, deflate etc. */
};

/* handle new connection */
int conn(int sock, proto_t *p);

/* process uri config line */
int load_uri(char *uri, MDB_txn *txn);

/* (re)load config */
int conf();

/* finalize */
void finit();

/* initialize */
int init();
