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
#ifndef __LSD_HTTP_H
#define __LSD_HTTP_H 1

#include "config.h"
#include "iov.h"
#include <stdarg.h>
#include <time.h>

#define HTTP_DB_URI "http_uri"
#define HTTP_METHOD_MAX 8	/* maximum length of HTTP method */
#define HTTP_URI_MAX 4096	/* maximum length of HTTP uri */
#define HTTP_VERSION_MAX 9	/* maximum length of HTTP uri */
#define CRLF "\r\n"

#define HTTP_CODES(X) \
	X(100,	HTTP_CONTINUE,			"Continue") \
	X(101,	HTTP_SWITCHING_PROTOCOLS,	"Switching Protocols") \
	X(200,	HTTP_OK,			"OK") \
	X(201,	HTTP_CREATED,			"Created") \
	X(202,	HTTP_ACCEPTED,			"Accepted") \
	X(203,	HTTP_NON_AUTHORITATIVE,		"Non-Authoritative Information") \
	X(204,	HTTP_NO_CONTENT,		"No Content") \
	X(205,	HTTP_RESET_CONTENT,		"Reset Content") \
	X(206,	HTTP_PARTIAL_CONTENT,		"Partial Content") \
	X(300,	HTTP_MULTIPLE_CHOICES,		"Multiple Choices") \
	X(301,	HTTP_MOVED_PERMANENTLY,		"Moved Permanently") \
	X(302,	HTTP_FOUND,			"Found") \
	X(303,	HTTP_SEE_OTHER,			"See Other") \
	X(400,	HTTP_BAD_REQUEST,		"Bad Request") \
	X(401,	HTTP_UNAUTHORIZED,		"Unauthorized") \
	X(402,	HTTP_PAYMENT_REQUIRED,		"Payment Required") \
	X(403,	HTTP_FORBIDDEN,			"Forbidden") \
	X(404,	HTTP_NOT_FOUND,			"Not Found") \
	X(405,	HTTP_METHOD_NOT_ALLOWED,	"Method Not Allowed") \
	X(406,	HTTP_NOT_ACCEPTABLE,		"Not Acceptable") \
	X(407,	HTTP_PROXY_AUTH_REQUIRED,	"Proxy Authentication Required") \
	X(408,	HTTP_REQUEST_TIMEOUT,		"Request Time-out") \
	X(409,	HTTP_CONFLICT,			"Conflict") \
	X(410,	HTTP_GONE,			"Gone") \
	X(411,	HTTP_LENGTH_REQUIRED,		"Length Required") \
	X(412,	HTTP_PRECONDITION_FAIL,		"Precondition Failed") \
	X(413,	HTTP_ENTITY_TOO_LARGE,		"Request Entity Too Large") \
	X(414,	HTTP_URI_TOO_LARGE,		"Request-URI Too Large") \
	X(415,	HTTP_UNSUPPORTED_MEDIA_TYPE,	"Unsupported Media Type") \
	X(416,	HTTP_RANGE_FAIL,		"Requested range not satisfiable") \
	X(417,	HTTP_EXPECTATION_FAILED,	"Expectation Failed") \
	X(418,	HTTP_TEAPOT,			"I am a teapot") \
	X(419,	HTTP_UNAVAILABLE_LEGAL,		"Unavailable for Legal Reasons") \
	X(500,	HTTP_INTERNAL_SERVER_ERROR,	"Internal Server Error") \
	X(501,	HTTP_NOT_IMPLEMENTED,		"Not Implemented") \
	X(502,	HTTP_BAD_GATEWAY,		"Bad Gateway") \
	X(503,	HTTP_SERVICE_UNAVILABLE,	"Service Unavailable") \
	X(504,	HTTP_GATEWAY_TIMEOUT,		"Gateway Time-out") \
	X(505,	HTTP_VERSION_NOT_SUPPORTED,	"HTTP Version not supported")
#undef X

#define HTTP_CODE_PHRASE(id, name, desc) case name: return desc;
#define HTTP_CODE_ENUM(id, name, desc) name = id,
typedef enum {
	HTTP_CODES(HTTP_CODE_ENUM)
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
	struct iovec httpv;             /* HTTP version */
	struct iovec method;            /* HTTP request method (GET, POST etc.) */
	struct iovec uri;               /* resource (url) requested */
	struct iovec host;              /* Host */
	struct iovec accept;		/* Accept */
	struct iovec encoding;		/* Accept-Encoding */
	struct iovec lang;		/* Accept-Language */
	struct iovec cache;		/* Cache-Control */
	struct iovec connection;	/* Connection */
	struct iovec referrer;		/* Referrer */
	struct iovec secwebsocketextensions;	/* Sec-WebSocket-Extensions */
	struct iovec secwebsocketkey;		/* Sec-WebSocket-Key */
	struct iovec secwebsocketprotocol;	/* Sec-WebSocket-Protocol */
	struct iovec secwebsocketversion;	/* Sec-WebSocket-Version */
	struct iovec upgrade;		/* Upgrade */
	struct iovec useragent;		/* User-Agent */
	size_t len;                     /* bytes recv()'d */
	time_t t;			/* timestamp so we have one consistent one to use */
	char upsec;			/* Upgrade-Insecure-Requests */
	char close;                     /* Connection: close */
	char conn_keepalive;		/* Connection: keep-alive */
	char conn_upgrade;		/* Connection: upgrade */
};

typedef struct http_response_s http_response_t;
struct http_response_s {
	iovstack_t iovs;		/* iovec response array */
	iovstack_t head;		/* iovec header array */
	struct iovec uri[HTTP_PARTS];	/* matched config uri */
	struct iovec body;		/* Response body */
	size_t len;                     /* bytes sent */
	http_encoding_t encoding;	/* gzip, deflate etc. */
	http_status_code_t code;	/* HTTP status code */
};

char *http_phrase(http_status_code_t code);

/* set TCP cork */
int setcork(int sock, int state);

/* receive data */
size_t rcv(conn_t *c, void *data, size_t len, int flags);

/* send data */
ssize_t snd(conn_t *c, void *data, size_t len, int flags);

/* send CRLF */
ssize_t snd_blank_line(conn_t *c);

/* send formatted string */
ssize_t snd_string(conn_t *c, char *str, ...);

/* handle new connection */
int conn(conn_t *c);

/* process uri config line */
int load_uri(char *uri, MDB_txn *txn);

/* (re)load config */
int conf();

/* finalize */
void finit();

/* initialize */
int init();

#endif /* __LSD_HTTP_H */
