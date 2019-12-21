/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * http.h
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

typedef enum {
	HTTP_SWITCHING_PROTOCOLS        = 101,
	HTTP_OK                         = 200,
	HTTP_CREATED                    = 201,
	HTTP_BAD_REQUEST                = 400,
	HTTP_UNAUTHORIZED               = 401,
	HTTP_FORBIDDEN                  = 403,
	HTTP_NOT_FOUND                  = 404,
	HTTP_METHOD_NOT_ALLOWED         = 405,
	HTTP_LENGTH_REQUIRED            = 411,
	HTTP_UNSUPPORTED_MEDIA_TYPE     = 415,
	HTTP_TEAPOT                     = 418,
	HTTP_INTERNAL_SERVER_ERROR      = 500,
	HTTP_NOT_IMPLEMENTED            = 501,
	HTTP_VERSION_NOT_SUPPORTED      = 505
} http_status_code_t;

typedef struct http_request_s http_request_t;
struct http_request_s {
	char *httpv;                    /* HTTP version */
	char *method;                   /* HTTP request method (GET, POST etc.) */
	char *res;                      /* resource (url) requested */
	size_t len;                     /* bytes recv()'d */
	char close;                     /* Connection: close */
};

typedef struct http_response_s http_response_t;
struct http_response_s {
	http_status_code_t code;        /* HTTP response code */
	size_t len;                     /* length of response body */
	char close;                     /* Connection: close */
};

/* handle new connection */
int conn(int sock, proto_t *p);

/* (re)load config */
int conf(proto_t *p);

/* initialize */
int init(proto_t *p);
