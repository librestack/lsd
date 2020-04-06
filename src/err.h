/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * err.c
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

#ifndef __LSD_ERR_H__
#define __LSD_ERR_H__ 1

#include <errno.h>

#define LSD_ERROR_CODES(X) \
	X(LSD_ERROR_SUCCESS,		"Success") \
	X(LSD_ERROR_FAILURE,		"Failure") \
	X(LSD_ERROR_INVALID_OPTS,	"Invalid option") \
	X(LSD_ERROR_CONFIG_READ,	"Unable to read config file") \
	X(LSD_ERROR_CONFIG_WRITE,	"Unable to write config data") \
	X(LSD_ERROR_CONFIG_INVALID,	"Error in config") \
	X(LSD_ERROR_INVALID_PROTOCOL,	"Invalid protocol") \
	X(LSD_ERROR_CONFIG_COMMIT,	"Config updated") \
	X(LSD_ERROR_CONFIG_ABORT,	"Config not changed") \
	X(LSD_ERROR_GETADDRINFO,	"Unable to translate address") \
	X(LSD_ERROR_NOHANDLER,		"No handler found") \
	X(LSD_ERROR_LOAD_MODULE,	"Unable to load module") \
	X(LSD_ERROR_DB,			"Database error") \
	X(LSD_ERROR_TLS_READ,		"TLS read error") \
	X(LSD_ERROR_TLS_WRITE,		"TLS write error") \
	X(LSD_ERROR_WEBSOCKET_RSVBITSET,           "(websocket) Reserved bit set") \
	X(LSD_ERROR_WEBSOCKET_BAD_OPCODE,          "(websocket) Bad opcode") \
	X(LSD_ERROR_WEBSOCKET_UNMASKED_DATA,       "(websocket) Unmasked client data") \
	X(LSD_ERROR_WEBSOCKET_CLOSE_CONNECTION,    "(websocket) Connection close requested") \
	X(LSD_ERROR_WEBSOCKET_FRAGMENTED_CONTROL,  "(websocket) Fragmented control frame") \
	X(LSD_ERROR_WEBSOCKET_UNEXPECTED_CONTINUE, "(websocket) Unexpected continuation frame") \
	X(LSD_ERROR_WEBSOCKET_UNEXPECTED_PONG,     "(websocket) Unexpected pong frame") \
	X(LSD_ERROR_LIBRECAST_CONTEXT_NULL,        "(librecast) Operation on null context") \
	X(LSD_ERROR_LIBRECAST_CHANNEL_NOT_EXIST,   "(librecast) No such channel") \
	X(LSD_ERROR_LIBRECAST_CHANNEL_NOT_SELECTED, "(librecast) No channel selected") \
	X(LSD_ERROR_LIBRECAST_CHANNEL_NOT_CREATED, "(librecast) Unable to create channel") \
	X(LSD_ERROR_LIBRECAST_CHANNEL_NOT_JOINED,  "(librecast) Unable to join channel") \
	X(LSD_ERROR_LIBRECAST_LISTEN_FAIL,         "(librecast) Listen failed on socket") \
	X(LSD_ERROR_LIBRECAST_NO_SOCKET,           "(librecast) No socket") \
	X(LSD_ERROR_LIBRECAST_OPCODE_INVALID,      "(librecast) Invalid opcode") \
	X(LSD_ERROR_LIBRECAST_SOCKET_NOT_CREATED,  "(librecast) Unable to create socket") \
	X(LSD_ERROR_LIBRECAST_INVALID_SOCKET_ID,   "(librecast) Invalid socket id") \
	X(LSD_ERROR_LIBRECAST_INVALID_PARAMS,      "(librecast) Invalid parameters to function")

#undef X

#define LSD_ERROR_MSG(name, msg) case name: return msg;
#define LSD_ERROR_ENUM(name, msg) name,
enum {
	LSD_ERROR_CODES(LSD_ERROR_ENUM)
};

/* log message and return code */
int err_log(unsigned int level, int e);

/* return human readable error message for e */
char *err_msg(int e);

/* print human readable error, using errsv (errno) or progam defined (e) code */
void err_print(int e, int errsv, char *errstr);

#endif /* __LSD_ERR_H__ */
