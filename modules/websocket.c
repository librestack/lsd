/* SPDX-License-Identifier: GPL-3.0-or-later
 *
 * websocket.c
 *
 * this file is part of LIBRESTACK
 *
 * Copyright (c) 2017-2020 Brett Sheffield <bacs@librecast.net>
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
#include "librecast.h"
#include "websocket.h"
#include "../src/err.h"
#include "../src/handler.h"
#include "../src/log.h"
#include "../src/str.h"
#include <arpa/inet.h>
#include <endian.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int ws_proto = WS_PROTOCOL_INVALID;

typedef struct ws_frame_header_t {
	uint8_t f1;
	uint8_t f2;
} ws_frame_header_t;

int ws_do_close(conn_t *c, ws_frame_t *f)
{
	(void)c; (void) f;
	DEBUG("(websocket) CLOSE");
	/* TODO: handle connection close reasons */
	return LSD_ERROR_WEBSOCKET_CLOSE_CONNECTION;
}

int ws_do_data(conn_t *c, ws_frame_t *f)
{
	DEBUG("(websocket) protocol: %s", ws_protocol_name(ws_proto));
	switch (ws_proto) {
		WS_PROTOCOLS(WS_PROTOCOL_FUN)
	}
	return 0;
}

int ws_do_noop(conn_t *c, ws_frame_t *f)
{
	(void)c; (void) f;
	DEBUG("(websocket) NOOP");
	return 0;
}

int ws_do_ping(conn_t *c, ws_frame_t *f)
{
	DEBUG("(websocket) PING");
	ws_send(c, WS_OPCODE_PONG, f->data, f->len);
	return 0;
}

int ws_do_pong(conn_t *c, ws_frame_t *f)
{
	(void)c; (void) f;
	/* TODO: handle client reply to our PING */
	DEBUG("(websocket) PONG");
	return 0;
}

int ws_handle_client_data(conn_t *c, ws_frame_t *f)
{
	(void)c;
	switch (f->opcode) {
	case 0x0:
		DEBUG("(websocket) DATA (continuation frame)");
		return LSD_ERROR_WEBSOCKET_UNEXPECTED_CONTINUE;
	case 0x1:
		DEBUG("(websocket) DATA (text)");
		break;
	case 0x2:
		DEBUG("(websocket) DATA (binary)");
		break;
	default:
		DEBUG("opcode 0x%x not valid for data frame", f->opcode);
		break;
	}
	return 0;
}

int ws_handle_request(conn_t *c)
{
	int err;
	ws_frame_t *f = NULL;

	err = ws_read_request(c, &f);
	if (err == 0) {
	        switch (f->opcode) {
			WS_OPCODES(WS_OPCODE_FUN)
		default:
			DEBUG("(websocket) unknown opcode %#x received", f->opcode);
			err = LSD_ERROR_WEBSOCKET_BAD_OPCODE;
			break;
		}
	}
	free(f);

	return err;
}
#if 0
static char *ws_opcode_desc(ws_opcode_t code)
{
	switch (code) {
		WS_OPCODES(WS_OPCODE_DESC)
	}
	return NULL;
}
#endif
char *ws_protocol_name(ws_protocol_t proto)
{
	switch (proto) {
		WS_PROTOCOLS(WS_PROTOCOL)
	};
	return NULL;
}

int ws_read_request(conn_t *c, ws_frame_t **ret)
{
	ws_frame_t *f;
	ws_frame_header_t *fh;
	ssize_t len;
	uint8_t mask, tmp;
	uint8_t masked, unmasked;
	uint32_t i;
	char *data;

	/* read websocket header */
	f = calloc(1, sizeof(struct ws_frame_t));
	fh = calloc(1, sizeof(struct ws_frame_header_t));
	len = rcv(c, fh, 2, 0);
	DEBUG("(websocket) %i bytes read (header)", (int)len);

	/* check some bit flags */
	f->fin = (fh->f1 & 0x80) >> 7;
	f->rsv1 = (fh->f1 & 0x40) >> 6;
	f->rsv2 = (fh->f1 & 0x20) >> 5;
	f->rsv3 = (fh->f1 & 0x10) >> 4;
	f->opcode = fh->f1 & 0xf;
	f->mask = (fh->f2 & 0x80) >> 7;
	f->len = fh->f2 & 0x7f;

	if (f->fin) {
		DEBUG("(websocket) FIN");
	}
	else if (f->opcode > 0x7) {
		FAIL(LSD_ERROR_WEBSOCKET_FRAGMENTED_CONTROL);
	}
	else {
		DEBUG("(websocket) fragmented frame received");
	}

	if (f->rsv1) {
		DEBUG("(websocket) RSV1");
		return err_log(LOG_ERROR, LSD_ERROR_WEBSOCKET_RSVBITSET);
	}
	if (f->rsv2) {
		DEBUG("(websocket) RSV2");
		return err_log(LOG_ERROR, LSD_ERROR_WEBSOCKET_RSVBITSET);
	}
	if (f->rsv3) {
		DEBUG("(websocket) RSV3");
		return err_log(LOG_ERROR, LSD_ERROR_WEBSOCKET_RSVBITSET);
	}

	switch (f->opcode) {
	case 0x0:
		DEBUG("(websocket) opcode 0x0: continuation frame");
		break;
	case 0x1:
		DEBUG("(websocket) opcode 0x1: text frame");
		break;
	case 0x2:
		DEBUG("(websocket) opcode 0x2: binary frame");
		break;
	/* %x3-7 are reserved for further non-control frames */
	case 0x8:
		DEBUG("(websocket) opcode 0x8: connection close");
		break;
	case 0x9:
		DEBUG("(websocket) opcode 0x9: ping");
		break;
	case 0xa:
		DEBUG("(websocket) opcode 0xa: pong");
		break;
	/* %xB-F are reserved for further control frames */
	default:
		DEBUG("(websocket) unknown opcode %#x received", f->opcode);
		return err_log(LOG_ERROR, LSD_ERROR_WEBSOCKET_BAD_OPCODE);
	}

	if (f->mask == 1) {
		DEBUG("(websocket) MASK");
	}
	else {
		logmsg(LOG_WARNING, "Rejecting unmasked client data");
		return err_log(LOG_ERROR, LSD_ERROR_WEBSOCKET_UNMASKED_DATA);
	}

	/* get payload length */
	if (f->len == 126) {
		/* 16 bit extended payload length */
		len = rcv(c, &(f->len), 2, 0);
		DEBUG("(websocket) %li bytes read (length)", len);
		f->len = ntohs(f->len);
	}
	else if (f->len == 127) {
		/* 64 bit extra specially extended payload length of great wonderfulness */
		len = rcv(c, &(f->len), 8, 0);
		DEBUG("(websocket) %li bytes read (length)", len);
		f->len = ntohll(f->len);
	}
	DEBUG("(websocket) length: %u", (unsigned int)f->len);

	/* get payload mask */
	len = rcv(c, &(f->maskkey), 4, 0);
	DEBUG("(websocket) %i bytes read (mask)", (int)len);
	DEBUG("(websocket) mask: %02x", ntohl(f->maskkey));

	/* read payload */
	data = calloc(1, f->len);
	len = rcv(c, data, f->len, 0);
	DEBUG("(websocket) %i bytes read (payload)", (int)len);

	/* unmask payload */
	f->data = calloc(1, f->len);
	for (i = 0; i < f->len; i++) {
		tmp = f->maskkey >> ((i % 4) * 8);
		bcopy(&tmp, &mask, 1);
		bcopy(data + i, &masked, 1);
		unmasked = mask ^ masked;
		bcopy(&unmasked, (char *)f->data + i, 1);
	}
	free(data);
	free(fh);

	*ret = f;

	return 0;
}

int ws_select_protocol(char *header)
{
	char *ptr, *tok;

	/* return the first matching protocol we support */
	for (tok = header; (ptr = strtok(tok, ",")); tok = NULL) {
		DEBUG("Trying protocol: %s", ptr);
		WS_PROTOCOLS(WS_PROTOCOL_SELECT)
	}

	return WS_PROTOCOL_INVALID;
}

ssize_t ws_send(conn_t *c, ws_opcode_t opcode, void *data, size_t len)
{
	uint16_t f = 0;
	uint16_t e16len = 0;
	uint64_t e64len = 0;
	ssize_t sent = 0;
	ssize_t bytes = 0;

	f |= 1 << 15; /* FIN */
	f |= opcode << 8;

	if (len < 126)
		f |= len;
	else if (len < UINT16_MAX) {
		DEBUG("extended (16) payload len=%i", (int) len);
		f |= 126;
		e16len = len;
	}
	else {
		DEBUG("extended (64) payload len=%i", (int) len);
		f |= 127;
		e64len = len;
	}
	f = htons(f);

	setcork(c->sock, 1);
	if ((bytes = snd(c, &f, 2, 0)) < 0)
		return -1;
	sent += bytes;

	if (e16len) {
		e16len = htons(e16len);
		if ((bytes = snd(c, &e16len, 2, 0)) < 0)
			return -1;
		sent += bytes;
	}
	else if (e64len) {
		e64len = htobe64(e64len);
		if ((bytes = snd(c, &e64len, 8, 0)) < 0)
			return -1;
		sent += bytes;
	}

	if ((bytes = snd(c, data, len, 0)) < 0)
		return -1;
	sent += bytes;
	setcork(c->sock, 0);
	DEBUG("%zi bytes sent", sent);

	return sent;
}
