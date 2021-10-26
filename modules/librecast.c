/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only
 *
 * librecast.c
 *
 * this file is part of LIBRESTACK
 *
 * Copyright (c) 2017-2021 Brett Sheffield <bacs@librecast.net>
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

#include "../src/err.h"
#include "../src/handler.h"
#include "../src/log.h"
#include "../src/str.h"
#include "librecast.h"

#include <arpa/inet.h>
#include <assert.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LCDB _LIBRECAST_DB_H

typedef struct lcast_sock_t {
	lc_socket_t *sock;
	uint32_t id;
	uint32_t token;
	struct lcast_sock_t *next;
} lcast_sock_t;

typedef struct lcast_chan_t {
	lc_channel_t *chan;
	uint32_t id;
	char *name;
	struct lcast_chan_t *next;
} lcast_chan_t;

static conn_t *websock;
static pthread_t keepalive_thread;
static lc_ctx_t *lctx;
static lcast_sock_t *lsock;
static lcast_chan_t *lchan;
session_t session;
uint64_t uid;
uint64_t sid;
uint64_t sss;

lcast_chan_t *lcast_channel_byid(uint32_t id);
lcast_chan_t *lcast_channel_byname(char *name);
lcast_chan_t *lcast_channel_new(char *name);
lcast_sock_t *lcast_socket_byid(uint32_t id);
lcast_sock_t *lcast_socket_new(void);
void lcast_channel_free(lcast_chan_t *chan);
int lcast_frame_decode(ws_frame_t *f, lcast_frame_t **r);
int lcast_frame_send(conn_t *c, lcast_frame_t *req, char *payload, uint32_t paylen);
void lcast_recv(lc_message_t *msg);
void lcast_recv_err(int err);

#if LCDB
static void lcast_session_register(void)
{
	int mode = LC_DB_MODE_DUP | LC_DB_MODE_BOTH;
	lc_db_idx(lctx, "session", "user", &sid, sizeof sid, &uid, sizeof uid, mode);
}
#endif

static int lcast_session_id(uint64_t *sid)
{
	FILE *fd = fopen("/dev/urandom", "r");
	if (fd == NULL)
		return -1;
	if (fread(sid, sizeof *sid, 1, fd) != sizeof *sid)
		return -1;
	fclose(fd);
	return 0;
}

static void lcast_session_start(void)
{
	lcast_session_id(&sid);
	sss = time(NULL);
	memset(&session, 0, sizeof session);
#if LCDB
	lcast_session_register();
#endif
}

static void lcast_session_update(uint64_t byi, uint64_t byo, uint64_t wsi, uint64_t wso)
{
	if (session.byi + byi > UINT64_MAX || session.byo + byo > UINT64_MAX
	||  session.wsi + wsi > UINT64_MAX || session.wso + wso > UINT64_MAX)
	{
		/* overflow, start new session */
		lcast_session_update(0, 0, 0, 0);
		lcast_session_start();
	}
	session.end = time(NULL);
	session.byi += byi;
	session.byo += byo;
	logmsg(LOG_DEBUG, "session %lu bytes in %lu bytes out", session.byi, session.byo);
	/* TODO: configure option - log to local db and/or channel */
#if LCDB
	lc_db_set(lctx, "session", &sid, sizeof sid, &session, sizeof session);
#endif
}

static int lcast_cmd_register(conn_t *c, lcast_frame_t *req, char *payload)
{
	(void)c; (void)req; (void)payload; /* FIXME */
	logmsg(LOG_TRACE, "%s", __func__);
	/* TODO: unpack / check sig on cap token */
	/* TODO: set uid */
#if LCDB
	lcast_session_register();
#endif
	return 0;
}

lcast_sock_t *lcast_socket_byid(uint32_t id)
{
	lcast_sock_t *p = lsock;

	logmsg(LOG_TRACE, "%s", __func__);
	while (p) {
		if (p->id == id)
			return p;
		p = p->next;
	}

	return NULL;
}

lcast_chan_t *lcast_channel_byid(uint32_t id)
{
	lcast_chan_t *p = lchan;

	logmsg(LOG_TRACE, "%s", __func__);
	logmsg(LOG_FULLTRACE, "id=%u", id);
	while (p) {
		if (p->id == id)
			return p;
		p = p->next;
	}
	logmsg(LOG_FULLTRACE, "exiting %s", __func__);

	return NULL;
}

lcast_chan_t *lcast_channel_byname(char *name)
{
	lcast_chan_t *p = lchan;

	logmsg(LOG_TRACE, "%s", __func__);
	while (p) {
		if (strcmp(p->name, name) == 0)
			return p;
		p = p->next;
	}

	return NULL;
}

void lcast_channel_free(lcast_chan_t *chan)
{
	logmsg(LOG_TRACE, "%s", __func__);
	if (chan) {
		lc_channel_free(chan->chan);
		free(chan->name);
		free(chan);
		chan = NULL;
	}
}

lcast_sock_t *lcast_socket_new(void)
{
	lcast_sock_t *sock = NULL;
	lcast_sock_t *p;
	int opt = 1;

	logmsg(LOG_TRACE, "%s", __func__);
	lcast_init();
	DEBUG("(librecast) CREATE socket");
	sock = calloc(1, sizeof(struct lcast_sock_t));
	sock->sock = lc_socket_new(lctx);
	sock->id = lc_socket_get_id(sock->sock);
	lc_socket_setopt(sock->sock, IPV6_MULTICAST_LOOP, &opt, sizeof(opt));
	DEBUG("socket id %u created", sock->id);
	for (p = lsock; p != NULL; p = p->next) {
		if (p->next == NULL) {
			p->next = sock;
			break;
		}
	}
	if (lsock == NULL)
		lsock = sock;

	return sock;
}

lcast_chan_t *lcast_channel_new(char *name)
{
	lcast_chan_t *chan = NULL;
	lcast_chan_t *p = lchan;

	logmsg(LOG_TRACE, "%s", __func__);
	lcast_init();

	/* check for existing channel */
	while (p) {
		chan = p;
		if (strcmp(p->name, name) == 0)
			return p;
		p = p->next;
	}
	p = chan;

	/* no such channel, create it */
	DEBUG("(librecast) CREATE channel '%s'", name);
	chan = calloc(1, sizeof(struct lcast_chan_t));
	chan->chan = lc_channel_new(lctx, name);
	chan->name = name;
	chan->id = lc_channel_get_id(chan->chan);

	if (p)
		p->next = chan;

	if (lchan == NULL)
		lchan = chan;

	return chan;
}

int lcast_frame_decode(ws_frame_t *f, lcast_frame_t **r)
{
	size_t offset = 0;
	char *head = (char*) (f->data);
	lcast_frame_t *req;

	logmsg(LOG_TRACE, "%s", __func__);
	req = calloc(1, sizeof(lcast_frame_t));

	bcopy(head, &req->opcode, sizeof(req->opcode));
	offset += sizeof(req->opcode);

	bcopy(head + offset, &req->len, sizeof(req->len));
	req->len = ntohl(req->len);
	offset += sizeof(req->len);

	bcopy(head + offset, &req->id, sizeof(req->id));
	req->id = ntohl(req->id);
	offset += sizeof(req->id);

	bcopy(head + offset, &req->id2, sizeof(req->id2));
	req->id2 = ntohl(req->id2);
	offset += sizeof(req->id2);

	bcopy(head + offset, &req->token, sizeof(req->token));
	req->token = ntohl(req->token);
	offset += sizeof(req->token);

	*r = req;

	return 0;
}

int lcast_frame_send(conn_t *c, lcast_frame_t *req, char *payload, uint32_t paylen)
{
	lcast_frame_t *msg;
	char *buf;
	char *body;
	size_t len_head;
	size_t len_body;
	size_t len_send;
	ssize_t bytes;

	logmsg(LOG_TRACE, "%s", __func__);
	len_head = sizeof(lcast_frame_t);
	len_body = (size_t)paylen;
	len_send = len_head + len_body;

	lcast_cmd_debug(req, payload);

	msg = calloc(1, sizeof(lcast_frame_t));
	msg->opcode = req->opcode;
	msg->len = htonl(paylen);
	msg->id = htonl(req->id);
	msg->id2 = htonl(req->id2);
	msg->token = htonl(req->token);

	DEBUG("lcast timestamp: %"PRIu64"", req->timestamp);
	msg->timestamp = htobe64(req->timestamp);

	buf = calloc(1, len_send);
	memcpy(buf, msg, len_head);
	if (payload && paylen > 0) {
		body = buf + len_head;
		memcpy(body, payload, len_body);
	}

	DEBUG("lcast_frame_send sending %zi bytes (head)", len_head);
	DEBUG("lcast_frame_send sending %zi bytes (body)", len_body);
	DEBUG("lcast_frame_send sending %zi bytes (total)", len_send);

	if ((bytes = ws_send(c, WS_OPCODE_BINARY, buf, len_send)) > 0)
		lcast_session_update(0, 0, 0, bytes);

	return 0;
}

int lcast_cmd_channel_bind(conn_t *c, lcast_frame_t *req, char *payload)
{
	(void)payload;
	lcast_chan_t *chan;
	lcast_sock_t *s;

	logmsg(LOG_TRACE, "%s", __func__);
	if ((chan = lcast_channel_byid(req->id)) == NULL)
		FAIL(LSD_ERROR_LIBRECAST_CHANNEL_NOT_EXIST);

	if ((s = lcast_socket_byid(req->id2)) == NULL)
		FAIL(LSD_ERROR_LIBRECAST_INVALID_SOCKET_ID);

	lc_channel_bind(s->sock, chan->chan);
	lcast_frame_send(c, req, NULL, 0);

	return 0;
}

int lcast_cmd_channel_join(conn_t *c, lcast_frame_t *req, char *payload)
{
	(void)payload;
	lcast_chan_t *chan;

	logmsg(LOG_TRACE, "%s", __func__);
	if ((chan = lcast_channel_byid(req->id)) == NULL)
		FAIL(LSD_ERROR_LIBRECAST_CHANNEL_NOT_EXIST);
	lc_channel_join(chan->chan);
	lcast_frame_send(c, req, NULL, 0);

	return 0;
}

int lcast_cmd_channel_new(conn_t *c, lcast_frame_t *req, char *payload)
{
	lcast_chan_t *chan;
	char *channel;

	logmsg(LOG_TRACE, "%s", __func__);
	channel = calloc(1, req->len + 1);
	memcpy(channel, payload, req->len);

	if ((chan = lcast_channel_new(channel)) == NULL)
		FAIL(LSD_ERROR_LIBRECAST_CHANNEL_NOT_CREATED);

	req->id = chan->id;
	lcast_frame_send(c, req, NULL, 0);

	return 0;
}

int lcast_cmd_channel_part(conn_t *c, lcast_frame_t *req, char *payload)
{
	(void)c; (void)payload;
	lcast_chan_t *chan;

	logmsg(LOG_TRACE, "%s", __func__);
	if ((chan = lcast_channel_byid(req->id)) == NULL)
		FAIL(LSD_ERROR_LIBRECAST_CHANNEL_NOT_EXIST);
	lc_channel_part(chan->chan);
	lcast_frame_send(c, req, NULL, 0);
	lcast_channel_free(chan);

	return 0;
}

int lcast_cmd_channel_send(conn_t *c, lcast_frame_t *req, char *payload)
{
	(void)c; (void)payload;
	lcast_chan_t *chan;
	lc_message_t msg;
	size_t bytes;

	logmsg(LOG_TRACE, "%s", __func__);
	if (!uid) {
		/* TODO: unknown user, only allow auth channel */
	}
	if ((chan = lcast_channel_byid(req->id)) == NULL)
		FAIL(LSD_ERROR_LIBRECAST_CHANNEL_NOT_EXIST);

	lc_msg_init_size(&msg, req->len);
	memcpy(lc_msg_data(&msg), payload, req->len);
	bytes = lc_msg_send(chan->chan, &msg);
	lcast_session_update(0, bytes, 0, 0);

	return 0;
}

#if LCDB
int lcast_cmd_channel_getmsg(conn_t *c, lcast_frame_t *req, char *payload)
{
	(void)c;
	char *tmp;
	int op = 0;
	int rc, msgs;
	lcast_chan_t *chan;
	lc_query_t *q = NULL;
	lc_messagelist_t *msglist = NULL, *msg;
	lcast_frame_t *rep = NULL;
	uint32_t i = 0;
	uint32_t len = 0;
	uint64_t timestamp;

	logmsg(LOG_TRACE, "%s", __func__);
	if (req == NULL)
		FAIL(LSD_ERROR_LIBRECAST_INVALID_PARAMS);
	if ((chan = lcast_channel_byid(req->id)) == NULL)
		FAIL(LSD_ERROR_LIBRECAST_CHANNEL_NOT_EXIST);

	if ((rc = lc_query_new(lc_channel_ctx(chan->chan), &q)) != 0)
		FAIL(rc);

	/* only retrieve messages for this channel */
	lc_query_push(q, LC_QUERY_CHANNEL, chan->name);

	/* process payload into query filters */
	/* [queryop(16)][len(32)][data] */
	while (i < req->len) {
		memcpy(&op, payload + i, 2); i += 2;
		op = be16toh(op);
		memcpy(&len, payload + i, 4); i += 4;
		len = be32toh(len);
		DEBUG("query opcode: %i", op);
		if (op == LC_QUERY_DB || op == LC_QUERY_KEY) {
			tmp = calloc(1, len + 1);
			memcpy(tmp, payload + i, len);
			DEBUG("query db/key: %s", tmp);
			lc_query_push(q, op, tmp);
			i += len;
			continue;
		}
		else if ((op & LC_QUERY_TIME) == LC_QUERY_TIME) {
			tmp = calloc(1, len + 1);
			memcpy(tmp, payload + i, len);
			timestamp = strtoumax(tmp, NULL, 10);
			free(tmp);
			DEBUG("query timestamp: %"PRIu64, timestamp);
			lc_query_push(q, op, &timestamp);
			i += len;
			continue;
		}
		else {
			break;
		}
	}

	msgs = lc_query_exec(q, &msglist);

	DEBUG("found %i messages", msgs);
	for (msg = msglist; msg != NULL; msg = msg->next) {
		rep = calloc(1, sizeof(lcast_frame_t));
		rep->opcode = LCAST_OP_SOCKET_MSG;
		rep->id = req->id;
		rep->token = req->token;
		rep->timestamp = msg->timestamp;

		/* replay the message */
		lcast_frame_send(websock, rep, msg->data, strlen(msg->data));
		free(rep);
	}

	lc_msglist_free(msglist);
	lc_query_free(q);

	logmsg(LOG_TRACE, "%s exiting", __func__);
	return 0;
}
#endif

int lcast_cmd_channel_getop(conn_t *c, lcast_frame_t *req, char *payload)
{
	(void)c; (void)req; (void)payload;

	logmsg(LOG_TRACE, "%s", __func__);

	/* TODO */

	return 0;
}

int lcast_cmd_channel_setop(conn_t *c, lcast_frame_t *req, char *payload)
{
	(void)c; (void)req; (void)payload;

	logmsg(LOG_TRACE, "%s", __func__);

	/* TODO */

	return 0;
}

#if LCDB
int lcast_cmd_channel_getval(conn_t *c, lcast_frame_t *req, char *payload)
{
	lcast_chan_t *chan;
	lc_channel_t *lchan;
	void *v;
	size_t vlen;

	logmsg(LOG_TRACE, "%s", __func__);
	if (req == NULL)
		FAIL(LSD_ERROR_LIBRECAST_INVALID_PARAMS);
	if (payload == NULL)
		FAIL(LSD_ERROR_LIBRECAST_INVALID_PARAMS);
	if ((chan = lcast_channel_byid(req->id)) == NULL)
		FAIL(LSD_ERROR_LIBRECAST_CHANNEL_NOT_EXIST);
	lchan = chan->chan;

	/* fetch from local cache */
	if (lc_db_get(lc_channel_ctx(lchan), lc_channel_uri(lchan), payload, req->len,
				&v, &vlen) == 0)
	{
		lcast_frame_send(c, req, v, vlen);
		free(v);
	}

	/* send request for latest value to network */
	lc_val_t key;
	key.data = payload;
	key.size = req->len;
	lc_channel_getval(lchan, &key);

	return 0;
}

int lcast_cmd_channel_setval(conn_t *c, lcast_frame_t *req, char *payload)
{
	(void)c;
	lcast_chan_t *chan;
	lc_channel_t *lchan;
	lc_val_t key, val;
	size_t keylen_size = 4;

	logmsg(LOG_TRACE, "%s", __func__);
	if (req == NULL)
		FAIL(LSD_ERROR_LIBRECAST_INVALID_PARAMS);
	if ((chan = lcast_channel_byid(req->id)) == NULL)
		FAIL(LSD_ERROR_LIBRECAST_CHANNEL_NOT_EXIST);
	if (payload == NULL)
		FAIL(LSD_ERROR_LIBRECAST_INVALID_PARAMS);

	lchan = chan->chan;

	/* extract key and value from payload */
	/* [keylen][key][val] */
	memcpy(&key.size, payload, keylen_size);
	key.size = be32toh(key.size);
	key.data = malloc(key.size);
	memcpy((&key)->data, payload + keylen_size, key.size);
	val.size = req->len - key.size - keylen_size;
	val.data = malloc(val.size);
	memcpy((&val)->data, payload + keylen_size + key.size, val.size);

	/* save to local cache */
	lc_db_set(lc_channel_ctx(lchan), lc_channel_uri(lchan), key.data, key.size, val.data, val.size);

	/* send to network */
	lc_channel_setval(lchan, &key, &val);

	free(key.data);
	free(val.data);

	logmsg(LOG_FULLTRACE, "%s exiting", __func__);
	return 0;
}
#endif

int lcast_cmd_channel_unbind(conn_t *c, lcast_frame_t *req, char *payload)
{
	(void)c; (void)req; (void)payload;

	logmsg(LOG_TRACE, "%s", __func__);

	/* TODO */

	return 0;
}

int lcast_cmd_socket_close(conn_t *c, lcast_frame_t *req, char *payload)
{
	(void)c; (void)req; (void)payload;

	logmsg(LOG_TRACE, "%s", __func__);

	/* TODO */

	return 0;
}

int lcast_cmd_socket_ignore(conn_t *c, lcast_frame_t *req, char *payload)
{
	(void)c; (void)req; (void)payload;

	logmsg(LOG_TRACE, "%s", __func__);

	/* TODO */

	return 0;
}

int lcast_cmd_socket_listen(conn_t *c, lcast_frame_t *req, char *payload)
{
	(void)payload;
	lcast_sock_t *s;

	logmsg(LOG_TRACE, "%s", __func__);
	if ((s = lcast_socket_byid(req->id)) == NULL)
		FAIL(LSD_ERROR_LIBRECAST_INVALID_SOCKET_ID);

	websock = c;
	s->token = req->token;
	lc_socket_listen(s->sock, lcast_recv, lcast_recv_err);

	return 0;
}

int lcast_cmd_socket_new(conn_t *c, lcast_frame_t *req, char *payload)
{
	(void)payload;
	lcast_sock_t *s;

	logmsg(LOG_TRACE, "%s", __func__);
	if ((s = lcast_socket_new()) == NULL)
		FAIL(LSD_ERROR_LIBRECAST_SOCKET_NOT_CREATED);

	req->id = s->id;
	lcast_frame_send(c, req, NULL, 0);

	return 0;
}

static int lcast_cmd_socket_getopt(conn_t *c, lcast_frame_t *req, char *payload)
{
	(void)c; (void)req; (void)payload;

	logmsg(LOG_TRACE, "%s", __func__);

	/* TODO */

	return 0;
}

int lcast_cmd_socket_setopt(conn_t *c, lcast_frame_t *req, char *payload)
{
	(void)c; (void)req; (void)payload;

	logmsg(LOG_TRACE, "%s", __func__);

	/* TODO */

	return 0;
}

void lcast_cmd_debug(lcast_frame_t *req, char *payload)
{
	(void)payload;
	char *command = lcast_cmd_name(req->opcode);

	logmsg(LOG_TRACE, "%s", __func__);
	DEBUG("(librecast) %s: opcode='%x'", command, req->opcode);
	DEBUG("(librecast) %s: len='%x'", command, req->len);
	DEBUG("(librecast) %s: id='%u'", command, req->id);
	DEBUG("(librecast) %s: id2='%u'", command, req->id2);
	DEBUG("(librecast) %s: token='%u'", command, req->token);
#ifdef LCAST_DEBUG_LOG_PAYLOAD
	if (payload) {
		char *msg = calloc(1, req->len + 1);
		memcpy(msg, payload, req->len);
		DEBUG("(librecast) %s: '%s'", command, msg);
		free(msg);
	}
#endif
	logmsg(LOG_FULLTRACE, "%s exiting", __func__);
}

int lcast_cmd_noop(conn_t *c, lcast_frame_t *req, char *payload)
{
	(void)c; (void)req; (void)payload;
	logmsg(LOG_TRACE, "%s", __func__);
	return 0;
}

int lcast_cmd_handler(conn_t *c, ws_frame_t *f)
{
	static char *stash = NULL;
	char *payload = NULL;
	static uint64_t len = 0;
	char *data = (char *)(f->data) + sizeof(lcast_frame_t);
	lcast_frame_t *req = NULL;

	logmsg(LOG_TRACE, "%s", __func__);
	lcast_frame_decode(f, &req);
	lcast_session_update(0, 0, req->len, 0);

	if (f->opcode <= 0x2) {
		/* data frame */
		if (f->opcode != WS_OPCODE_CONTINUE) {
			/* first or only frame in set */
			len = 0;
			free(stash);
			stash = NULL;
		}

		stash = realloc(stash, req->len + len);
		assert(stash);

		memcpy(stash + len, data, req->len);
		lcast_cmd_debug(req, stash);
		len += req->len;
		payload = stash;
	}

	/* NB: control frames can arrive between fragmented data frames */

	if (f->fin) {
		/* FIN bit set. This is either the last or only frame in the set. */
		switch (req->opcode) {
			LCAST_OPCODES(LCAST_OP_FUN)
		default:
			ERRMSG(LSD_ERROR_LIBRECAST_OPCODE_INVALID);
		}
		free(stash);
		stash = NULL;
	}
	free(req);

	return 0;
}

char *lcast_cmd_name(lcast_opcode_t opcode)
{
	logmsg(LOG_TRACE, "%s", __func__);
	LCAST_OPCODES(LCAST_OP_CODE)
	return NULL;
}

int lcast_handle_client_data(conn_t *c, ws_frame_t *f)
{
	logmsg(LOG_TRACE, "%s", __func__);
	DEBUG("lc_handle_client_data() has opcode 0x%x", f->opcode);

	switch (f->opcode) {
	case 0x0:
		DEBUG("(librecast) DATA (continuation frame)");
		return lcast_cmd_handler(c, f);
	case 0x1:
		DEBUG("(librecast) DATA (text)");
		FAIL(LSD_ERROR_NOT_IMPLEMENTED);
	case 0x2:
		DEBUG("(librecast) DATA (binary)");
		return lcast_cmd_handler(c, f);
	default:
		DEBUG("opcode 0x%x not valid for data frame", f->opcode);
		break;
	}

	return 0;
}

static void * lcast_keepalive(void *arg)
{
	(void)arg;
	unsigned int seconds = LCAST_KEEPALIVE_INTERVAL;
	ssize_t bytes;

	while(websock) {
		sleep(seconds);
		DEBUG("keepalive ping (%us)", seconds);
		if ((bytes = ws_send(websock, WS_OPCODE_PING, NULL, 0)) < 2)
			break;
		lcast_session_update(0, 0, 0, bytes);
	}
	DEBUG("thread %s exiting", __func__);

	return NULL;
}

void lcast_init(void)
{
	logmsg(LOG_TRACE, "%s", __func__);
	lcast_session_start();
	if (lctx == NULL)
		lctx = lc_ctx_new();
	assert(lctx != NULL);
#if LCDB
	lc_db_open(lctx, NULL);
#endif
	DEBUG("LIBRECAST CONTEXT id=%u", lc_ctx_get_id(lctx));

	/* start PING thread */
	if (keepalive_thread == 0) {
		pthread_attr_t attr = {0};
		pthread_attr_init(&attr);
		pthread_create(&keepalive_thread, &attr, lcast_keepalive, NULL);
		pthread_attr_destroy(&attr);
	}
}

void lcast_recv(lc_message_t *msg)
{
	lcast_frame_t *req = calloc(1, sizeof(lcast_frame_t));
	char *data;
	size_t skip = 0;

	logmsg(LOG_TRACE, "%s", __func__);
	lcast_session_update(msg->bytes, 0, 0, 0);
	switch (msg->op) {
	case LC_OP_RET:
		req->opcode = LCAST_OP_CHANNEL_GETVAL;
		skip = sizeof(lc_seq_t) + sizeof(lc_rnd_t);
		break;
	case LC_OP_SET:
		req->opcode = LCAST_OP_CHANNEL_SETVAL;
		break;
	default:
		req->opcode = LCAST_OP_SOCKET_MSG;
	}
	req->len = msg->len - skip;
	data = (char *)msg->data + skip;
	req->id = msg->sockid;
	req->timestamp = msg->timestamp;

	lcast_sock_t *s;
	if ((s = lcast_socket_byid(msg->sockid)) != NULL)
		req->token = s->token;

	lcast_frame_send(websock, req, data, req->len);
	free(req);
}

void lcast_recv_err(int err)
{
	logmsg(LOG_TRACE, "%s", __func__);
	/* TODO: fetch error from librecast */
	DEBUG("lcast_recv_err(): %i", err);
}
