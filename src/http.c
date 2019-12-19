#include "config.h"
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <unistd.h>

/* FIXME: move to header file */
#define HTTP_OK				200
#define HTTP_BAD_REQUEST		400
#define HTTP_VERSION_NOT_SUPPORTED	505

ssize_t http_readline(int sock, char *buf)
{
	ssize_t len = recv(sock, buf, BUFSIZ - 1, 0);

	/* scan buffer for newline and remove */
	for (int i = len; i > 0; i--) {
		if (buf[i] == '\n') {
			buf[i] = '\0';
			//return --i;
			len - i;
		}
		if (buf[i] == '\n') {
			buf[i] = '\0';
			len - i;
		}
	}

	return len;
}

int http_read_request(char *buf, size_t len)
{
	char method[len];
	char resource[len];
	char httpv[len];

	if (!buf) return HTTP_BAD_REQUEST;
	if (sscanf(buf, "%s %s HTTP/%s", method, resource, httpv) != 3)
		return HTTP_BAD_REQUEST;
	if ((strcmp(httpv, "1.0")) && (strcmp(httpv, "1.1")))
		return HTTP_VERSION_NOT_SUPPORTED;
	
	fprintf(stderr, "%s\n", buf);
	
	return HTTP_OK;
}

void http_status(int sock, int status)
{
	dprintf(sock, "HTTP/1.1 %i - Some Status Here\r\n", status);
}

int init(int sock, proto_t *p)
{
	char buf[BUFSIZ];
	ssize_t len;
	int err = 0;
	int state = 1;

	//dprintf(sock, "%s\n", p->module);

	while ((len = http_readline(sock, buf))) {
		//state = 1;
		//setsockopt(sock, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));
		//dprintf(sock, "got %li bytes\r\n", len);
		err = http_read_request(buf, len);
		http_status(sock, err);
		dprintf(sock, "Content-Type: text/plain\r\n");
		dprintf(sock, "Content-Length: 7\r\n");
		//dprintf(sock, "Connection: close\r\n");
		send(sock, "\r\n", 2, 0);
		send(sock, "hello\r\n", 7, 0);
		send(sock, "\r\n", 2, 0);
		//sprintf(buf, "Some more info here\r\n");
		//send(sock, buf, strlen(buf), 0);
		int state = 0;
		setsockopt(sock, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));
	}

	return 0;
}
