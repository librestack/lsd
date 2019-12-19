#include "log.h"
#include <stdio.h>
#include <unistd.h>

int init(int sock, proto_t *p)
{
	char buf[1024] = "";
	ssize_t len;
	dprintf(sock, "Module %s\n", p->module);
	while(len = read(sock, buf, 1023) > 0) {
		dprintf(sock, "%s", buf);
	}
	return 0;
}
