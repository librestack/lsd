#include "../src/log.h"
#include <stdio.h>
#include <unistd.h>

int init(void)
{
	loglevel = 127;
	DEBUG("Module ECHO init()");
	return 0;
}
