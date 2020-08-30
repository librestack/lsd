#include "log.h"
#include <stdio.h>
#include <unistd.h>

unsigned int loglevel;

int init(void)
{
	loglevel = 127;
	DEBUG("Module ECHO init()");
	return 0;
}
