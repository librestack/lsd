#include "log.h"
#include <stdio.h>
#include <unistd.h>

unsigned int loglevel;

int init()
{
	loglevel = 127;
	DEBUG("Module ECHO init()");
	return 0;
}
