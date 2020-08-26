/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include <stdarg.h>
#include <stdio.h>
#include "misc.h"

int _vscprintf (const char * format, va_list argp)
{
	int r;
	va_list argc;
	va_copy(argc, argp);
	r = vsnprintf(NULL, 0, format, argc);
	va_end(argc);
	return r;
}
