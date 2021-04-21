/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/config.h"

int main()
{
	char dbpath[] = "0000-0003.tmp.XXXXXX";
	char *dbtemp = mkdtemp(dbpath);
	char *argv[] = { "0000-0003", "--dbpath", dbtemp, NULL };
	int argc = sizeof argv / sizeof argv[0] - 1;
	test_name("config_init() / config_close()");

	/* check for leaks - requires make check */
	config_init(argc, argv);

	/* simulate multiple HUPs */
	for (int i = 0; i < 10; i++) config_init(0, NULL);
	config_close();

	return fails;
}
