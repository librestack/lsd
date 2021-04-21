/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/config.h"

int main()
{
	char dbpath[] = "0000-0002.tmp.XXXXXX";
	int argc = 3;
	char *dbtemp = mkdtemp(dbpath);
	char *argv[] = { "0000-0001", "--dbpath", dbtemp, NULL };
	char notfound[] = "--ignoreme";
	test_name("config_dbpath()");
	test_expect(dbtemp, config_dbpath(argc, argv));
	argv[1] = notfound;
	test_assert(config_dbpath(argc, argv) == NULL, "no --dbpath supplied");
	return fails;
}
