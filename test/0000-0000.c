/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/config.h"

int main()
{
	char dbpath[] = "0000-0000.tmp.XXXXXX";
	test_name("config_init_db() / config_close()");

	/* check for leaks - requires make check */
	config_init_db(mkdtemp(dbpath));
	config_close();

	return fails;
}
