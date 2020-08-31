/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/config.h"
#include "../src/err.h"

int main()
{
	char dbpath[] = "0000-0001.tmp.XXXXXX";
	test_name("config_mime_load()");

	test_log("expecting Database error...");
	test_assert(config_mime_load() == LSD_ERROR_DB, "config_mime_load() requires database");

	test_log("now, try again with a database");
	config_init_db(mkdtemp(dbpath));
	config_mime_load();
	config_close();

	return fails;
}
