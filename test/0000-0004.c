/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/config.h"

int main()
{
	char *argv[] = { "0000-0004", "--loglevel", "127", "--config", "./0000-0004.conf", NULL };
	int argc = sizeof argv / sizeof argv[0] - 1;

	test_name("config_load_modules() / config_unload_modules()");
	config_init(argc, argv);
	config_load_modules();
	config_unload_modules();
	config_close();

	return fails;
}
