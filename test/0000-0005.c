/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/config.h"
#include "../src/server.h"

int main()
{
	char *argv[] = { "0000-0005", "--loglevel", "127", "--config", "./0000-0005.conf", NULL };
	int argc = sizeof argv / sizeof argv[0] - 1;
	pid_t pid;

	test_name("server_listen()");
	pid = fork();
	if (!pid) {
		close(1); /* prevent server messing up test output */
		config_init(argc, argv);
		config_load_modules();
		server_listen();
		config_unload_modules();
		config_close();
	}

	return fails;
}
