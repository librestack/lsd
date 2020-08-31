/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"
#include "../src/config.h"

int main()
{
	test_name("testing tests");

	test_assert(0 == 0, "this passes");

	test_assert(config_init(0, NULL) == 0, "config_init()");

	return fails;
}