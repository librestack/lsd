/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#include "test.h"

int fails = 0;

void vfail_msg(char *msg, va_list argp)
{
	char *b;
	b = malloc(_vscprintf(msg, argp) + 1);
	vsprintf(b, msg, argp);
	printf("\n            %-70s", b);
	free(b);
	fails++;
}

void fail_msg(char *msg, ...)
{
	va_list argp;
	va_start(argp, msg);
	vfail_msg(msg, argp);
	va_end(argp);
}

void test_assert(int condition, char *msg, ...)
{
	if (!condition) {
		va_list argp;
		va_start(argp, msg);
		vfail_msg(msg, argp);
		va_end(argp);
	}
}

void test_sleep(time_t tv_sec, long tv_nsec)
{
	struct timespec ts = { tv_sec, tv_nsec };
	test_log("test thread sleeping");
	nanosleep(&ts, NULL);
	test_log("test thread waking");
}

void test_strcmp(char *str1, char *str2, char *msg, ...)
{
	if (str1 == NULL || str2 == NULL || strcmp(str1, str2)) {
		va_list argp;
		va_start(argp, msg);
		vfail_msg(msg, argp);
		va_end(argp);
	}
}

void test_strncmp(char *str1, char *str2, size_t len, char *msg, ...)
{
	if (str1 == NULL || str2 == NULL || strncmp(str1, str2, len)) {
		va_list argp;
		va_start(argp, msg);
		vfail_msg(msg, argp);
		va_end(argp);
	}
}

void test_expect(char *expected, char *got)
{
	test_strcmp(expected, got, "expected: '%s', got: '%s'", expected, got);
}

void test_expectn(char *expected, char *got, size_t len)
{
	test_strncmp(expected, got, len, "expected: '%s', got: '%s'", expected, got);
}

void test_expectiov(struct iovec *expected, struct iovec *got)
{
	test_assert(expected->iov_len == got->iov_len, "expected '%.*s' (length mismatch) %zu != %zu",
			(int)expected->iov_len, (char *)expected->iov_base,
			expected->iov_len, got->iov_len);
	if (expected->iov_len != got->iov_len) return;
	test_strncmp(expected->iov_base, got->iov_base, expected->iov_len,
			"expected: '%.*s', got: '%.*s'",
			(int)expected->iov_len, (char *)expected->iov_base,
			(int)got->iov_len, (char *)got->iov_base);
}

void test_log(char *msg, ...)
{
	char *b;
	va_list argp;
	va_start(argp, msg);
	b = malloc(_vscprintf(msg, argp) + 1);
	vsprintf(b, msg, argp);
	fprintf(stderr, "%s\n", b);
	va_end(argp);
	free(b);
}

void test_name(char *str, ...)
{
	char *b;
	va_list argp;
	va_start(argp, str);
	b = malloc(_vscprintf(str, argp) + 1);
	vsprintf(b, str, argp);
	printf("%-70s", b);
	test_log("  (%s)", b);
	va_end(argp);
	free(b);
}

int test_skip(char *str, ...)
{
	char *b;
	va_list argp;
	va_start(argp, str);
	b = malloc(_vscprintf(str, argp) + 1);
	vsprintf(b, str, argp);
	printf("(skipped) %-60s", b);
	test_log("  (%s)", b);
	va_end(argp);
	free(b);
	return 0;
}
