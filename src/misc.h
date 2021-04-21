/* SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#ifndef _LIBRESTACK_MISC_H__
#define _LIBRESTACK_MISC_H__ 1

/* return size of buffer to allocate for vsnprintf() */
int _vscprintf (const char * format, va_list argp);

#endif /* _LIBRESTACK_MISC_H__ */
