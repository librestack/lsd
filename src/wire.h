/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (c) 2020 Brett Sheffield <bacs@librecast.net> */

#ifndef _LSDM_WIRE_H
#define _LSDM_WIRE_H 1

#include <errno.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

ssize_t wire_pack(struct iovec *data, const struct iovec iovs[], int iov_count,
		uint8_t op, uint8_t flags);
ssize_t wire_pack_7bit(struct iovec *data, const struct iovec iovs[], int iov_count, size_t offset);
ssize_t wire_pack_pre(struct iovec *data, const struct iovec iovs[], int iov_count,
		const struct iovec pre[], int pre_count);
ssize_t wire_unpack(const struct iovec *data, struct iovec iovs[], int iov_count,
		uint8_t *op, uint8_t *flags);
ssize_t wire_unpack_7bit(const struct iovec *data, struct iovec iovs[], int iov_count, size_t offset);
ssize_t wire_unpack_pre(const struct iovec *data, struct iovec iovs[], int iov_count,
		struct iovec pre[], int pre_count);

#endif /* _LSDM_WIRE_H */
