#include "wire.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

ssize_t wire_pack_7bit(struct iovec *data, struct iovec iovs[], int iov_count, size_t offset)
{
	uint64_t n;
	char *ptr = (char *)data->iov_base + offset;
	for (int i = 0; i < iov_count; i++) {
		/* encode length as bytes with 7 bits + overflow bit */
		for (n = htole64(iovs[i].iov_len); n > 0x7f; n >>= 7)
			memset(ptr++, 0x80 | n, 1);
		memset(ptr++, n, 1);
		memcpy(ptr, iovs[i].iov_base, iovs[i].iov_len);
		ptr += iovs[i].iov_len;
	}
	return data->iov_len;
}

ssize_t wire_pack_pre(struct iovec *data, struct iovec iovs[], int iov_count,
		struct iovec *pre, int pre_count)
{
	size_t offset = 0;
	char *ptr;
	uint64_t n;
	if (!data) {
		errno = EINVAL;
		return -1;
	}
	for (int i = 0; i < pre_count; i++) offset += pre[i].iov_len;
	data->iov_len = offset;
	for (int i = 0; i < iov_count; i++) {
		/* 1 byte for length + data */
		data->iov_len += iovs[i].iov_len + 1;
		for (n = htole64(iovs[i].iov_len); n > 0x7f; n >>= 7)
			data->iov_len++; /* extra length byte */
	}
	ptr = data->iov_base = calloc(1, data->iov_len + 1);
	if (data->iov_base == NULL) {
		errno = ENOMEM;
		return -1;
	}
	for (int i = 0; i < pre_count; i++) {
		memcpy(ptr, pre[i].iov_base, pre[i].iov_len);
		ptr += pre[i].iov_len;
	}
	return wire_pack_7bit(data, iovs, iov_count, offset);
}

ssize_t wire_pack(struct iovec *data, struct iovec iovs[], int iov_count, uint8_t op, uint8_t flags)
{
	struct iovec pre[2] = {0};
	pre[0].iov_base = &op;
	pre[0].iov_len = 1;
	pre[1].iov_base = &flags;
	pre[1].iov_len = 1;
	return wire_pack_pre(data, iovs, iov_count, pre, 2);
}

ssize_t wire_unpack_7bit(struct iovec *data, struct iovec iovs[], int iov_count, size_t offset)
{
	char *ptr = (char *)data->iov_base + offset;
	size_t len;
	char *endptr = (char *)data->iov_base + data->iov_len;
	for (int i = 0; i < iov_count && ptr < endptr; i++) {
		uint64_t n = 0, shift = 0;
		uint8_t b;
		do {
			if (ptr >= endptr) {
				errno = EILSEQ;
				return -1;
			}
			b = ((uint8_t *)ptr++)[0];
			n |= (b & 0x7f) << shift;
			shift += 7;
		} while (b & 0x80);
		len = (size_t)le64toh(n);
		if (ptr + len > endptr) {
			errno = EBADMSG;
			return -1;
		}
		iovs[i].iov_len = len;
		iovs[i].iov_base = ptr;
		ptr += len;
	}
	return data->iov_len;
}

ssize_t wire_unpack_pre(struct iovec *data, struct iovec iovs[], int iov_count,
		struct iovec pre[], int pre_count)
{
	size_t offset = 0;
	for (int i = 0; i < pre_count; i++) {
		memcpy(pre[i].iov_base, (char *)data->iov_base + offset, pre[i].iov_len);
		offset += pre[i].iov_len;
	}
	return wire_unpack_7bit(data, iovs, iov_count, offset);
}

ssize_t wire_unpack(struct iovec *data, struct iovec iovs[], int iov_count,
		uint8_t *op, uint8_t *flags)
{
	struct iovec pre[2] = {0};
	pre[0].iov_len = 1;
	pre[0].iov_base = op;
	pre[1].iov_len = 1;
	pre[1].iov_base = flags;
	return wire_unpack_pre(data, iovs, iov_count, pre, 2);
}
