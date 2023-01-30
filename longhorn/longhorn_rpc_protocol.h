// SPDX-License-Identifier: GPL-2.0
#ifndef LONGHORN_RPC_PROTOCOL_H
#define LONGHORN_RPC_PROTOCOL_H

#define MAGIC_VERSION 0x1b01 // LongHorn01

struct message_header {
    uint16_t    magic_version;
    uint32_t    seq;
    uint32_t    type;
    uint64_t    offset;
    uint32_t    size;
    uint32_t    data_length;
} __attribute__((packed));

struct message {
    uint16_t    magic_version;
    uint32_t    seq;
    uint32_t    type;
    int64_t     offset;
    uint32_t    size;
    uint32_t    data_length;
    void*       data;
};

enum {
	TypeRead,
	TypeWrite,
	TypeResponse,
	TypeError,
	TypeEOF,
	TypeClose,
	TypePing,
	TypeUnmap
};


#endif
