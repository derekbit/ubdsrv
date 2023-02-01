// SPDX-License-Identifier: GPL-2.0
#ifndef LONGHORN_RPC_PROTOCOL_H
#define LONGHORN_RPC_PROTOCOL_H

#include "uthash.h"
#include "utlist.h"

#define MAGIC_VERSION 0x1b01 // LongHorn01
#define MESSAGE_HEADER_SIZE 26

struct message {
    uint16_t    magic_version;
    uint32_t    seq;
    uint32_t    type;
    int64_t     offset;
    uint32_t    size;
    uint32_t    data_length;
    void*       data;

    pthread_cond_t  cond;
    pthread_mutex_t mutex;

    UT_hash_handle  hh;

    struct message *next, *prev;
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

int send_msg(int fd, struct message *msg);
int receive_msg(int fd, struct message *msg);

#endif
