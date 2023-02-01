// SPDX-License-Identifier: GPL-2.0
#ifndef LONGHORN_RPC_CLIENT_H
#define LONGHORN_RPC_CLIENT_H

#include <stdint.h>

struct lh_client_conn {
    int seq;
    int fd;

    pthread_t response_thread;
    pthread_mutex_t mutex;

    struct message *msg_hashtable;
    struct message *msg_list;
    pthread_mutex_t msg_mutex;
};

struct lh_client_conn *lh_client_open_conn(char *socket_path);
void lh_client_close_conn(lh_client_conn *conn);

struct message *lh_client_create_request(struct lh_client_conn *conn, void *buf, size_t count, off_t offset, uint32_t type);
void lh_client_destroy_request(struct message *msg);

uint8_t *serialize_request(struct message *msg);
void queue_request(struct lh_client_conn *conn, struct message *req);

#endif
