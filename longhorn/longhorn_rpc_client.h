// SPDX-License-Identifier: GPL-2.0
#ifndef LONGHORN_RPC_CLIENT_H
#define LONGHORN_RPC_CLIENT_H

#include <stdint.h>
#include <pthread.h>

enum {
    CLIENT_CONN_STATE_OPEN = 0,
    CLIENT_CONN_STATE_CLOSE,
};

struct lh_client_conn {
    int seq;
    int fd;
    int state;

    pthread_mutex_t mutex;

    struct message *msg_hashtable;
    struct message *msg_list;
    pthread_mutex_t msg_mutex;


    
    int notify_fd;

    pthread_t response_thread;

    uint8_t *request_header;
    uint8_t *response_header;
    int header_size;

};

extern struct lh_client_conn *lh_client_open_conn(char *socket_path);
extern int lh_client_close_conn(struct lh_client_conn *conn);


#endif
