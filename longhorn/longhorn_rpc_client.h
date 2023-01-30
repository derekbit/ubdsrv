// SPDX-License-Identifier: GPL-2.0
#ifndef LONGHORN_RPC_CLIENT_H
#define LONGHORN_RPC_CLIENT_H

struct lh_client_conn {
    int seq;
    int fd;
    /*
    int notify_fd;
    int timeout_fd;
    int state;
    pthread_mutex_t mutex;

    pthread_t response_thread;
    pthread_t timeout_thread;

    struct Message *msg_hashtable;
    struct Message *msg_list;
    pthread_mutex_t msg_mutex;

    uint8_t *request_header;
    uint8_t *response_header;
    int header_size;
    */
};

extern int lh_client_open_conn(char *socket_path);


#endif
