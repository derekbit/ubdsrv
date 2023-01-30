#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "longhorn_rpc_client.h"
#include "longhorn_rpc_protocol.h"
#include "uthash.h"
#include "utlist.h"

static int receive_response(struct lh_client_conn *conn, struct message *res)
{
    return receive_msg(conn->fd, res);
}

static struct message *find_and_remove_request_from_queue(struct lh_client_conn *conn, int seq)
{
    struct message *req = NULL;

    pthread_mutex_lock(&conn->msg_mutex);

    HASH_FIND_INT(conn->msg_hashtable, &seq, req);
    if (req) {
        HASH_DEL(conn->msg_hashtable, req);
        DL_DELETE(conn->msg_list, req);
    }
    pthread_mutex_unlock(&conn->msg_mutex);

    return req;
}

static void *response_process(void *arg)
{
    struct lh_client_conn *conn = (struct lh_client_conn *) arg;
    struct message *res;
    int ret = 0;

    res = (struct message *) calloc(1, sizeof(struct message));
    if (!res) {
        perror("malloc");
        return NULL;
    }

    while (1) {
        struct message *req;

        if (receive_response(conn, res)) {
            break;
        }

        if (res->type == TypeClose) {
            fprintf(stderr, "Receive close message, about to end the connection\n");
            break;
        }

        switch (res->type) {
        case TypeRead:
        case TypeWrite:
            fprintf(stderr, "Wrong type for response %d of seq %d\n", res->type, res->seq);
            continue;
        case TypeError:
            fprintf(stderr, "Receive error for response %d of seq %d\n", res->type, res->seq);
            /* fall through so we can response to caller */
        case TypeEOF:
        case TypeResponse:
            break;
        default:
            fprintf(stderr, "Unknown message type %d\n", res->type);
        }

        req = find_and_remove_request_from_queue(conn, res->seq);
        if (!req) {
            fprintf(stderr, "Unknown response sequence %d\n", res->seq);
            free(res->data);
            continue;
        }

        pthread_mutex_lock(&req->mutex);

        if (res->type == TypeResponse || res->type == TypeEOF) {
			req->size = res->size;
			req->data_length = res->data_length;
			if (res->data_length != 0) {
                memcpy(req->data, res->data, res->data_length);
			}
        } else if (res->type == TypeError) {
            req->type = TypeError;
        }

        free(res->data);

        pthread_mutex_unlock(&req->mutex);

        pthread_cond_signal(&req->cond);
    }

    free(res);

    if (ret != 0) {
        fprintf(stderr, "Receive response returned error\n");
    }

    lh_client_close_conn(conn);
    return NULL;
}

static int start_process(struct lh_client_conn *conn) 
{
    if (pthread_create(&conn->response_thread, NULL, &response_process, conn) < 0) {
        perror("pthread creation");
        return -1;
    }
    return 0;
}

struct lh_client_conn *lh_client_open_conn(char *socket_path)
{
    struct lh_client_conn *conn = NULL;
    struct sockaddr_un addr;
    int fd = -1;
    int ret = 0;
    int connected = 0;
    int error = -1;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        goto end;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(socket_path) >= 108) {
        fprintf(stderr, "socket path is too long, more than 108 characters\n");
        errno = EINVAL;
        goto end;
    }

    strncpy(addr.sun_path, socket_path, strlen(socket_path));

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr))) {
        perror("connect");
        goto end;
    }

    conn = (struct lh_client_conn *) calloc(1, sizeof(struct lh_client_conn));
    if (!conn) {
        perror("calloc");
        goto end;
    }

    conn->fd = fd;
    conn->seq = 0;

    conn->msg_hashtable = NULL;
    conn->msg_list = NULL;

    ret = pthread_mutex_init(&conn->mutex, NULL);
    if (ret < 0) {
        perror("pthread mutex initilization");
        goto end;
    }

     ret = pthread_mutex_init(&conn->msg_mutex, NULL);
     if (ret < 0) {
        perror("pthread mutex initilization");
        goto end;
     }

    conn->state = CLIENT_CONN_STATE_OPEN;

    if (start_process(conn)) {
        goto end;
    }

    error = 0;
end:
    if (error) {
        if (fd != -1) {
            close(fd);
        }

        free(conn);
        return NULL;
    }
    return conn;
}

int lh_client_close_conn(struct lh_client_conn *conn)
{
    struct message *req, *tmp;

    if (!conn) {
        return 0;
    }

    pthread_mutex_lock(&conn->mutex);
    if (conn->state == CLIENT_CONN_STATE_CLOSE) {
        pthread_mutex_unlock(&conn->mutex);
        return 0;
    }

    conn->state = CLIENT_CONN_STATE_CLOSE;
    close(conn->fd);

    pthread_mutex_unlock(&conn->mutex);
    pthread_mutex_lock(&conn->msg_mutex);

    // Clean up and fail all pending requests
    HASH_ITER(hh, conn->msg_hashtable, req, tmp) {
        HASH_DEL(conn->msg_hashtable, req);
        DL_DELETE(conn->msg_list, req);

        pthread_mutex_lock(&req->mutex);
        req->type = TypeError;
        fprintf(stderr, "Cancel request %d due to disconnection\n", req->seq);
        pthread_mutex_unlock(&req->mutex);
        pthread_cond_signal(&req->cond);
    }

    pthread_mutex_unlock(&conn->msg_mutex);

    if (pthread_cancel(conn->response_thread) < 0) {
        perror("respond thread cancellation");
    }

    if (pthread_join(conn->response_thread, NULL) < 0) {
        perror("respond thread join");
    }

    return 0;
}