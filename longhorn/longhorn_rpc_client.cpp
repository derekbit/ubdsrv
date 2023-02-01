#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <syslog.h>
#include <pthread.h>
#include <syslog.h>
#include <stdlib.h>

#include "longhorn_rpc_client.h"
#include "longhorn_rpc_protocol.h"

static uint32_t new_seq(struct lh_client_conn *conn)
{
    return __sync_fetch_and_add(&conn->seq, 1);
}

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

static void *process_response(void *arg)
{
    struct lh_client_conn *conn = (struct lh_client_conn *) arg;
    struct message *res;
    int ret = 0;

    res = (struct message *) calloc(1, sizeof(struct message));
    if (!res) {
        perror("calloc");
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
    if (pthread_create(&conn->response_thread, NULL, &process_response, conn) < 0) {
        perror("pthread creation");
        return -1;
    }
    return 0;
}

void queue_request(struct lh_client_conn *conn, struct message *req)
{
    pthread_mutex_lock(&conn->msg_mutex);

    HASH_ADD_INT(conn->msg_hashtable, seq, req);
    DL_APPEND(conn->msg_list, req);

    pthread_mutex_unlock(&conn->msg_mutex);
}

struct lh_client_conn *lh_client_open_conn(char *socket_path)
{
    struct lh_client_conn *conn;
    struct sockaddr_un addr;
    int fd = -1;
    int error = -1;

    conn = (struct lh_client_conn *) calloc(1, sizeof(struct lh_client_conn));
    if (!conn) {
        return NULL;
    }

    if (pthread_mutex_init(&conn->mutex, NULL) < 0) {
        perror("Pthread mutex initialization");
        errno = EFAULT;
        goto end;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        errno = EFAULT;
        goto end;
    }

    conn->fd = fd;

    conn->msg_hashtable = NULL;
    conn->msg_list = NULL;
    if (pthread_mutex_init(&conn->msg_mutex, NULL) < 0) {
        perror("pthread mutex initialization");
        goto end;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(socket_path) >= 108) {
        errno = EINVAL;
        goto end;
    }

    strncpy(addr.sun_path, socket_path, strlen(socket_path));

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        errno = EFAULT;
        goto end;
    }

    if (start_process(conn)) {
        errno = EFAULT;
        goto end;
    }

    error = 0;
end:
    if (error) {
        if (fd >= 0)
            close(fd);

        pthread_mutex_destroy(&conn->mutex);
        free(conn);
    }

    return conn;
}

void lh_client_close_conn(lh_client_conn *conn)
{
    struct message *req, *tmp;

    if (!conn) {
        return;
    }

    close(conn->fd);

    pthread_mutex_lock(&conn->msg_mutex);
    // Clean up and fail all pending requests
    HASH_ITER(hh, conn->msg_hashtable, req, tmp) {
        HASH_DEL(conn->msg_hashtable, req);
        DL_DELETE(conn->msg_list, req);

        req->type = TypeError;
        fprintf(stderr, "Cancel request %d due to disconnection\n", req->seq);
    }
    pthread_mutex_unlock(&conn->msg_mutex);

    if (pthread_cancel(conn->response_thread) < 0) {
        perror("respond thread cancellation");
    }

    if (pthread_join(conn->response_thread, NULL) < 0) {
        perror("respond thread join");
    }

    free(conn);
}

void lh_client_destroy_request(struct message *msg)
{
    if (!msg) {
        return;
    }

    pthread_cond_destroy(&msg->cond);
    pthread_mutex_destroy(&msg->mutex);

    free(msg);
}

struct message *lh_client_create_request(struct lh_client_conn *conn, void *buf, size_t count, off_t offset, uint32_t type)
{
    struct message *req;
    int rc = 0;

    if (type != TypeRead && type != TypeWrite) {
        fprintf(stderr, "BUG: invalid type for process_request %d\n", type);
        return NULL;
    }

    req = (struct message *) calloc(1, sizeof(struct message));
    if (!req) {
        return NULL;
    }

    req->magic_version = MAGIC_VERSION;
    req->seq = new_seq(conn);
    req->type = type;
    req->offset = offset;
    req->size = count;
    req->data = buf;
	if (req->type == TypeWrite) {
        req->data_length = count;
	}

    rc = pthread_cond_init(&req->cond, NULL);
    if (rc < 0) {
        perror("Pthread cond initialization");
        rc = -EFAULT;
        free(req);
        return NULL;
    }

    rc = pthread_mutex_init(&req->mutex, NULL);
    if (rc < 0) {
        perror("Pthread mutex initialization");
        pthread_cond_destroy(&(req->cond));
        free(req);
        return NULL;
    }

    return req;
}

uint8_t *serialize_request(struct message *msg)
{
    uint8_t *header;
    int pos = 0;

    uint16_t magic_version = htole16(msg->magic_version);
	uint32_t seq = htole32(msg->seq);
	uint32_t type = htole32(msg->type);
	uint64_t offset = htole64(*((uint64_t *)(&msg->offset)));
	uint32_t size = htole32(msg->size);
	uint32_t data_length = htole32(msg->data_length);

    header = (uint8_t *) malloc(sizeof(uint8_t) * MESSAGE_HEADER_SIZE);
    if (!header) {
        return NULL;
    }

    memcpy(header, &magic_version, sizeof(magic_version));
    pos += sizeof(magic_version);

    memcpy(header + pos, &seq, sizeof(seq));
    pos += sizeof(seq);

    memcpy(header + pos, &type, sizeof(type));
    pos += sizeof(type);

    memcpy(header + pos, &offset, sizeof(offset));
    pos += sizeof(offset);

    memcpy(header + pos, &size, sizeof(size));
    pos += sizeof(size);

    memcpy(header + pos, &data_length, sizeof(data_length));
    pos += sizeof(data_length);

    return header;
}