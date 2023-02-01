#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <endian.h>
#include <stdlib.h>
#include <syslog.h>

#include "longhorn_rpc_protocol.h"

static ssize_t read_full(int fd, void *buf, ssize_t len)
{
    ssize_t nread = 0;
    ssize_t ret;

    while (nread < len) {
        ret = read(fd, buf + nread, len - nread);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            return ret;
        } else if (ret == 0) {
            return nread;
        }
        nread += ret;
    }

    return nread;
}

static ssize_t write_full(int fd, void *buf, ssize_t len)
{
    ssize_t nwrote = 0;
    ssize_t ret;

    while (nwrote < len) {
        ret = write(fd, buf + nwrote, len - nwrote);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            return ret;
        }
        nwrote += ret;
    }

    return nwrote;
}

int send_msg(int fd, struct message *msg)
{
    ssize_t n = 0;
	uint16_t magic_version = htole16(MAGIC_VERSION);
	uint32_t seq = htole32(msg->seq);
	uint32_t type = htole32(msg->type);
	uint64_t offset = htole64(*((uint64_t *)(&msg->offset)));
	uint32_t size = htole32(msg->size);
	uint32_t data_length = htole32(msg->data_length);

    msg->magic_version = MAGIC_VERSION;

    n = write_full(fd, &magic_version, sizeof(magic_version));
    if (n != sizeof(magic_version)) {
        syslog(LOG_ERR, "Failed to write magic version\n");
        errno = EINVAL;
        return -1;
    }

    n = write_full(fd, &seq, sizeof(seq));
    if (n != sizeof(seq)) {
        syslog(LOG_ERR, "Failed to write seq\n");
        errno = EINVAL;
        return -1;
    }

    n = write_full(fd, &type, sizeof(type));
    if (n != sizeof(type)) {
        syslog(LOG_ERR, "Failed to write type\n");
        errno = EINVAL;
        return -1;
    }

    n = write_full(fd, &offset, sizeof(offset));
    if (n != sizeof(offset)) {
        syslog(LOG_ERR, "Failed to write offset\n");
        errno = EINVAL;
        return -1;
    }

    n = write_full(fd, &size, sizeof(size));
    if (n != sizeof(size)) {
        syslog(LOG_ERR, "Failed to write size\n");
        errno = EINVAL;
        return -1;
    }

    n = write_full(fd, &data_length, sizeof(data_length));
    if (n != sizeof(data_length)) {
        syslog(LOG_ERR, "Failed to write data length\n");
        errno = EINVAL;
        return -1;
    }

	if (msg->data_length != 0) {
		n = write_full(fd, msg->data, msg->data_length);
		if (n != msg->data_length) {
            if (n < 0)
                syslog(LOG_ERR, "Failed to write data\n");

            syslog(LOG_ERR, "Failed to write data, wrote %zd; expected %u\n", n, msg->data_length);
            errno = EINVAL;
            return -1;
		}
	}

    return 0;
}

int receive_msg(int fd, struct message *msg)
{
    ssize_t n;
    uint64_t offset;

    bzero(msg, sizeof(struct message));

    // There is only one thread reading the response, and socket is
    // full-duplex, so no need to lock
	n = read_full(fd, &msg->magic_version, sizeof(msg->magic_version));
    if (n != sizeof(msg->magic_version)) {
        syslog(LOG_ERR, "Failed to read magic version\n");
        return -1;
    }

	msg->magic_version = le16toh(msg->magic_version);
    if (msg->magic_version != MAGIC_VERSION) {
        syslog(LOG_ERR, "Wrong magic version 0x%x, expected 0x%x\n", msg->magic_version, MAGIC_VERSION);
        return -1;
    }

	n = read_full(fd, &msg->seq, sizeof(msg->seq));
    if (n != sizeof(msg->seq)) {
        syslog(LOG_ERR, "Failed to read seq\n");
        return -1;
    }
	msg->seq = le32toh(msg->seq);

    n = read_full(fd, &msg->type, sizeof(msg->type));
    if (n != sizeof(msg->type)) {
        syslog(LOG_ERR, "Failed to read type\n");
        return -1;
    }
	msg->type = le32toh(msg->type);

    n = read_full(fd, &offset, sizeof(offset));
    if (n != sizeof(offset)) {
        syslog(LOG_ERR, "Failed to read offset\n");
        return -1;
    }
	offset = le64toh(offset);
	msg->offset = *( (int64_t *) &offset);

    n = read_full(fd, &msg->size, sizeof(msg->size));
    if (n != sizeof(msg->size)) {
        syslog(LOG_ERR, "Failed to read magic size\n");
        return -1;
    }
	msg->size = le32toh(msg->size);

    n = read_full(fd, &msg->data_length, sizeof(msg->data_length));
    if (n != sizeof(msg->data_length)) {
        syslog(LOG_ERR, "Failed to read data length\n");
        return -1;
    }
	msg->data_length = le32toh(msg->data_length);

	if (msg->data_length > 0) {
		msg->data = malloc(msg->data_length);
        if (!msg->data) {
            syslog(LOG_ERR, "Cannot allocate memory for data: %s\n", strerror(errno));
            return -1;
        }

		n = read_full(fd, msg->data, msg->data_length);
		if (n != msg->data_length) {
            syslog(LOG_ERR, "Cannot read full from fd, %u vs %zd\n", msg->data_length, n);
			free(msg->data);
            return -1;
		}
	}

	return 0;
}
