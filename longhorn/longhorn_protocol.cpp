// SPDX-License-Identifier: GPL-2.0
#include <sys/un.h>

#include "ublksrv.h"
#include "ublksrv_tgt.h"
#include "longhorn_protocol.h"
#include "longhorn_common.h"

int openunix(const char *path)
{
    int sock;
    struct sockaddr_un un_addr;

    memset(&un_addr, 0, sizeof(un_addr));

    un_addr.sun_family = AF_UNIX;

    if (strnlen(path, sizeof(un_addr.sun_path)) == sizeof(un_addr.sun_path)) {
        longhorn_err("unix socket path is too long\n");
        return -1;
    }

    strncpy(un_addr.sun_path, path, sizeof(un_addr.sun_path) - 1);

    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        longhorn_err("socket failed: %s\n", strerror(errno));
        return -1;
    };

    if (connect(sock, (struct sockaddr *) &un_addr, sizeof(un_addr)) == -1) {
        longhorn_err("connect failed: %s\n", strerror(errno));
        close(sock);
        return -1;
    }

    return sock;
}
