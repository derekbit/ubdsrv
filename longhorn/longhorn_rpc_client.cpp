#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#include "longhorn_rpc_client.h"

int lh_client_open_conn(char *socket_path) {
    struct sockaddr_un addr;
    int fd;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        errno = EFAULT;
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(socket_path) >= 108) {
        errno = EINVAL;
        return -1;
    }

    strncpy(addr.sun_path, socket_path, strlen(socket_path));

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        errno = EFAULT;
        return -1;
    }

    return fd;
}
