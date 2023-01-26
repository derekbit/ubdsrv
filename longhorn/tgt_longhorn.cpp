#include <sys/socket.h>
#include <sys/un.h>

#include "ublksrv_tgt.h"

struct lh_client_conn {
    int fd;
};

struct lh_client_conn *lh_client_allocate_conn() {
    return (lh_client_conn *) calloc(1, sizeof(struct lh_client_conn));
}

struct lh_client_conn *lh_client_open_conn(char *socket_path) {
    struct lh_client_conn *conn = NULL;
    struct sockaddr_un addr;
    int fd, rc = 0;
    int i, connected = 0;

    conn = lh_client_allocate_conn();
    if (!conn) {
        errno = EINVAL;
        return NULL;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        errno = EFAULT;
        return NULL;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(socket_path) >= 108) {
        errno = EINVAL;
        return NULL;
    }

    strncpy(addr.sun_path, socket_path, strlen(socket_path));

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        errno = EFAULT;
        return NULL;
    }

    conn->fd = fd;

    return conn;
}

static int longhorn_init_tgt(struct ublksrv_dev *dev, int type, int argc, char *argv[])
{
    struct ublksrv_tgt_info *tgt = &dev->tgt;
    const struct ublksrv_ctrl_dev_info *info = ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
    static const struct option lo_longopts[] = {
        { "sock-path", 1, NULL, 'f' },
        { "size", 1, NULL, 's' },
        { NULL }
    };
    int jbuf_size;
    int ret;
    char *jbuf;
    int opt;
    char *sock_path = NULL;
    int64_t size = 0;
    struct ublksrv_tgt_base_json tgt_json = {
		.type = type,
	};
	struct ublk_params p = {
		.types = UBLK_PARAM_TYPE_BASIC,
		.basic = {
			.logical_bs_shift = 9,
			.physical_bs_shift = 12,
			.io_opt_shift = 12,
			.io_min_shift = 9,
			.max_sectors = info->max_io_buf_bytes >> 9,
		},
	};

    strcpy(tgt_json.name, "longhorn");

    if (type != UBLKSRV_TGT_TYPE_LONGHORN)
        return -1;

    while ((opt = getopt_long(argc, argv, "-:f:s:", lo_longopts, NULL)) != -1) {
		switch (opt) {
		case 'f':
			sock_path = strdup(optarg);
			break;
        case 's':
            size = atol(optarg);
            break;
		}
	}

    ublksrv_tgt_set_io_data_size(tgt);
    tgt_json.dev_size = tgt->dev_size = size;
    tgt->tgt_ring_depth = info->queue_depth;
    syslog(LOG_INFO, "Debug ====> info->queue_depth=%d\n", info->queue_depth);

    jbuf = ublksrv_tgt_realloc_json_buf(dev, &jbuf_size);
    ublksrv_json_write_dev_info(ublksrv_get_ctrl_dev(dev), jbuf, jbuf_size);
    ublksrv_json_write_target_base_info(jbuf, jbuf_size, &tgt_json);

    do {
		ret = ublksrv_json_write_target_str_info(jbuf, jbuf_size,
				"sock_path", sock_path);
		if (ret < 0)
			jbuf = ublksrv_tgt_realloc_json_buf(dev, &jbuf_size);
   } while (ret < 0);
    do {
		ret = ublksrv_json_write_target_long_info(jbuf, jbuf_size,
				"size", (long)size);
		if (ret < 0)
			jbuf = ublksrv_tgt_realloc_json_buf(dev, &jbuf_size);
   } while (ret < 0);

	do {
		ret = ublksrv_json_write_params(&p, jbuf, jbuf_size);
		if (ret < 0)
			jbuf = ublksrv_tgt_realloc_json_buf(dev, &jbuf_size);
	} while (ret < 0);

    return 0;
}

static void longhorn_deinit_tgt(const struct ublksrv_dev *dev)
{

}

static int longhorn_handle_io_async(const struct ublksrv_queue *q, const struct ublk_io_data *data)
{
    int ret;
	struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);
	return 0;
}

struct ublksrv_tgt_type longhorn_tgt_type = {
    .handle_io_async = longhorn_handle_io_async,
    .init_tgt = longhorn_init_tgt,
    .deinit_tgt = longhorn_deinit_tgt,

    .type = UBLKSRV_TGT_TYPE_LONGHORN,
    .name = "longhorn",
};

static void tgt_longhorn_init() __attribute__((constructor));

static void tgt_longhorn_init(void)
{
    ublksrv_register_tgt_type(&longhorn_tgt_type);
}