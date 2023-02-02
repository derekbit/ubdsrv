#include <sys/socket.h>
#include <sys/un.h>
#include <stdint.h>

#include "ublksrv_tgt.h"
#include "longhorn_rpc_client.h"
#include "longhorn_rpc_protocol.h"

static inline struct lh_client_conn *dev_to_conn(const struct ublksrv_dev *dev)
{
	return (lh_client_conn *) dev->tgt.tgt_data;
}

static inline struct lh_client_conn *queue_to_conn(const struct ublksrv_queue *q)
{
	return (struct lh_client_conn *) q->private_data;
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
	struct lh_client_conn *conn = NULL;
	uint64_t size = 0;
	struct ublksrv_tgt_base_json tgt_json;
	struct ublk_params p;

	strcpy(tgt_json.name, "longhorn");

	if (type != UBLKSRV_TGT_TYPE_LONGHORN)
		return -1;

	while ((opt = getopt_long(argc, argv, "-:f:s:", lo_longopts, NULL)) != -1) {
		switch (opt) {
		case 'f':
			sock_path = strdup(optarg);
			break;
		case 's':
			size = uint64_t(atol(optarg));
			break;
		}
	}

	conn = lh_client_open_conn(sock_path);
	if (!conn) {
		syslog(LOG_ERR, "failed to open %s: %s\n", sock_path, strerror(errno));
		return -1;
	}

	syslog(LOG_INFO, "Established unix domain socket connection to %s\n", sock_path);

	p = (struct ublk_params) {
		.types = UBLK_PARAM_TYPE_BASIC,
		.basic = {
			//.attrs = 
			.logical_bs_shift = 9,
			.physical_bs_shift = 12,
			.io_opt_shift = 12,
			.io_min_shift = 9,
			.max_sectors = info->max_io_buf_bytes >> 9,
            //.chunk_sectors =
            .dev_sectors = size >> 9,
            //.virt_boundary_mask =
		},
	};

	tgt_json = (struct ublksrv_tgt_base_json) {
		//.name
		.type = type,
		.dev_size = size,
	};

	ublksrv_tgt_set_io_data_size(tgt);

	tgt->dev_size = size;
	tgt->tgt_ring_depth = info->queue_depth;
	tgt->nr_fds = 1;
	tgt->fds[1] = conn->fd;
	tgt->tgt_data = conn;
	//tgt->iowq_max_workers = 

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
	struct lh_client_conn *conn = dev_to_conn(dev);

	lh_client_close_conn(conn);
}

static int write_request(const struct ublksrv_queue *q, uint8_t *serialized_req)
{
	return write_full(q->dev->tgt.fds[1], serialized_req, MESSAGE_HEADER_SIZE);
}

static int write_request_data(const struct ublksrv_queue *q, const struct ublk_io_data *data)
{
	const struct ublksrv_io_desc *iod = data->iod;

	return write_full(q->dev->tgt.fds[1], (void *) iod->addr, iod->nr_sectors << 9);
}

static uint32_t io_type_from_ublk_op(unsigned ublk_op)
{
	switch (ublk_op) {
	case UBLK_IO_OP_READ:
		return TypeRead;
	case UBLK_IO_OP_WRITE:
		return TypeWrite;
	}
	return 0;
}

static int __longhorn_handle_io_async(const struct ublksrv_queue *q, const struct ublk_io_data *data, int tag)
{
	struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);
	const struct ublksrv_io_desc *iod = data->iod;
	unsigned ublk_op = ublksrv_get_op(iod);
	struct lh_client_conn *conn = queue_to_conn(q);
	uint8_t *serialized_req = NULL;
	struct message *req;
	int ret;

	req = lh_client_create_request(conn,
		(void *) iod->addr,
		uint32_t(iod->nr_sectors << 9), // size
		iod->start_sector << 9, // offset
		io_type_from_ublk_op(ublk_op));

	serialized_req = serialize_request(req);

	queue_request(conn, req);

	pthread_mutex_lock(&req->mutex);

	pthread_mutex_lock(&conn->mutex);
	ret = write_request(q, serialized_req);
	if (ret < 0) {
		goto error_out;
	}
	if (ublk_op == UBLK_IO_OP_WRITE) {
		ret = write_request_data(q, data);
		if (ret < 0) {
			goto error_out;
		}
	}
	pthread_mutex_unlock(&conn->mutex);

	pthread_cond_wait(&req->cond, &req->mutex);
	pthread_mutex_unlock(&req->mutex);

	ublksrv_complete_io(q, tag, data->iod->nr_sectors << 9);

	free(serialized_req);
	lh_client_destroy_request(req);

	return 0;
error_out:
	pthread_mutex_unlock(&conn->mutex);
	pthread_mutex_unlock(&req->mutex);

	free(serialized_req);
	lh_client_destroy_request(req);
	return -1;
}

static int longhorn_handle_io_async(const struct ublksrv_queue *q, const struct ublk_io_data *data)
{
	struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);

	__longhorn_handle_io_async(q, data, data->tag);

	return 0;
}

static int longhorn_init_queue(const struct ublksrv_queue *q, void **queue_data_ptr)
{
	struct lh_client_conn *conn = dev_to_conn(q->dev);

	*queue_data_ptr = (void *) conn;

	return 0;
}

struct ublksrv_tgt_type longhorn_tgt_type = {
	.handle_io_async = longhorn_handle_io_async,

	.init_tgt = longhorn_init_tgt,
	.deinit_tgt = longhorn_deinit_tgt,

	.type = UBLKSRV_TGT_TYPE_LONGHORN,
	.name = "longhorn",

	.init_queue = longhorn_init_queue,
};

static void tgt_longhorn_init() __attribute__((constructor));

static void tgt_longhorn_init(void)
{
	ublksrv_register_tgt_type(&longhorn_tgt_type);
}