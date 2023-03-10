#include <sys/socket.h>
#include <sys/un.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <coroutine>

#include "ublksrv_tgt_endian.h"
#include "ublksrv_tgt.h"

#include "tgt_longhorn.h"
#include "longhorn_protocol.h"

static inline struct longhorn_queue_data *longhorn_get_queue_data(const struct ublksrv_queue *q)
{
    return (struct longhorn_queue_data *)q->private_data;
}

static inline struct longhorn_io_data *io_tgt_to_longhorn_data(const struct ublk_io_tgt *io)
{
    return (struct longhorn_io_data *)(io + 1);
}

static inline bool is_recv_io(const struct ublksrv_queue *q, const struct ublk_io_data *data)
{
    return data->tag >= q->q_depth;
}

static int req_to_longhorn_cmd_type(const struct ublksrv_io_desc *iod)
{
    switch (ublksrv_get_op(iod)) {
    case UBLK_IO_OP_READ:
        return LONGHORN_CMD_TYPE_READ;
    case UBLK_IO_OP_WRITE:
        return LONGHORN_CMD_TYPE_WRITE;
    //case UBLK_IO_OP_FLUSH:
    //    return LONGHORN_CMD_TYPE_FLUSH;    
    //case UBLK_IO_OP_DISCARD:
    //    return LONGHORN_CMD_TYPE_UNMAP;
    //case UBLK_IO_OP_WRITE_SAME:
    //    return LONGHORN_CMD_TYPE_WRITE_SAME;
    //case UBLK_IO_OP_WRITE_ZEROES:
    //    return LONGHORN_CMD_TYPE_WRITE_ZEROS;
    default:
        return -1;
    }
}

static unsigned req_to_longhorn_op(const struct ublksrv_io_desc *iod)
{
    int type = req_to_longhorn_cmd_type(iod);

    if (type < 0) {
        return 0;
    }

    return (1 << type);
}

static inline void __longhorn_build_req(const struct ublksrv_queue *q,
                                        const struct ublk_io_data *data,
                                        const struct longhorn_io_data *longhorn_data,
                                        uint32_t type,
                                        struct message *req)
{
    req->magic = htole16(LONGHORN_MESSAGE_MAGIC);
    req->seq = htole32(longhorn_data->seq);
    req->type = htole32(type);
    req->offset = cpu_to_le64((uint64_t)data->iod->start_sector << 9);
    req->size = htole32(data->iod->nr_sectors << 9);
    if (type == LONGHORN_CMD_TYPE_WRITE) {
        req->data_length = htole32(data->iod->nr_sectors << 9);
    } else {
        req->data_length = htole32(0);
    }
}

static int longhorn_queue_req(const struct ublksrv_queue *q,
                              const struct ublk_io_data *data,
                              const struct message *req,
                              const struct msghdr *msg)
{
    struct longhorn_queue_data *q_data = longhorn_get_queue_data(q);
    const struct ublksrv_io_desc *iod = data->iod;
    struct io_uring_sqe *sqe = io_uring_get_sqe(q->ring_ptr);
    unsigned ublk_op = ublksrv_get_op(iod);
    unsigned longhorn_op = req_to_longhorn_op(data->iod);
    unsigned msg_flags = MSG_NOSIGNAL;

    if (!sqe) {
        longhorn_err("%s: get sqe failed, tag %d op %d\n",
            __func__, data->tag, ublk_op);
        return -ENOMEM;
    }

    if (longhorn_op == 0) {
        return -EINVAL;
    }

    msg_flags |= MSG_WAITALL;

    if (ublk_op == UBLK_IO_OP_WRITE) {
        io_uring_prep_sendmsg(sqe, q->q_id + 1, msg, msg_flags);
    } else {
        io_uring_prep_send(sqe, q->q_id + 1, req, sizeof(*req), msg_flags);
    }

    sqe->user_data = build_user_data(data->tag, longhorn_op,
        longhorn_op == LONGHORN_OP_WRITE ? data->iod->nr_sectors : 0, 1);

    io_uring_sqe_set_flags(sqe, /*IOSQE_CQE_SKIP_SUCCESS |*/
        IOSQE_FIXED_FILE | IOSQE_IO_LINK);

    q_data->last_send_sqe = sqe;
    q_data->chained_send_ios += 1;


    longhorn_info("%s: queue io op %d(%llu %x %llx) ios(%u %u)"
        " (qid %d tag %u, cmd_op %u target: %d, user_data %llx)\n",
        __func__, ublk_op, data->iod->start_sector,
        data->iod->nr_sectors, sqe->addr,
        q_data->in_flight_ios, q_data->chained_send_ios,
        q->q_id, data->tag, ublk_op, 1, sqe->user_data);

    return 1;
}

int longhorn_setup_tgt(struct ublksrv_dev *dev, char *sock_path, unsigned long long dev_size)
{
    struct ublksrv_tgt_info *tgt = &dev->tgt;
    const struct ublksrv_ctrl_dev_info *info = ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
    int fd;

    longhorn_info("Establishing unix domain socket connection to %s\n", sock_path);

    fd = openunix(sock_path);
    if (fd < 0) {
        longhorn_err("Failed to establish unix domain socket connection to %s: %s", sock_path, strerror(errno));
        return -1;
    }

    tgt->fds[1] = fd;
    tgt->nr_fds = 1;

    tgt->dev_size = dev_size;

    tgt->tgt_ring_depth = info->queue_depth + 1;
    tgt->extra_ios = 1; // One extra slot for receiving engine reply
    tgt->io_data_size = sizeof(struct ublk_io_tgt) + sizeof(struct longhorn_io_data);

    ublksrv_dev_set_cq_depth(dev, 2 * tgt->tgt_ring_depth);

    return 0;
}

static int longhorn_init_tgt(struct ublksrv_dev *dev, int type, int argc, char *argv[])
{
    struct ublksrv_tgt_info *tgt = &dev->tgt;
    const struct ublksrv_ctrl_dev_info *info = ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
    struct ublksrv_tgt_base_json tgt_json;
    struct ublk_params params;

    char *jbuf;
    int jbuf_size;
    int ret;
    int opt;
    char *sock_path = NULL;
    uint64_t size = 0;

    static const struct option lo_longopts[] = {
        { "sock-path", 1, NULL, 'f' },
        { "size", 1, NULL, 's' },
        { NULL }
    };

    longhorn_info("Initializing Longhorn target\n");

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

    if (longhorn_setup_tgt(dev, sock_path, size) < 0) {
        longhorn_err("Failed to establish connection to %s: %s\n", sock_path, strerror(errno));
        return EXIT_FAILURE;
    }

    params = (struct ublk_params) {
        .types = UBLK_PARAM_TYPE_BASIC,
        .basic = {
            .attrs = 0U,
            .logical_bs_shift = 9,
            .physical_bs_shift = 12,
            .io_opt_shift = 12,
            .io_min_shift = 9,
            .max_sectors = info->max_io_buf_bytes >> 9,
            .dev_sectors = tgt->dev_size >> 9,
        },
    };

    tgt_json = (struct ublksrv_tgt_base_json) {
        .name = "longhorn",
        .type = type,
        .dev_size = size,
    };

    jbuf = ublksrv_tgt_realloc_json_buf(dev, &jbuf_size);
    if (!jbuf) {
        longhorn_err("Failed to realloc json buf: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    ublksrv_json_write_dev_info(ublksrv_get_ctrl_dev(dev), jbuf, jbuf_size);
    LONGHORN_WRITE_TGT_STR(dev, jbuf, jbuf_size, "sock_path", sock_path);

    ublksrv_json_write_target_base_info(jbuf, jbuf_size, &tgt_json);

    do {
        ret = ublksrv_json_write_params(&params, jbuf, jbuf_size);
        if (ret < 0)
            jbuf = ublksrv_tgt_realloc_json_buf(dev, &jbuf_size);
    } while (ret < 0);

    return 0;
}

static void longhorn_deinit_tgt(const struct ublksrv_dev *dev)
{
    const ublksrv_tgt_info *tgt = &dev->tgt;
    const struct ublksrv_ctrl_dev_info *info = ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
    int fd = tgt->fds[1];

    longhorn_info("Deinitializing Longhorn target\n");

    shutdown(fd, SHUT_RDWR);
    close(fd);
}

static int longhorn_init_queue(const struct ublksrv_queue *q, void **queue_data_ptr)
{
    struct longhorn_queue_data *data;

    longhorn_info("Initializing queue for longhorn target\n");

    data = (struct longhorn_queue_data *)calloc(sizeof(struct longhorn_queue_data), 1);
    if (!data) {
        longhorn_err("Failed to initialize queue for longhorn target: %s\n", strerror(errno));
        return -errno;
    }

    data->next_chain.clear();
    data->recv_started = 0;

    *queue_data_ptr = (void *)data;

    return 0;
}

static void longhorn_deinit_queue(const struct ublksrv_queue *q)
{
    struct longhorn_queue_data *data;

    longhorn_info("Deinitializing queue for Longhorn target\n");

    data = longhorn_get_queue_data(q);
    free(data);
}

static void longhorn_usage_for_add(void)
{
    printf("TODO\n");
}

static co_io_job __longhorn_handle_io_async(const struct ublksrv_queue *q, const struct ublk_io_data *data, struct ublk_io_tgt *io)
{
    int ret = -EIO;
    struct message req;
    struct longhorn_queue_data *q_data = longhorn_get_queue_data(q);
    struct longhorn_io_data *longhorn_data = io_tgt_to_longhorn_data(io);
    int type = req_to_longhorn_cmd_type(data->iod);
    struct iovec iov[2] = {
        [0] = {
            .iov_base = (void *)&req,
            .iov_len = sizeof(req),
        },
        [1] = {
            .iov_base = (void *)data->iod->addr,
            .iov_len = data->iod->nr_sectors << 9,
        },
    };
    struct msghdr msg = {
        .msg_iov = iov,
        .msg_iovlen = 2,
    };

    if (type == -1) {
        longhorn_err("Unsupported longhorn command type %d\n", type);
        goto fail;
    }

    longhorn_data->seq = data->tag;
    __longhorn_build_req(q, data, longhorn_data, type, &req);
    q_data->in_flight_ios += 1;

    longhorn_data->done = 0;
again:
    ret = longhorn_queue_req(q, data, &req, &msg);
    if (ret < 0)
        goto fail;

    co_await__suspend_always(data->tag);
    if (io->tgt_io_cqe->res == -EAGAIN)
        goto again;

    ret = io->tgt_io_cqe->res;
fail:
    if (ret < 0) {
        longhorn_err("%s: err %d\n", __func__, ret);
    } else {
        ret += longhorn_data->done;
    }

    ublksrv_complete_io(q, data->tag, ret);
    q_data->in_flight_ios -= 1;

    longhorn_info("%s: tag %d ret %d\n", __func__, data->tag, ret);

    co_return;
}
static int longhorn_handle_io_async(const struct ublksrv_queue *q, const struct ublk_io_data *data)
{
    struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);
    struct longhorn_queue_data *q_data = longhorn_get_queue_data(q);

    if (q_data->send_sqe_chain_busy) {
        q_data->next_chain.push_back(data);
    } else {
        io->co = __longhorn_handle_io_async(q, data, io);
    }

    return 0;
}

/*
 * Don't touch @data because the pointed ublk io request may have been
 * completed before this send cqe is handled. And ublk io request completion
 * is triggered by reply received from nbd server.
 */
static void longhorn_send_req_done(const struct ublksrv_queue *q,
                                   const struct ublk_io_data *data,
                                   const struct io_uring_cqe *cqe)
{
    struct longhorn_queue_data *q_data = longhorn_get_queue_data(q);
    unsigned ublk_op = user_data_to_op(cqe->user_data);
    int tag = user_data_to_tag(cqe->user_data);
    unsigned int nr_sects = user_data_to_tgt_data(cqe->user_data);
    unsigned total;

    ublk_assert(q_data->chained_send_ios);
    if (!--q_data->chained_send_ios) {
        if (q_data->send_sqe_chain_busy)
            q_data->send_sqe_chain_busy = 0;
    }

    /*
     * In case of failure, how to tell recv work to handle the
     * request? So far just warn it, maybe nbd server will
     * send one err reply.
     */
    if (cqe->res < 0) {
        longhorn_err("%s: tag %d cqe fail %d %llx\n",
                __func__, tag, cqe->res, cqe->user_data);
    }

    /*
     * We have set MSG_WAITALL, so short send shouldn't be possible,
     * but just warn in case of io_uring regression
     */
    total = sizeof(struct message);
    if (ublk_op == UBLK_IO_OP_WRITE)
        total += (nr_sects << 9);

    if (cqe->res < total)
        longhorn_err("%s: short send/receive tag %d op %d %llx, len %u written %u cqe flags %x\n",
                __func__, tag, ublk_op, cqe->user_data,
                total, cqe->res, cqe->flags);
}

static void longhorn_tgt_io_done(const struct ublksrv_queue *q, const struct ublk_io_data *data, const struct io_uring_cqe *cqe)
{
    int tag = user_data_to_tag(cqe->user_data);

    ublk_assert(tag == data->tag);

    if (is_recv_io(q, data)) {
        struct longhorn_queue_data *q_data = longhorn_get_queue_data(q);

        /*
         * Delay recv data handling into nbd_handle_io_bg(), so
         * any recv sqe won't cut in the send sqe chain.
         *
         * So far, recv is strictly serialized, so saving
         * this single cqe works; in the future, if
         * recv becomes batched, here has to be fixed
         */
        q_data->recv_cqe = *cqe;
        q_data->need_handle_recv = 1;
        return;
    }

    longhorn_send_req_done(q, data, cqe);
}

static void longhorn_handle_send_bg(const struct ublksrv_queue *q, struct longhorn_queue_data *q_data)
{
    if (!q_data->send_sqe_chain_busy) {
        std::vector<const struct ublk_io_data *> &ios = q_data->next_chain;

        for (auto it = ios.cbegin(); it != ios.cend(); ++it) {
            auto data = *it;
            struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);

            ublk_assert(data->tag < q->q_depth);
            io->co = __longhorn_handle_io_async(q, data, io);
        }

        ios.clear();

        if (q_data->chained_send_ios && !q_data->send_sqe_chain_busy)
            q_data->send_sqe_chain_busy = 1;
    }

    if (q_data->last_send_sqe) {
        q_data->last_send_sqe->flags &= ~IOSQE_IO_LINK;
        q_data->last_send_sqe = NULL;
    }
}

/* recv completion drives the whole IO flow */
static inline int longhorn_start_recv(const struct ublksrv_queue *q,
                                      struct longhorn_io_data *longhorn_data,
                                      void *buf, int len,
                                      bool reply, unsigned done)
{
    struct longhorn_queue_data *q_data = longhorn_get_queue_data(q);
    struct io_uring_sqe *sqe = io_uring_get_sqe(q->ring_ptr);
    unsigned int op = reply ? LONGHORN_OP_RESPONSE : LONGHORN_OP_READ;
    unsigned int tag = q->q_depth;    // recv always use this extra tag

    if (!sqe) {
        longhorn_err("%s: get sqe failed, len %d reply %d done %d\n",
            __func__, len, reply, done);
        return -ENOMEM;
    }

    longhorn_data->done = done;

    io_uring_prep_recv(sqe, q->q_id + 1, (char *)buf + done, len - done, MSG_WAITALL);
    io_uring_sqe_set_flags(sqe, IOSQE_FIXED_FILE);

    /* bit63 marks us as tgt io */
    sqe->user_data = build_user_data(tag, op, 0, 1);

    ublk_assert(q_data->in_flight_ios);
    longhorn_info("%s: q_inflight %d queue recv %s"
            "(qid %d tag %u, target: %d, user_data %llx)\n",
            __func__, q_data->in_flight_ios, reply ? "reply" : "io",
            q->q_id, tag, 1, sqe->user_data);

    return 0;
}

static inline uint32_t longhorn_seq_to_tag(uint32_t seq)
{
    return (uint32_t)seq;
}

/*
 * Submit recv worker for reading nbd reply or read io data
 *
 * return value:
 *
 * 0 : queued via io_uring
 * len : data read already, must be same with len
 * < 0 : failure
 */
static int longhorn_do_recv(const struct ublksrv_queue *q,
                            struct longhorn_io_data *longhorn_data, int fd,
                            void *buf, unsigned len)
{
    unsigned msg_flags = MSG_DONTWAIT | MSG_WAITALL;
    int i = 0, done = 0;
    const int loops = len < 512 ? 16 : 32;
    int ret;

    while (i++ < loops && done < len) {
        ret = recv(fd, (char *)buf + done, len - done, msg_flags);
        if (ret > 0)
            done += ret;
        if (!done)
            break;
    }
    if (done == len)
        return done;

    longhorn_info("%s: sync(non-blocking) recv %d(%s)/%d/%u\n",
        __func__, ret, strerror(errno), done, len);
    return longhorn_start_recv(q, longhorn_data, buf, len, len < 512, done);
}

static int longhorn_handle_recv_reply(const struct ublksrv_queue *q,
                                      struct longhorn_io_data *longhorn_data,
                                      const struct io_uring_cqe *cqe,
                                      const struct ublk_io_data **io_data)
{
    struct longhorn_queue_data *q_data = longhorn_get_queue_data(q);
    const struct ublk_io_data *data;
    struct ublk_io_tgt *io;
    uint32_t seq, tag;
    int hwq;
    unsigned ublk_op;
    int ret = -EINVAL;

    if (cqe->res < 0) {
        longhorn_err("%s %d: reply cqe %d\n", __func__, __LINE__, cqe->res);
        ret = cqe->res;
        goto fail;
    } else if (cqe->res == 0 && longhorn_data->done == 0) {
        longhorn_err("%s %d: zero reply cqe %d %llx\n", __func__,
                __LINE__, cqe->res, cqe->user_data);
    }

    if (le16toh(q_data->reply.magic) != LONGHORN_MESSAGE_MAGIC) {
        longhorn_err("%s %d: reply bad magic %x size %d res %d\n",
                __func__, __LINE__, le16toh(q_data->reply.magic), le32toh(q_data->reply.size), cqe->res);
        ret = -EPROTO;
        goto fail;
    }

    if (cqe->res + longhorn_data->done != sizeof(struct message)) {
        longhorn_err("%s %d: bad reply cqe %d %llx, done %u\n",
                __func__, __LINE__, cqe->res, cqe->user_data, longhorn_data->done);
    }
    ublk_assert(cqe->res + longhorn_data->done == sizeof(struct message));

    memcpy(&seq, &q_data->reply.seq, sizeof(seq));
    tag = longhorn_seq_to_tag(seq);
    hwq = ublk_unique_tag_to_hwq(tag);

    if (tag >= q->q_depth) {
        longhorn_err("%s %d: tag is too big %d\n", __func__, __LINE__, tag);
        goto fail;
    }

    if (hwq != q->q_id) {
        longhorn_err("%s %d: hwq is too big %d\n", __func__, __LINE__, hwq);
        goto fail;
    }

    data = ublksrv_queue_get_io_data(q, tag);
    io = __ublk_get_io_tgt_data(data);
    longhorn_data = io_tgt_to_longhorn_data(io);

    ublk_op = ublksrv_get_op(data->iod);
    if (ublk_op == UBLK_IO_OP_READ) {
        *io_data = data;
        return 1;
    } else {
        struct io_uring_cqe fake_cqe;
        uint32_t type = q_data->reply.type;


        longhorn_info("%s: got write reply, tag %d type %u\n", __func__, data->tag, type);

        if (type == LONGHORN_CMD_TYPE_ERROR) {
            fake_cqe.res = -EIO;
        } else {
            if (ublk_op == UBLK_IO_OP_WRITE)
                fake_cqe.res = data->iod->nr_sectors << 9;
            else
                fake_cqe.res = 0;
        }

        io->tgt_io_cqe = &fake_cqe;
        io->co.resume();
        return 0;
    }
fail:
    return ret;
}

static void __longhorn_resume_read_req(const struct ublk_io_data *data,
                                       const struct io_uring_cqe *cqe,
                                       unsigned done)
{
    struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);
    struct longhorn_io_data *longhorn_data = io_tgt_to_longhorn_data(io);

    longhorn_data->done = done;
    io->tgt_io_cqe = cqe;

    io->co.resume();
}

/*
 * Every request will be responded with one reply, and we complete the
 * request after the reply is received.
 *
 * Read request is a bit special, since the data returned are received
 * with the reply together, so we have to handle read IO data here.
 */
static co_io_job __longhorn_handle_recv(const struct ublksrv_queue *q,
                                   const struct ublk_io_data *data,
                                   struct ublk_io_tgt *io)
{
    struct longhorn_io_data *longhorn_data = io_tgt_to_longhorn_data(io);
    struct longhorn_queue_data *q_data = longhorn_get_queue_data(q);
    int fd = q->dev->tgt.fds[q->q_id + 1];
    unsigned int len;
    uint64_t cqe_buf[2] = { 0 };
    struct io_uring_cqe *fake_cqe = (struct io_uring_cqe *)cqe_buf;

    q_data->recv_started = 1;

    while (q_data->in_flight_ios > 0) {
        const struct ublk_io_data *io_data = NULL;
        int ret;
read_reply:
        ret = longhorn_do_recv(q, longhorn_data, fd, &q_data->reply, sizeof(q_data->reply));
        if (ret == sizeof(q_data->reply)) {
            longhorn_data->done = ret;
            fake_cqe->res = 0;
            io->tgt_io_cqe = fake_cqe;
            goto handle_recv;
        } else if (ret < 0) {
            break;
        }

        co_await__suspend_always(data->tag);
        if (io->tgt_io_cqe->res == -EAGAIN)
            goto read_reply;

handle_recv:
        ret = longhorn_handle_recv_reply(q, longhorn_data, io->tgt_io_cqe, &io_data);
        if (ret < 0)
            break;
        if (!ret)
            continue;
read_io:
        ublk_assert(io_data != NULL);

        len = io_data->iod->nr_sectors << 9;
        ret = longhorn_do_recv(q, longhorn_data, fd, (void *)io_data->iod->addr, len);
        if (ret == len) {
            longhorn_data->done = ret;
            fake_cqe->res = 0;
            io->tgt_io_cqe = fake_cqe;
            goto handle_read_io;
        } else if (ret < 0) {
            break;
        }

        /* still wait on recv coroutine context */
        co_await__suspend_always(data->tag);

        ret = io->tgt_io_cqe->res;
        if (ret == -EAGAIN)
            goto read_io;

handle_read_io:
        __longhorn_resume_read_req(io_data, io->tgt_io_cqe, longhorn_data->done);
    }
    q_data->recv_started = 0;
    co_return;
}

static void longhorn_handle_recv_bg(const struct ublksrv_queue *q, struct longhorn_queue_data *q_data)
{
    if (q_data->in_flight_ios && !q_data->recv_started) {
        const struct ublk_io_data *data = ublksrv_queue_get_io_data(q, q->q_depth);
        struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);

        ublk_assert(data->tag == q->q_depth);

        io->co = __longhorn_handle_recv(q, data, io);
    }

    /* reply or read io data is comming */
    if (q_data->need_handle_recv) {
        const struct ublk_io_data *data = ublksrv_queue_get_io_data(q, q->q_depth);
        struct ublk_io_tgt *io = __ublk_get_io_tgt_data(data);

        ublk_assert(data->tag == q->q_depth);

        io->tgt_io_cqe = &q_data->recv_cqe;

        io->co.resume();
        q_data->need_handle_recv = 0;
    }
}

static void __longhorn_handle_io_bg(const struct ublksrv_queue *q, struct longhorn_queue_data *q_data)
{
    longhorn_handle_send_bg(q, q_data);

    /* stop to queue send now since we need to recv now */
    if (q_data->chained_send_ios && !q_data->send_sqe_chain_busy)
        q_data->send_sqe_chain_busy = 1;

    /*
     * recv SQE can't cut in send SQE chain, so it has to be
     * moved here after the send SQE chain is built
     *
     * Also queuing ublk io command may allocate sqe too.
     */    
    longhorn_handle_recv_bg(q, q_data);
}

/*
 * The initial send request batch should be in same send sqe batch, before
 * this batch isn't done, all new send requests are staggered into next_chain
 * which will be flushed after the current chain is completed.
 *
 * Also recv work is always started after send requests are queued, because
 * the recv sqe may cut the send sqe chain, and the ublk io cmd sqe may cut
 * the send sqe chain too.
 *
 * This is why nbd_handle_recv_bg() always follows nbd_handle_send_bg().
 */
static void longhorn_handle_io_bg(const struct ublksrv_queue *q, int nr_queued_io)
{
    struct longhorn_queue_data *q_data = longhorn_get_queue_data(q);

    __longhorn_handle_io_bg(q, q_data);

    if (q_data->in_flight_ios == 0 && q_data->send_sqe_chain_busy) {
        /* all inflight ios are done, so it is safe to send request */
        q_data->send_sqe_chain_busy = 0;

        if (!q_data->next_chain.empty())
            __longhorn_handle_io_bg(q, q_data);
    }

    if (!q_data->recv_started && !q_data->send_sqe_chain_busy && !q_data->next_chain.empty()) {
        longhorn_err("%s: hang risk: pending ios %d/%d\n",
                __func__, q_data->in_flight_ios, q_data->chained_send_ios);
    }
}

struct ublksrv_tgt_type longhorn_tgt_type = {
    .handle_io_async = longhorn_handle_io_async,
    .tgt_io_done = longhorn_tgt_io_done,
    .handle_io_background = longhorn_handle_io_bg,
    .usage_for_add = longhorn_usage_for_add,

    .init_tgt = longhorn_init_tgt,
    .deinit_tgt = longhorn_deinit_tgt,

    .type = UBLKSRV_TGT_TYPE_LONGHORN,
    .name = "longhorn",

    .init_queue = longhorn_init_queue,
    .deinit_queue = longhorn_deinit_queue,
};

static void tgt_longhorn_init() __attribute__((constructor));

static void tgt_longhorn_init(void)
{
    ublksrv_register_tgt_type(&longhorn_tgt_type);
}
