// SPDX-License-Identifier: GPL-2.0
#ifndef TGT_LONGHORN_H
#define TGT_LONGHORN_H

#include <stdint.h>
#include <vector>
#include "longhorn_protocol.h"
#include "longhorn_common.h"

struct longhorn_queue_data {
    unsigned short in_flight_ios;

    unsigned short recv_started:1;
    unsigned short need_handle_recv:1;
    unsigned short send_sqe_chain_busy:1;

    unsigned int chained_send_ios;

    /*
     * When the current chain is busy, staggering send ios
     * into this queue(next_chain). After the current chain
     * is consumed, submit all send ios in 'next_chain' as
     * one whole batch.
     */
    std::vector <const struct ublk_io_data *> next_chain;

    struct io_uring_sqe *last_send_sqe;
    struct message reply;
    struct io_uring_cqe recv_cqe;
};

struct longhorn_io_data {
    uint32_t seq;
    uint32_t done;    // for handling partial recv
};

#define LONGHORN_WRITE_TGT_STR(dev, jbuf, jbuf_size, name, val) do { \
    int ret;                        \
    if (val)                        \
        ret = ublksrv_json_write_target_str_info(jbuf,    \
                jbuf_size, name, val);        \
    else                            \
        ret = 0;                    \
    if (ret < 0)                        \
        jbuf = ublksrv_tgt_realloc_json_buf(dev, &jbuf_size);    \
    else                            \
        break;                        \
} while (1)

#define LONGHORN_WRITE_TGT_LONG(dev, jbuf, jbuf_size, name, val) do { \
    int ret = ublksrv_json_write_target_ulong_info(jbuf, jbuf_size, \
            name, val);                    \
    if (ret < 0)                            \
        jbuf = ublksrv_tgt_realloc_json_buf(dev, &jbuf_size);    \
    else                            \
        break;                        \
} while (1)

#endif /* TGT_LONGHORN_H */
