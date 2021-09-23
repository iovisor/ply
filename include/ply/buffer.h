/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef _PLY_BUFFER_H
#define _PLY_BUFFER_H

#include <stdint.h>

#include <linux/perf_event.h>

#include <sys/queue.h>

struct buffer_ev {
	struct perf_event_header hdr;
	uint32_t size;

	uint64_t id;
	uint8_t  data[0];
} __attribute__((packed));

struct buffer_evh {
	TAILQ_ENTRY(buffer_evh) node;

	uint64_t id;
	void *priv;

	struct ply_return (*handle)(struct buffer_ev *ev, void *priv);
};

void buffer_evh_register(struct buffer_evh *evh);

struct buffer;

struct buffer *buffer_new(int mapfd);

struct ply_return buffer_loop(struct buffer *buf, int timeout);

#endif	/* _PLY_BUFFER_H */
