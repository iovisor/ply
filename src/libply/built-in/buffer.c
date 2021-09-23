/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>

#include <ply/ply.h>
#include <ply/internal.h>

#include "built-in.h"

TAILQ_HEAD(buffer_evhs, buffer_evh);
static struct buffer_evhs evhs = TAILQ_HEAD_INITIALIZER(evhs);

static struct buffer_evh *buffer_evh_find(uint64_t id)
{
	struct buffer_evh *evh;

	TAILQ_FOREACH(evh, &evhs, node) {
		if (evh->id == id)
			return evh;
	}

	return NULL;
}

static struct ply_return buffer_evh_call(struct buffer_ev *ev, size_t size)
{
	struct buffer_evh *evh;

	evh = buffer_evh_find(ev->id);
	if (!evh) {
		_e("unknown event: id:%#"PRIx64" size:%#zx\n",
		   ev->id, size);
		return (struct ply_return) { .err = 1, .val = ENOSYS };
	}

	return evh->handle(ev, evh->priv);
}

void buffer_evh_register(struct buffer_evh *evh)
{
	static uint64_t next_id = 0;

	evh->id = next_id++;
	TAILQ_INSERT_TAIL(&evhs, evh, node);
}


struct lost_event {
	struct perf_event_header hdr;
	uint64_t id;
	uint64_t lost;
} __attribute__((packed));

struct buffer_q {
	int fd;
	struct perf_event_mmap_page *mem;

	void *buf;
};

struct buffer {
	int mapfd;
	uint32_t ncpus;

	struct pollfd *poll;
	struct buffer_q q[0];
};

static inline uint64_t __get_head(struct perf_event_mmap_page *mem)
{
	volatile uint64_t head = *((volatile uint64_t *)&mem->data_head);

	asm volatile("" ::: "memory");
	return head;
}

static inline void __set_tail(struct perf_event_mmap_page *mem, uint64_t tail)
{
	asm volatile("" ::: "memory");

	mem->data_tail = tail;
}

struct ply_return buffer_q_drain(struct buffer_q *q)
{
	struct lost_event *lost;
	struct ply_return ret = {};
	struct buffer_ev *ev;
	uint64_t size, offs, head, tail;
	uint8_t *base, *this, *next;

	size = q->mem->data_size;
	offs = q->mem->data_offset;
	base = (uint8_t *)q->mem + offs;

	for (head = __get_head(q->mem); q->mem->data_tail != head;
	     __set_tail(q->mem, q->mem->data_tail + ev->hdr.size)) {
		tail = q->mem->data_tail;

		this = base + (tail % size);
		ev   = (void *)this;
		next = base + ((tail + ev->hdr.size) % size);

		if (next < this) {
			size_t left = (base + size) - this;

			q->buf = realloc(q->buf, ev->hdr.size);
			memcpy(q->buf, this, left);
			memcpy(q->buf + left, base, ev->hdr.size - left);
			ev = q->buf;
		}

		switch (ev->hdr.type) {
		case PERF_RECORD_SAMPLE:
			ret = buffer_evh_call(ev, ev->hdr.size);
			break;

		case PERF_RECORD_LOST:
			lost = (void *)ev;

			if (ply_config.strict) {
				_e("lost %"PRId64" events", lost->lost);
				ret.err = 1;
				ret.val = EOVERFLOW;
			} else {
				_w("lost %"PRId64" events", lost->lost);
			}
			break;

		default:
			_e("unknown perf event %#"PRIx32, ev->hdr.type);
			ret.err = 1;
			ret.val = EINVAL;
			break;
		}

		if (ret.err || ret.exit)
			break;
	}

	return ret;
}

struct ply_return buffer_loop(struct buffer *buf, int timeout)
{
	struct ply_return ret;
	uint32_t cpu;
	int ready;

	for (;;) {
		ready = poll(buf->poll, buf->ncpus, timeout);
		if (ready < 0) {
			ret.err = 1;
			ret.val = errno;
			return ret;
		}

		if (timeout == -1) {
			assert(ready);
		} else if (ready == 0) {
			ret.err = 0;
			return ret;
		}

		for (cpu = 0; ready && (cpu < buf->ncpus); cpu++) {
			if (!(buf->poll[cpu].revents & POLLIN))
				continue;

			ret = buffer_q_drain(&buf->q[cpu]);
			if (ret.err | ret.exit)
				return ret;

			ready--;
		}
	}

	return ret;
}

int buffer_q_init(struct buffer *buf, uint32_t cpu)
{
	struct perf_event_attr attr = { 0 };
	struct buffer_q *q = &buf->q[cpu];
	size_t size;
	int err;

	attr.type          = PERF_TYPE_SOFTWARE;
	attr.config        = PERF_COUNT_SW_BPF_OUTPUT;
	attr.sample_type   = PERF_SAMPLE_RAW;
	attr.wakeup_events = 1;

	q->fd = perf_event_open(&attr, -1, cpu, -1, 0);
	if (q->fd < 0) {
		_e("could not create queue\n");
		return q->fd;
	}

	err = bpf_map_update(buf->mapfd, &cpu, &q->fd, BPF_ANY);
	if (err) {
		_e("could not link map to queue\n");
		return err;
	}

	size = sysconf(_SC_PAGESIZE) * (ply_config.buf_pages + 1);
	q->mem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, q->fd, 0);
	if (q->mem == MAP_FAILED) {
		_e("could not mmap queue\n");
		return -1;
	}

	buf->poll[cpu].fd     = q->fd;
	buf->poll[cpu].events = POLLIN;
	return 0;
}

struct buffer *buffer_new(int mapfd)
{
	struct buffer *buf;
	int err, cpu, ncpus = t_buffer.map.len;

	buf = xcalloc(1, sizeof(*buf) + ncpus * sizeof(buf->q[0]));

	buf->mapfd = mapfd;
	buf->ncpus = ncpus;

	buf->poll = xcalloc(ncpus, sizeof(*buf->poll));

	for (cpu = 0; cpu < ncpus; cpu++) {
		err = buffer_q_init(buf, cpu);
		if (err)
			return NULL;
	}

	return buf;
}



static int stdbuf_static_validate(const struct func *func, struct node *n)
{
	n->expr.ident = 1;
	return 0;
}

static struct func stdbuf_func = {
	.name = "stdbuf",
	.type = &t_buffer,
	.static_ret = 1,

	.static_validate = stdbuf_static_validate,
};

static int bwrite_ir_post(const struct func *func, struct node *n,
			  struct ply_probe *pb)
{
	struct node *buf, *data, *ctx;

	ctx  = n->expr.args;
	buf  = ctx->next;
	data = buf->next;

	ir_emit_perf_event_output(pb->ir, buf->sym, ctx->sym, data->sym);
	return 0;
}

static struct tfield f_bwrite[] = {
	{ .type = &t_void },
	{ .type = &t_buffer },
	{ .type = &t_void },
	{ .type = NULL }
};

struct type t_bwrite = {
	.ttype = T_FUNC,
	.func = { .type = &t_void, .args = f_bwrite },
};

static struct func bwrite_func = {
	.name = "bwrite",
	.type = &t_bwrite,
	.static_ret = 1,

	.ir_post = bwrite_ir_post,
};

void buffer_init(void)
{
	built_in_register(&stdbuf_func);
	built_in_register(&bwrite_func);
}
