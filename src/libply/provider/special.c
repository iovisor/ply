/*
 * Copyright  Namhyung Kim <namhyung@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <ply/ply.h>
#include <ply/internal.h>

#include "xprobe.h"

static char exename[PATH_MAX];
static special_probe_t begin_fn;
static special_probe_t end_fn;
static unsigned long begin_offset;
static unsigned long end_offset;

int register_special_probes(special_probe_t begin, special_probe_t end)
{
	FILE *fp;
	char buf[PATH_MAX];
	unsigned long base_addr;

	if (begin == NULL && end == NULL)
		return 0;

	begin_fn = begin;
	end_fn = end;

	if (!realpath("/proc/self/exe", exename)) {
		_w("cannot read pathname of the process image\n");
		return -1;
	}

	fp = fopen("/proc/self/maps", "r");
	if (fp == NULL) {
		_w("cannot read memory mapping info\n");
		return -1;
	}
	while (fgets(buf, sizeof(buf), fp)) {
		unsigned long start, end;
		unsigned long off, ino;
		char prot[8];
		char dev[8];
		char path[PATH_MAX];

		if (sscanf(buf, "%lx-%lx %s %lx %s %lu %s\n",
			   &start, &end, prot, &off, dev, &ino, path) != 7)
			continue;

		if (strcmp(path, exename))
			continue;

		base_addr = start;
		break;
	}
	fclose(fp);

	begin_offset = (unsigned long)begin - base_addr;
	end_offset = (unsigned long)end - base_addr;
	return 0;
}

void trigger_begin_probe(struct ply_probe *pb)
{
	struct xprobe *xp = pb->provider_data;

	/* special probe isn't in a perf event group */
	perf_event_enable(xp->evfds[0]);

	begin_fn();
}

void trigger_end_probe(struct ply_probe *pb)
{
	struct xprobe *xp = pb->provider_data;

	/* special probe isn't in a perf event group */
	perf_event_enable(xp->evfds[0]);

	end_fn();
}

static int special_sym_alloc(struct ply_probe *pb, struct node *n)
{
	return -ENOENT;
}

static int special_probe(struct ply_probe *pb)
{
	struct xprobe *xp;
	unsigned long offset = begin_offset;

	if (!strcmp(pb->provider->name, "END"))
		offset = end_offset;

	/* should not happen */
	if (offset == 0) {
		_e("cannot use special provider\n");
		return -1;
	}

	xp = xcalloc(1, sizeof(*xp));
	xp->type = 'p';
	xp->ctrl_name = "uprobe_events";
	asprintf(&xp->pattern, "%s:%lu", exename, offset);
	assert(xp->pattern);

	pb->provider_data = xp;
	pb->special = 1;
	return 0;
}

struct provider begin_provider = {
	.name = "BEGIN",
	.prog_type = BPF_PROG_TYPE_KPROBE,

	.probe     = special_probe,
	.sym_alloc = special_sym_alloc,

	.attach = xprobe_attach,
	.detach = xprobe_detach,
};

struct provider end_provider = {
	.name = "END",
	.prog_type = BPF_PROG_TYPE_KPROBE,

	.probe     = special_probe,
	.sym_alloc = special_sym_alloc,

	.attach = xprobe_attach,
	.detach = xprobe_detach,
};
