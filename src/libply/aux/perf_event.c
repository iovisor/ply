/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include <ply/ply.h>
#include <ply/internal.h>

static int perf_event_id(struct ply_probe *pb, const char *path)
{
	FILE *fp;
	int id;

	fp = fopenf("r", "%s/id", path);
	if (!fp)
		goto err;

	if (fscanf(fp, "%d", &id) != 1)
		goto err;

	return id;
err:
	return -errno;
}

int perf_event_attach(struct ply_probe *pb, const char *path,
		      int task_mode)
{
	struct perf_event_attr attr = {};
	int fd, id;
	int pid = task_mode ? 0 : -1;
	int cpu = task_mode ? -1 : 0;
	int group_fd = task_mode ? -1 : pb->ply->group_fd;

	id = perf_event_id(pb, path);
	if (id < 0)
		return id;

	attr.type = PERF_TYPE_TRACEPOINT;
	attr.sample_type = PERF_SAMPLE_RAW;
	attr.sample_period = 1;
	attr.wakeup_events = 1;
	attr.config = id;
	attr.disabled = 1;

	fd = perf_event_open(&attr, pid, cpu, group_fd, 0);
	if (fd < 0)
		return -errno;

	/* if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0)) { */
	/* 	close(fd); */
	/* 	return -errno; */
	/* } */

	if (ioctl(fd, PERF_EVENT_IOC_SET_BPF, pb->bpf_fd)) {
		close(fd);
		return -errno;
	}

	if (pb->ply->group_fd == -1 && !task_mode)
		pb->ply->group_fd = fd;

	return fd;
}

int perf_event_enable(int group_fd)
{
	if (ioctl(group_fd, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP))
		return -errno;

	return 0;
}

int perf_event_disable(int group_fd)
{
	if (ioctl(group_fd, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP))
		return -errno;

	return 0;
}
