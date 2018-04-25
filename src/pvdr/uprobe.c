/*
 * Copyright 2015-2017 Tobias Waldekranz <tobias@waldekranz.com>
 *
 * This file is part of ply.
 *
 * ply is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, under the terms of version 2 of the
 * License.
 *
 * ply is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ply.  If not, see <http://www.gnu.org/licenses/>.
 */

/* 
 * Refer to https://www.kernel.org/doc/Documentation/trace/uprobetracer.txt
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fnmatch.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <linux/version.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <ply/bpf-syscall.h>
#include <ply/module.h>
#include <ply/ply.h>
#include <ply/pvdr.h>

#include "kprobe.h"

/* 
 * XXX - TODO: Don't rely on the kprobe functions, we need to generalise them
 *       to work with both kprobe and uprobe.  Alternatively, pull them here
 *       and rename to uprobe so we have dedicated code.
 * 
 *       See kprobe_setattach() which has uprobe checks hard coded.
 */

int uprobe_load(node_t *probe, prog_t *prog, const char *type,
		       kprobe_t **kpp)
{
	kprobe_t *kp;
	char *func;

	kp = probe_load(BPF_PROG_TYPE_KPROBE, probe, prog);
	if (!kp)
		return -EINVAL;

	kp->type = type;

	kp->ctrl = fopen("/sys/kernel/debug/tracing/uprobe_events", "a+");
	if (!kp->ctrl) {
		_eno("unable to open uprobe_events");
		return -errno;
	}

	*kpp = kp;
	func = strchr(probe->string, ':') + 1;
	return kprobe_setattach_pattern(kp, func, 1);
}

int uprobe_setup(node_t *probe, prog_t *prog)
{
	return uprobe_load(probe, prog, "p",
			   (kprobe_t **)&probe->dyn->probe.pvdr_priv);
}

pvdr_t uprobe_pvdr = {
	.name = "uprobe",
	.desc = "Userland function entry provider.",

	.resolve = kprobe_resolve,

	.setup = uprobe_setup,
	.teardown = kprobe_teardown,
};

int uretprobe_setup(node_t *probe, prog_t *prog)
{
	return uprobe_load(probe, prog, "r",
			   (kprobe_t **)&probe->dyn->probe.pvdr_priv);
}

pvdr_t uretprobe_pvdr = {
	.name = "uretprobe",
	.desc = "Userland function return provider.",

	.resolve = kretprobe_resolve,

	.setup = uretprobe_setup,
	.teardown = kprobe_teardown,
};

/* Register Provider */
__attribute__((constructor))
static void uprobe_pvdr_register(void)
{
	pvdr_register(   &uprobe_pvdr);
	pvdr_register(&uretprobe_pvdr);
}