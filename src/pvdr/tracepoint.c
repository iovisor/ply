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

/* Tracepoint Provider 
 *
 * Refer to https://www.kernel.org/doc/Documentation/trace/tracepoints.txt
 * for more information.
 * 
 * A tracepoint placed in code provides a hook to call a function (probe)
 * that you can provide at runtime. A tracepoint can be "on" (a probe is
 * connected to it) or "off" (no probe is attached). When a tracepoint is
 * "off" it has no effect, except for adding a tiny time penalty
 * (checking a condition for a branch) and space penalty (adding a few
 * bytes for the function call at the end of the instrumented function
 * and adds a data structure in a separate section).  When a tracepoint
 * is "on", the function you provide is called each time the tracepoint
 * is executed, in the execution context of the caller. When the function
 * provided ends its execution, it returns to the caller (continuing from
 * the tracepoint site).
 * 
 * You can put tracepoints at important locations in the code. They are
 * lightweight hooks that can pass an arbitrary number of parameters,
 * which prototypes are described in a tracepoint declaration placed in a
 * header file.
 * 
 * They can be used for tracing and performance accounting.
 */
#ifdef LINUX_HAS_TRACEPOINT

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

static int trace_attach(kprobe_t *kp, const char *func)
{
	int id;

	id = probe_event_id(kp, func);
	if (id < 0)
		return id;

	return probe_attach(kp, id);
}

static int trace_load(node_t *probe, prog_t *prog)
{
	kprobe_t *kp;
	char *func;

	kp = probe_load(BPF_PROG_TYPE_TRACEPOINT, probe, prog);
	if (!kp)
		return -EINVAL;

	probe->dyn->probe.pvdr_priv = kp;

	func = strchr(probe->string, ':') + 1;

	return trace_attach(kp, func);
}

const module_t *trace_modules[] = {
	&trace_module,

	&method_module,
	&common_module,

	NULL
};

static int trace_resolve(node_t *call, const func_t **f)
{
	return modules_get_func(trace_modules, call, f);
}

pvdr_t trace_pvdr = {
	.name = "trace",
	.desc = "Linux Kernel Tracepoint Provider.",

	.resolve = trace_resolve,

	.setup      = trace_load,
	.teardown   = probe_teardown,
};

/* Register provider */
__attribute__((constructor))
static void trace_pvdr_register(void)
{
	pvdr_register(&trace_pvdr);
}

#endif
