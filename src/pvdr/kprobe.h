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

#ifndef _KPROBE_H
#define _KPROBE_H

#define KPROBE_MAXLEN   0x100

/*
 * Structure used for internal representation of kprobes, kretprobes and
 * tracepoints.
 */
typedef struct kprobe {
	const char *pvdr;
	const char *type;
	FILE *ctrl;
	int bfd;

	struct {
		int cap, len;
		int *fds;
	} efds;
} kprobe_t;

extern const module_t *kprobe_modules[];
extern const module_t *kretprobe_modules[];

int probe_event_id(kprobe_t *kp, const char *path);
int probe_attach(kprobe_t *kp, int id);
kprobe_t *probe_load(enum bpf_prog_type type, node_t *probe, prog_t *prog);
int probe_teardown_events(kprobe_t *kp);
int probe_teardown(node_t *probe);
int kprobe_setattach(kprobe_t *kp, const char *func_and_offset, int attach);
int kprobe_setattach_pattern(kprobe_t *kp, const char *pattern, int attach);
int kprobe_load(node_t *probe, prog_t *prog, const char *probestring, const char *type, kprobe_t **kpp);
int kprobe_detach(kprobe_t *kp, const char *probestring);
int kprobe_default(node_t *probe, node_t **stmts);
int kprobe_resolve(node_t *call, const func_t **f);
int kprobe_setup(node_t *probe, prog_t *prog);
int kprobe_destroy(kprobe_t *kp, const char *pattern);
int kprobe_teardown(node_t *probe);
int kretprobe_default(node_t *probe, node_t **stmts);
int kretprobe_resolve(node_t *call, const func_t **f);
int kretprobe_setup(node_t *probe, prog_t *prog);

#endif	/* _KPROBE_H */
