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

typedef struct profile {
	int *efds;
	int num;
	kprobe_t *kp;
} profile_t;

static int probe_event_id(kprobe_t *kp, const char *path)
{
	FILE *fp;
	char ev_id[16];

	fp = fopenf("r", "/sys/kernel/debug/tracing/events/%s/id", path);
	if (!fp)
		return -errno;

	if (!fgets(ev_id, sizeof(ev_id), fp))
		return -EIO;

	fclose(fp);
	return strtol(ev_id, NULL, 0);
}

static int probe_attach(kprobe_t *kp, int id)
{
	struct perf_event_attr attr = {};
	int efd, gfd;

	attr.type = PERF_TYPE_TRACEPOINT;
	attr.sample_type = PERF_SAMPLE_RAW;
	attr.sample_period = 1;
	attr.wakeup_events = 1;
	attr.config = id;

	gfd = kp->efds.len ? kp->efds.fds[0] : -1;
	efd = perf_event_open(&attr, -1, 0, gfd, 0);
	if (efd < 0) {
		_d("could not open perf_event: %s", strerror(errno));
		return -errno;
	}

	if (ioctl(efd, PERF_EVENT_IOC_ENABLE, 0)) {
		close(efd);
		_d("could not enable probe: %s", strerror(errno));
		return -errno;
	}

	if (ioctl(efd, PERF_EVENT_IOC_SET_BPF, kp->bfd)) {
		close(efd);
		_d("could not set BPF program: %s", strerror(errno));
		return -errno;
	}

	if (kp->efds.len == kp->efds.cap) {
		size_t sz = kp->efds.cap * sizeof(*kp->efds.fds);

		kp->efds.fds = realloc(kp->efds.fds, sz << 1);
		assert(kp->efds.fds);
		kp->efds.cap <<= 1;
	}

	kp->efds.fds[kp->efds.len++] = efd;

	return 1;
}

static kprobe_t *probe_load(enum bpf_prog_type type,
			    node_t *probe, prog_t *prog)
{
	kprobe_t *kp;

	kp = calloc(1, sizeof(*kp));
	assert(kp);

	kp->pvdr = probe->dyn->probe.pvdr->name;
	kp->efds.fds = calloc(1, sizeof(*kp->efds.fds));
	assert(kp->efds.fds);
	kp->efds.cap = 1;
	kp->efds.len = 0;

	kp->bfd = bpf_prog_load(type, prog->insns, prog->ip - prog->insns);
	if (kp->bfd < 0) {
		_eno("%s", probe->string);
		if (!bpf_log_buf[0]) {
			_e("no output from kernel verifier");
			_e("was ply built against the running kernel?");
		} else {
			_e("output from kernel bpf verifier:\n%s", bpf_log_buf);
		}

		free(kp);
		return NULL;
	}

	return kp;
}

static int probe_teardown_events(kprobe_t *kp)
{
	int i;

	for (i = 0; i < kp->efds.len; i++)
		close(kp->efds.fds[i]);
	free(kp->efds.fds);

	return 0;
}

static int probe_teardown(node_t *probe)
{
	int err;

	kprobe_t *kp = probe->dyn->probe.pvdr_priv;

	err = probe_teardown_events(kp);

	if (kp->ctrl)
		fclose(kp->ctrl);
	free(kp);

	return err;
}

/* KPROBE provider */

/*
 * Set attach state for function/offset to attached if attach is 1, otherwise
 * detach.
 *
 * In order to make [uk][ret]probes unique to this instance of ply, we name
 * the probes [type]_[func]_[offset]_[pid], where
 *	- type is the type of probe (p for [uk]probes, r for [uk]retprobes);
 *	- func and offset are function name and offset
 *	- pid is process id of this process.
 *
 * For example, p_kfree_skb_0_1234 is the kprobe for kfree_skb at offset 0
 * created by process 1234.
 *
 * Making probes unique like this allows us to have multiple [uk][ret]probes
 * active for different instances of ply running simultaneously, and it
 * gives us a way to clean up after ourselves only when done.
 */
static int kprobe_setattach(kprobe_t *kp, const char *func_and_offset,
			    int attach)
{
	char fullprobename[KPROBE_MAXLEN];
	char probename[KPROBE_MAXLEN];
	char *probeclass = "kprobes";
	char func[KPROBE_MAXLEN];
	char *fix_probename;
	const char *offstr;
	long offs = 0;
	int funclen;
	int i, id, err;

	offstr = strchrnul(func_and_offset, '+');
	if (*offstr) {
		offs = strtol(offstr, NULL, 0);
		if (offs < 0) {
			_e("unknown offset in probe '%s'", func);
			return -EINVAL;
		}
	}
	funclen = (int)(offstr - func_and_offset);
	snprintf(func, funclen+1, "%*.*s", funclen, funclen, func_and_offset);

	snprintf(probename, sizeof(probename), "%s_%s_%ld_%d",
		 kp->type, func, offs, G.self);

	/*
	 * u[ret]probes are of form /path/to/execname:func+offset - replace ':'
	 * and '/' elements. +offset is not currently supported.
	 */
	if (strcmp(kp->pvdr, "uprobe") == 0 ||
	    strcmp(kp->pvdr, "uretprobe") == 0) {
		if (offs != 0) {
			_w("uprobes do not support addresses of form %s",
			   func_and_offset);
			return -EINVAL;
		}
		probeclass = "uprobes";
		for (i = 0; i < strlen(probename); i++) {
			switch (probename[i]) {
			case ':':
			case '/':
				probename[i] = '_';
				break;
			default:
				break;
			}
		}
	}

	snprintf(fullprobename, sizeof(fullprobename),
			 "%s/%s", probeclass, probename);

	assert(kp->ctrl);
	_d("%s %s+%x", attach ? "attaching to" : "detaching from", func, offs);
	fseek(kp->ctrl, 0, SEEK_END);
	if (attach) {
		if (offs)
			err = fprintf(kp->ctrl, "%s:%s %s+%ld\n", kp->type,
				      probename, func, offs);
		else
			err = fprintf(kp->ctrl, "%s:%s %s\n", kp->type,
				      probename, func);

	} else
		err = fprintf(kp->ctrl, "-:%s\n", probename);

	if (err < 0)
		err = -errno;
	else
		err = 0;

	fflush(kp->ctrl);

	/* If detaching or something went wrong, we're done... */
	if (!attach || err) {
		if (err) {
			_d("error %d %s %s (%s+%x)", err,
			   attach ? "attaching to" : "detaching from",
			   probename, func, offs);
		}
		return err;
	}

	id = probe_event_id(kp, fullprobename);
	if (id < 0)
		return id;

	return probe_attach(kp, id);
}

static int kprobe_setattach_pattern(kprobe_t *kp, const char *pattern,
				    int attach)
{
	int i, err;

	if (!strchr(pattern, '?') && !strchr(pattern, '*'))
		return kprobe_setattach(kp, pattern, attach);

	if (!G.ksyms) {
		_e("probe wildcards not supported without KALLSYMS support");
		return -ENOSYS;
	}

	for (i = 0; i < G.ksyms->cache->hdr.n_syms; i++) {
		const ksym_t *k = &G.ksyms->cache->sym[i];

		if (fnmatch(pattern, k->sym, 0))
			continue;

		err = kprobe_setattach(kp, k->sym, attach);
		if (err == -EEXIST || err == -ENOENT) {
			_w("'%s' will not be probed: %s", k->sym,
			   err == -EEXIST ? "probe already exists" :
			   "probe not found");
			err = 0;
		}
	}

	return (err < 0) ? err : kp->efds.len;
}

static int kprobe_load(node_t *probe, prog_t *prog, const char *probestring,
		       const char *type, kprobe_t **kpp)
{
	kprobe_t *kp;
	char *func;

	kp = probe_load(BPF_PROG_TYPE_KPROBE, probe, prog);
	if (!kp)
		return -EINVAL;

	kp->type = type;

	kp->ctrl = fopen("/sys/kernel/debug/tracing/kprobe_events", "a+");
	if (!kp->ctrl) {
		_eno("unable to open kprobe_events");
		return -errno;
	}

	*kpp = kp;
	func = strchr(probestring, ':') + 1;
	return kprobe_setattach_pattern(kp, func, 1);
}

static int kprobe_detach(kprobe_t *kp, const char *probestring)
{
	char *func;

	func = strchr(probestring, ':') + 1;

	return kprobe_setattach_pattern(kp, func, 0);
}

const module_t *kprobe_modules[] = {
	&kprobe_module,

	&method_module,
	&common_module,

	NULL
};

int kprobe_default(node_t *probe, node_t **stmts)
{
	node_t *c, *vargs;
	char *fmt;

	if (asprintf(&fmt, "%s:  pid:%%-5d  comm:%%v  func:%%v\n", probe->string) == -1) {
		return -1;
	}
	vargs = node_str_new(fmt);

	c = node_call_new(strdup("common"), strdup("pid"), NULL);
	insque_tail(c, vargs);

	c = node_call_new(strdup("common"), strdup("comm"), NULL);
	insque_tail(c, vargs);

	c = node_call_new(strdup("kprobe"), strdup("func"), NULL);
	insque_tail(c, vargs);

	*stmts = node_call_new(strdup("common"), strdup("printf"), vargs);

	node_foreach(c, *stmts)
		c->parent = probe;

	return 0;
}

static int kprobe_resolve(node_t *call, const func_t **f)
{
	return modules_get_func(kprobe_modules, call, f);
}

static int kprobe_setup(node_t *probe, prog_t *prog)
{
	return kprobe_load(probe, prog, probe->string, "p",
			   (kprobe_t **)&probe->dyn->probe.pvdr_priv);
}

static int kprobe_destroy(kprobe_t *kp, const char *pattern)
{
	int err1, err2;

	/* preserve first error we hit but drive on... */
	err1 = probe_teardown_events(kp);

	/*
	 * we need to detach after closing all event fds relating to probe,
	 * otherwise we cannot remove the associated event from
	 * /sys/kernel/debug/tracing/kprobe_events.
	 */
	err2 = kprobe_detach(kp, pattern);

	fclose(kp->ctrl);

	free(kp);

	return err1 ? err1 : err2;
}

static int kprobe_teardown(node_t *probe)
{
	kprobe_t *kp = probe->dyn->probe.pvdr_priv;

	return kprobe_destroy(kp, probe->string);
}

pvdr_t kprobe_pvdr = {
	.name = "kprobe",
	.desc = "Kernel function entry provider.",

	.dflt    = kprobe_default,
	.resolve = kprobe_resolve,

	.setup      = kprobe_setup,
	.teardown   = kprobe_teardown,
};


const module_t *kretprobe_modules[] = {
	&kretprobe_module,

	&method_module,
	&common_module,

	NULL
};

int kretprobe_default(node_t *probe, node_t **stmts)
{
	node_t *c, *vargs;
	char *fmt;

	if (asprintf(&fmt, "%s:  pid:%%-5d  comm:%%v  retval:%%d\n", probe->string) == -1) {
		return -1;
	}
	vargs = node_str_new(fmt);

	c = node_call_new(strdup("common"), strdup("pid"), NULL);
	insque_tail(c, vargs);

	c = node_call_new(strdup("common"), strdup("comm"), NULL);
	insque_tail(c, vargs);

	c = node_call_new(strdup("kretprobe"), strdup("retval"), NULL);
	insque_tail(c, vargs);

	*stmts = node_call_new(strdup("common"), strdup("printf"), vargs);

	node_foreach(c, *stmts)
		c->parent = probe;

	return 0;
}

static int kretprobe_resolve(node_t *call, const func_t **f)
{
	return modules_get_func(kretprobe_modules, call, f);
}

static int kretprobe_setup(node_t *probe, prog_t *prog)
{
	return kprobe_load(probe, prog, probe->string, "r",
			   (kprobe_t **)&probe->dyn->probe.pvdr_priv);
}

pvdr_t kretprobe_pvdr = {
	.name = "kretprobe",
	.desc = "Kernel function return provider.",

	.dflt    = kretprobe_default,
	.resolve = kretprobe_resolve,

	.setup      = kretprobe_setup,
	.teardown   = kprobe_teardown,
};

/* PROFILE provider */

static int profile_resolve(node_t *call, const func_t **f)
{
        return modules_get_func(kprobe_modules, call, f);
}

static void profile_destroy(profile_t *profile)
{
	int i;

	if (!profile)
		return;

	if (profile->kp)
		kprobe_destroy(profile->kp, "kprobe:perf_swevent_hrtimer");
	for (i = 0; i < profile->num; i++) {
		if (profile->efds[i] > 0)
			close(profile->efds[i]);
	}
	free(profile->efds);
	free(profile);
}

static int profile_teardown(node_t *probe)
{
	profile_t *profile = probe->dyn->probe.pvdr_priv;

	profile_destroy(profile);

	return 0;
}

static int profile_perf_event_open(profile_t *profile, int cpu, int freq)
{
	struct perf_event_attr attr = {};
	int err = 0, i = profile->num;

	attr.type = PERF_TYPE_SOFTWARE;
	attr.config = PERF_COUNT_SW_CPU_CLOCK;
	attr.freq = 1;
	attr.sample_freq = freq;

	profile->efds[i] = perf_event_open(&attr, -1, cpu, -1, 0);
	if (profile->efds[i] < 0)
		return -errno;
	if (ioctl(profile->efds[i], PERF_EVENT_IOC_ENABLE, 0)) {
		close(profile->efds[i]);
		return -errno;
	}
	profile->num++;
	return 0;
}

/*
 * profile provider is implemented by creating a perf event
 * PERF_TYPE_SOFTWARE/PERF_COUNT_SW_CPU_CLOCK for each CPU (or
 * a specified CPU) and using a kprobe on "kprobe:perf_swevent_hrtimer"
 * to catch it occuring in kernel context.
 */
static int profile_setup(node_t *probe, prog_t *prog)
{
	struct perf_event_attr attr = {};
	int cpu = -1, ncpus;
	profile_t *profile;
	char *freqstr;
	int freq = -1;
	int err = 0;

	/*
	 * Expected format is either profile:[n]hz where n is a number between
	 * 1 and 1000, or profile:[c]:[n]hz where c is the CPU to profile.
	 */
	if (sscanf(probe->string, "profile:%dhz", &freq) != 1 &&
	    sscanf(probe->string, "profile:%d:%dhz", &cpu, &freq) != 2)
		return -EINVAL;

	if (freq < 0 || freq > 1000)
		return -EINVAL;

	ncpus = sysconf(_SC_NPROCESSORS_ONLN);

	if (cpu < -1 || cpu > ncpus)
		return -EINVAL;

	if (cpu >= 0)
		ncpus = 1;

	profile = calloc(1, sizeof(*profile));
	if (!profile)
		return -ENOMEM;

	profile->efds = calloc(ncpus, sizeof (int));
	if (!profile->efds) {
		free(profile);
		return -ENOMEM;
	}
	if (cpu != -1)
		err = profile_perf_event_open(profile, cpu, freq);
	else {
		for (cpu = 0; cpu < ncpus; cpu++) {
			err = profile_perf_event_open(profile, cpu, freq);
			if (err)
				goto out;
		}
		profile->num++;
	}

	if (!err)
		err = kprobe_load(probe, prog, "kprobe:perf_swevent_hrtimer",
				  "p", &profile->kp);
out:
	if (err <= 0)
		profile_destroy(profile);
	else
		probe->dyn->probe.pvdr_priv = profile;

	return err;
}

pvdr_t profile_pvdr = {
        .name = "profile",
		.desc = "Profiles with time-based intervals.",

        .resolve = profile_resolve,

        .setup = profile_setup,
        .teardown = profile_teardown,
};

static int uprobe_load(node_t *probe, prog_t *prog, const char *type,
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

static int uprobe_setup(node_t *probe, prog_t *prog)
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

static int uretprobe_setup(node_t *probe, prog_t *prog)
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

/* Register Proiver */
__attribute__((constructor))
static void kprobe_pvdr_register(void)
{
	pvdr_register(   &kprobe_pvdr);
	pvdr_register(&kretprobe_pvdr);
	pvdr_register(  &profile_pvdr);
	pvdr_register(   &uprobe_pvdr);
	pvdr_register(&uretprobe_pvdr);
}
