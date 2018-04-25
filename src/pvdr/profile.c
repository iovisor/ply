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
 * PROFILE provider
 * 
 * The profile provider provides probes associated with a time-based interrupt 
 * firing every fixed, specified time interval.
 * 
 * profile provider is implemented by creating a perf event
 * PERF_TYPE_SOFTWARE/PERF_COUNT_SW_CPU_CLOCK for each CPU (or
 * a specified CPU) and using a kprobe on "kprobe:perf_swevent_hrtimer"
 * to catch it occuring in kernel context.
 * 
 * Expected format is either profile:[n]hz where n is a number between
 * 1 and 1000, or profile:[c]:[n]hz where c is the CPU to profile.
 * 
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

typedef struct profile {
	int *efds;
	int num;
	kprobe_t *kp;
} profile_t;

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
	return err;
}


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

/* Register Provider */
__attribute__((constructor))
static void profile_pvdr_register(void)
{
	pvdr_register(&profile_pvdr);
}