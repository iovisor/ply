/*
 * Copyright  Ism Hong <ism.hong@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <ply/ply.h>
#include <ply/internal.h>


struct profile_data {
	int cpu;
	int ncpus;
	unsigned long long freq;
	int *evfds;
};

static int profile_sym_alloc(struct ply_probe *pb, struct node *n)
{
	return -ENOENT;
}

static int profile_probe(struct ply_probe *pb)
{
	int cpu = -1, ncpus = 0;
	struct profile_data *data;
	int freq = -1;

	/*
	 * Expected format is either profile:[n]hz where n is a number between
	 * 1 and 1000, or profile:[c]:[n]hz where c is the CPU to profile.
	 */
	if (sscanf(pb->probe, "profile:%d:%dhz", &cpu, &freq) != 2) {
		cpu = -1;
		if (sscanf(pb->probe, "profile:%dhz", &freq) != 1)
			return -EINVAL;
	}

	if (freq < 0 || freq > 1000)
		return -EINVAL;

	ncpus = sysconf(_SC_NPROCESSORS_ONLN);

	if (cpu < -1 || cpu > ncpus)
		return -EINVAL;

	if (cpu >= 0)
		ncpus = 1;

	data = calloc(1, sizeof(*data));
	if (!data)
		return -ENOMEM;

	data->evfds = calloc(ncpus, sizeof (int));
	if (!data->evfds) {
		free(data);
		return -ENOMEM;
	}

	data->freq = (unsigned long long)freq;
	data->cpu = cpu;
	data->ncpus = ncpus ;

	pb->provider_data = data;
	return 0;
}

static int profile_attach(struct ply_probe *pb)
{
	struct profile_data *data = pb->provider_data;
	int cpu;

	if (data->cpu != -1) {
		data->evfds[0] = perf_event_attach_profile(pb, data->cpu,
						 data->freq);
		if (data->evfds[0] < 0) {
			_e("%s: Unable to attach profile probe: %s\n",
			   pb->probe, strerror(errno));
			return data->evfds[0];
		}
	} else {
		for (cpu = 0; cpu < data->ncpus; cpu++) {
			data->evfds[cpu] = perf_event_attach_profile(pb, cpu, data->freq);
			if (data->evfds[cpu] < 0) {
				_e("%s: Unable to attach profile probe: %s\n",
						pb->probe, strerror(errno));
				return data->evfds[cpu];
			}
		}
	}

	return 0;
}

static int profile_detach(struct ply_probe *pb)
{
	struct profile_data *data = pb->provider_data;

	for (int i = 0; i < data->ncpus; i++) {
		if (data->evfds[i] > 0)
			close(data->evfds[i]);
	}
	free(data->evfds);
	free(data);

	return 0;
}

struct provider profile = {
	.name = "profile",
	.prog_type = BPF_PROG_TYPE_PERF_EVENT,

	.sym_alloc = profile_sym_alloc,
	.probe 	   = profile_probe,

	.attach = profile_attach,
	.detach = profile_detach,
};
