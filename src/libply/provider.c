/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <ply/ply.h>
#include <ply/provider.h>

SLIST_HEAD(provider_list, provider);
static struct provider_list heads = SLIST_HEAD_INITIALIZER(heads);

/* supported providers */
extern struct provider kprobe;
extern struct provider kretprobe;
extern struct provider tracepoint;
extern struct provider built_in;
extern struct provider begin_provider;
extern struct provider end_provider;
extern struct provider interval;
extern struct provider profile;

struct provider *provider_get(const char *name)
{
	struct provider *p;
	char *search;

	search = strtok(strdup(name), ":");

	SLIST_FOREACH(p, &heads, entry) {
 		if (strstr(p->name, search) == p->name)
			break;
	}

	free(search);
	return p;
}

void provider_init(void)
{
	SLIST_INSERT_HEAD(&heads, &end_provider, entry);
	SLIST_INSERT_HEAD(&heads, &begin_provider, entry);
	SLIST_INSERT_HEAD(&heads, &built_in, entry);
	SLIST_INSERT_HEAD(&heads, &interval, entry);
	SLIST_INSERT_HEAD(&heads, &profile, entry);
	SLIST_INSERT_HEAD(&heads, &tracepoint, entry);
	SLIST_INSERT_HEAD(&heads, &kretprobe, entry);
	/* place kprobe at head so that 'k' can match first. */
	SLIST_INSERT_HEAD(&heads, &kprobe, entry);
}
