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

#include <errno.h>
#include <string.h>

#include <ply/ply.h>
#include <ply/pvdr.h>

TAILQ_HEAD(pvdrs, pvdr);
static struct pvdrs pvdr_list = TAILQ_HEAD_INITIALIZER(pvdr_list);

/*
 * pvdr_print - Print available providers and their short description
 */
int 
pvdr_print(void)
{
	pvdr_t *pvdr;
	int err = 0;
	
	printf("%20s %s\n", "PROVIDER", "DESCRIPTION");
	TAILQ_FOREACH(pvdr, &pvdr_list, node) {
		printf("%20s %s\n", pvdr->name, pvdr->desc);
	}

	return err;
}

/* 
 * pvdr_find - Find a provider in the registered list
 */
pvdr_t *pvdr_find(const char *pspec)
{
	pvdr_t *pvdr;
	char *colon;

	colon = strchr(pspec, ':');
	if (!colon)
		return NULL;
	
	TAILQ_FOREACH(pvdr, &pvdr_list, node) {
		if (!strncmp(pvdr->name, pspec, colon - pspec))
			return pvdr;
	}

	return NULL;
}

int pvdr_resolve_call(node_t *call, void *_probe)
{
	node_t *probe = _probe;
	pvdr_t *pvdr = probe->dyn->probe.pvdr;
	int err;

	if (call->type != TYPE_CALL)
		return 0;

	err = pvdr->resolve(call, &call->dyn->call.func);
	if (err)
		_e("in '%s', unknown function '%s'",
		   probe->string, call->string);

	return err;
}

int pvdr_resolve(node_t *script)
{	
	node_t *probe;
	pvdr_t *pvdr;
	int err;

	for (probe = script->script.probes; probe; probe = probe->next) {
		pvdr = pvdr_find(probe->string);
		if (!pvdr) {
			_e("no provider matching '%s'", probe->string);
			return -ENOENT;
		}

		if (!probe->probe.stmts) {
			if (!pvdr->dflt) {
				_e("no default probe available for '%s'\n",
				   probe->string);
				return -EINVAL;
			}

			err = pvdr->dflt(probe, &probe->probe.stmts);
			if (err)
				return err;
		}

		probe->dyn->probe.pvdr = pvdr;
		err = node_walk(probe, pvdr_resolve_call, NULL, probe);
		if (err)
			return err;
	}

	return 0;
}

void pvdr_register(pvdr_t *pvdr)
{
	TAILQ_INSERT_TAIL(&pvdr_list, pvdr, node);
}
