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

#ifndef _PROVIDER_H
#define _PROVIDER_H

#include <sys/queue.h>

#include <ply/ast.h>
#include <ply/compile.h>
#include <ply/module.h>
typedef struct pvdr {
	TAILQ_ENTRY(pvdr) node;

	const char *name;	/* Name of provider */
	const char *desc; 	/* Short description */

	int    (*dflt)(node_t *probe, node_t **stmts);
	int (*resolve)(node_t *call, const func_t **f);

  	int    (*setup)(node_t *probe, prog_t *prog);
	int (*teardown)(node_t *probe);
} pvdr_t;

int 	pvdr_print	 (void);
pvdr_t *pvdr_find    (const char *name);
int     pvdr_resolve (node_t *script);
void    pvdr_register(pvdr_t *pvdr);

void printf_drain     (node_t *script);
int  printf_compile   (node_t *call, prog_t *prog);
int  printf_loc_assign(node_t *call);
int  printf_annotate  (node_t *call);

#endif	/* _PROVIDER_H */
