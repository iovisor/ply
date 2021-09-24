/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef _PLY_H
#define _PLY_H

#include <stdio.h>

#include "sym.h"
#include "utils.h"

struct ksyms;
struct ply;
struct node;
struct ir;

struct ply_return {
	int val;
	unsigned err:1;
	unsigned exit:1;
};

/* api */
struct ply_probe {
	struct ply_probe *next, *prev;
	struct ply *ply;

	char *probe;
	struct node *ast;

	struct symtab locals;

	struct provider *provider;
	void *provider_data;

	struct ir *ir;
	int bpf_fd;
	int special;
};

struct ply_config {
	size_t map_elems;
	size_t string_size;
	size_t buf_pages;   /* number of memory pages, per-cpu, per buffer */
	size_t stack_depth;

	unsigned unicode:1; /* allow unicode in output. */
	unsigned hex:1;	    /* prefer hexadecimal output for scalars. */
	unsigned sort:1;    /* sort maps before output, requires more memory. */
	unsigned ksyms:1;   /* create ksyms cache. */
	unsigned strict:1;  /* abort on error. */
	unsigned verify:1;  /* capture verifier output, uses 16M of memory. */
};

extern struct ply_config ply_config;

struct ply {
	struct sym *stdbuf;

	struct ply_probe *probes;
	struct symtab globals;
	struct ksyms *ksyms;

	char *group;
	int   group_fd;
};

#define ply_probe_foreach(_ply, _probe)					\
	for ((_probe) = (_ply)->probes;	(_probe); (_probe) = (_probe)->next)

static inline struct ply_probe *sym_to_probe(struct sym *sym)
{
	if (sym->st->global)
		return NULL;

	return container_of(sym->st, struct ply_probe, locals);
}

void ply_maps_print(struct ply *ply);

struct ply_return ply_loop(struct ply *ply);

int ply_start(struct ply *ply);
int ply_stop(struct ply *ply);

int ply_load(struct ply *ply);
int ply_unload(struct ply *ply);

int ply_add_probe(struct ply *ply, struct ply_probe *probe);
int ply_compile(struct ply *ply);


int  ply_fparse(struct ply *ply, FILE *fp);
int  ply_parsef(struct ply *ply, const char *fmt, ...);
void ply_free  (struct ply *ply);
int  ply_alloc (struct ply **plyp);

typedef void (*special_probe_t)(void);

void ply_init(special_probe_t begin, special_probe_t end);

#endif	/* _PLY_H */
