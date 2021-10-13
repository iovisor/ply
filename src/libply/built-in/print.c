/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <assert.h>
#include <errno.h>
#include <string.h>

#include <ply/ply.h>
#include <ply/internal.h>

#include "built-in.h"

struct printf_evh {
	const char *fmt;
	struct node *n;

	struct buffer_evh evh;
};

struct printf_data {
	struct type *t;
	struct tfield *f;
	void *data;
};

union value {
	char c;
	signed char sc;
	unsigned char uc;
	signed short ss;
	unsigned short us;
	signed int si;
	unsigned int ui;
	signed long sl;
	unsigned long ul;
	signed long long sll;
	unsigned long long ull;
	intmax_t smax;
	uintmax_t umax;
	ssize_t ssz;
	size_t sz;
	ptrdiff_t diff;
	double d;
	long double ld;
	uintptr_t ptr;
	char str[0];
};

int printf_int(FILE *fp, const char *spec, const char *type, union value *val)
{
	int unsignd = strspn(type, "ouxX");

	switch (*(type - 1)) {
	case 'h':
		if (*(type - 2) == 'h') {
			if (unsignd)
				return fprintf(fp, spec, val->uc);
			else
				return fprintf(fp, spec, val->sc);
		} else {
			if (unsignd)
				return fprintf(fp, spec, val->us);
			else
				return fprintf(fp, spec, val->ss);
		}
	case 'j':
		if (unsignd)
			return fprintf(fp, spec, val->umax);
		else
			return fprintf(fp, spec, val->smax);
	case 'l':
		if (*(type - 2) == 'l') {
		longlong:
			if (unsignd)
				return fprintf(fp, spec, val->ull);
			else
				return fprintf(fp, spec, val->sll);
		} else {
			if (unsignd)
				return fprintf(fp, spec, val->ul);
			else
				return fprintf(fp, spec, val->sl);
		}
	case 'q':
		goto longlong;
	case 't':
		return fprintf(fp, spec, val->diff);
	case 'z':
		if (unsignd)
			return fprintf(fp, spec, val->sz);
		else
			return fprintf(fp, spec, val->ssz);
	default:
		if (unsignd)
			return fprintf(fp, spec, val->ui);
		else
			return fprintf(fp, spec, val->si);
	}

	assert(0);
	return 0;
}

int printf_float(FILE *fp, const char *spec, const char *type, union value *val)
{
	switch (*(type - 1)) {
	case 'L':
		return fprintf(fp, spec, val->ld);
	default:
		return fprintf(fp, spec, val->d);
	}

	assert(0);
	return 0;
}

int printf_xfprintxf(struct printxf *pxf,
		     FILE *fp, const char *spec, void *_pd)
{
	struct printf_data *pd = _pd;
	const char *type;
	union value *val;
	size_t size;
	int ret = -ENOSYS;

	if (!pd->f->type)
		return fputs(spec, fp);

	/* We copy the value to ensure aligned access for all widths,
	 * not all CPUs handle unaligned accesses gracefully. Always
	 * allocate at least enough space to fit a long long, in case
	 * the user does something like printf("%lld\n", (char)i). */
	size = max((ssize_t)sizeof(*val), type_sizeof(pd->f->type));

	/* Allocate an extra NUL byte to ensure that any value can
	 * safely be interpreted as string. */
	val = xcalloc(1, size + 1);
	memcpy(val, pd->data + type_offsetof(pd->t, pd->f->name), size);

	for (type = spec; *(type + 1); type++);

	switch (*type) {
	case 'c':
		ret = fprintf(fp, spec, val->c);
		break;
	case 'p':
		ret = fprintf(fp, spec, (void *)val->ptr);
		break;
	case 's':
		ret = fprintf(fp, spec, val->str);
		break;
	case 'v':
		ret = type_fprint(pd->f->type, fp, val->str);
		break;

	case 'd':
	case 'i':
	case 'o':
	case 'u':
	case 'x': case 'X':
		ret = printf_int(fp, spec, type, val);
		break;
	case 'a': case 'A':
	case 'e': case 'E':
	case 'f': case 'F':
	case 'g': case 'G':
		ret = printf_float(fp, spec, type, val);
		break;
	default:
		ret = fputs(spec, fp);
	}

	free(val);

	pd->f++;
	return ret;
}

struct printxf printf_printxf = {
	.xfprintxf = {
		['a'] = printf_xfprintxf, ['A'] = printf_xfprintxf,
		['c'] = printf_xfprintxf, ['d'] = printf_xfprintxf,
		['e'] = printf_xfprintxf, ['E'] = printf_xfprintxf,
		['f'] = printf_xfprintxf, ['F'] = printf_xfprintxf,
		['g'] = printf_xfprintxf, ['G'] = printf_xfprintxf,
		['i'] = printf_xfprintxf, ['o'] = printf_xfprintxf,
		['p'] = printf_xfprintxf, ['s'] = printf_xfprintxf,
		['u'] = printf_xfprintxf, ['v'] = printf_xfprintxf,
		['x'] = printf_xfprintxf, ['X'] = printf_xfprintxf,
	},
};

static struct ply_return printf_ev_handler(struct buffer_ev *ev, void *_pevh)
{
	struct printf_evh *pevh = _pevh;

	if (!pevh->n) {
		fputs(pevh->fmt, stdout);
	} else {
		struct printf_data pd = {
			.t = pevh->n->sym->type,
			.f = pevh->n->sym->type->sou.fields,
			.data = ev->data,
		};

		xfprintxf(&printf_printxf, stdout, pevh->fmt, &pd);
	}

	return (struct ply_return){ };
}

static int printf_rewrite(const struct func *func, struct node *n,
			struct ply_probe *pb)
{
	struct node *bwrite, *exprs, *ev;
	struct printf_evh *pevh;
	uint64_t id;

	pevh = n->sym->priv;
	id = pevh->evh.id;

	exprs = n->expr.args->next;
	n->expr.args->next = NULL;

	ev = node_expr(&n->loc, ":struct",
		       __node_num(&n->loc, sizeof(pevh->evh.id), NULL, &id),
		       exprs ? node_expr(&n->loc, ":struct", exprs, NULL) : NULL,
		       NULL);

	bwrite = node_expr(&n->loc, "bwrite",
			   node_expr(&n->loc, "ctx", NULL),
			   node_expr(&n->loc, "stdbuf", NULL),
			   ev,
			   NULL);

	node_replace(n, bwrite);

	pevh->n = ev->expr.args->next;
	return 1;
}

static int printf_type_infer(const struct func *func, struct node *n)
{
	struct node *expr = n->expr.args;
	struct printf_evh *pevh;

	if (n->sym->type)
		return 0;

	if (!n->expr.args) {
		_ne(n, "format specifier missing.\n");
		return -EINVAL;
	}

	if (n->expr.args->ntype != N_STRING) {
		_ne(n, "format specifier must be a string literal.\n");
		return -EINVAL;
	}

	n->expr.args->string.virtual = 1;

	pevh = xcalloc(1, sizeof(*pevh));

	pevh->evh.handle = printf_ev_handler;
	pevh->evh.priv = pevh;
	buffer_evh_register(&pevh->evh);

	pevh->fmt = n->expr.args->string.data;

	/* TODO: leaked */
	n->sym->priv = pevh;
	n->sym->type = &t_void;
	return 0;
}

static struct func printf_func = {
	.name = "printf",
	.type = &t_vargs_func,
	.type_infer = printf_type_infer,

	.rewrite = printf_rewrite,
};

struct print_ev_data {
	struct node *n;
	struct ply *ply;
};

static struct ply_return print_ev_handler(struct buffer_ev *ev, void *_n)
{
	struct print_ev_data *data = _n;
	struct node *n = data->n;
	struct type *t = n->sym->type;
	struct tfield *f;

	tfields_foreach(f, t->sou.fields) {
		if (f != t->sou.fields)
			fputs(", ", stdout);

		if (f->type->ttype == T_MAP) {
			type_fprint(f->type, stdout, data->ply);
			continue;
		}

		type_fprint(f->type, stdout,
			    ev->data + type_offsetof(t, f->name));
	}

	putchar('\n');
	return (struct ply_return){ };
}

static int print_rewrite(const struct func *func, struct node *n,
			struct ply_probe *pb)
{
	struct node *bwrite, *exprs, *ev;
	struct buffer_evh *evh;
	struct print_ev_data *data;
	uint64_t id;

	evh = n->sym->priv;
	id = evh->id;

	exprs = n->expr.args;
	n->expr.args = NULL;

	ev = node_expr(&n->loc, ":struct",
		       __node_num(&n->loc, sizeof(evh->id), NULL, &id),
		       node_expr(&n->loc, ":struct", exprs, NULL),
		       NULL);

	bwrite = node_expr(&n->loc, "bwrite",
			   node_expr(&n->loc, "ctx", NULL),
			   node_expr(&n->loc, "stdbuf", NULL),
			   ev,
			   NULL);

	node_replace(n, bwrite);

	data = malloc(sizeof(*data));
	if (data == NULL)
		return -1;

	data->n = ev->expr.args->next;
	data->ply = pb->ply;

	/* TODO: leaked */
	evh->priv = data;
	return 1;
}

static int print_type_infer(const struct func *func, struct node *n)
{
	struct buffer_evh *evh;

	if (n->sym->type)
		return 0;

	evh = xcalloc(1, sizeof(*evh));

	evh->handle = print_ev_handler;
	buffer_evh_register(evh);

	/* TODO: leaked */
	n->sym->priv = evh;
	n->sym->type = &t_void;
	return 0;
}

static struct func print_func = {
	.name = "print",
	.type = &t_vargs_func,
	.type_infer = print_type_infer,

	.rewrite = print_rewrite,
};

void print_init(void)
{
	built_in_register(&printf_func);
	built_in_register(&print_func);
}
