/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <string.h>

#include <ply/ply.h>
#include <ply/internal.h>

struct tracepoint {
	struct func data_func;	

	char *path;
	int evfd;
};

static int tracepoint_data_ir_post(const struct func *func, struct node *n,
				   struct ply_probe *pb)
{
	struct node *ctx = n->expr.args;

	n->sym->irs = ctx->sym->irs;
	return 0;
}

static int tracepoint_data_rewrite(const struct func *func, struct node *n,
				   struct ply_probe *pb)
{
	node_expr_append(&n->loc, n, node_expr(&n->loc, "ctx", NULL));
	return 0;
}

static const struct func tracepoint_data_func = {
	/* This a template - the type will be specific to each
	 * tracepoint and will be generated dynamically. */
	.name = "data",
	.static_ret = 1,

	.rewrite = tracepoint_data_rewrite,
	.ir_post = tracepoint_data_ir_post,
};

static int tracepoint_sym_alloc(struct ply_probe *pb, struct node *n)
{
	struct tracepoint *tp = pb->provider_data;
	const struct func *func = NULL;
	int err;

	switch (n->ntype) {
	case N_EXPR:
		if (!strcmp(n->expr.func, "data")) {
			func = &tp->data_func;
			n->expr.ident = 1;
		}
		break;
	default:
		break;
	}

	if (!func)
		return -ENOENT;

	err = func_static_validate(func, n);
	if (err)
		return err;

	n->sym = sym_alloc(&pb->locals, n, func);

	if (func->static_ret)
		n->sym->type = func_return_type(func);
	return 0;
}

static struct type *tracepoint_parse_type(const char *str, unsigned long size,
					  unsigned long sign)
{
	int explicit_sign = 1;

	if (!strncmp(str, "signed ", sizeof("signed")))
		str += sizeof("signed");
	else if (!strncmp(str, "unsigned ", sizeof("unsigned")))
		str += sizeof("unsigned");
	else
		explicit_sign = 0;

	/* Find all basic scalars. */
	if (!strcmp(str, "char"))
		return explicit_sign ? (sign ? &t_schar : &t_uchar) : &t_char;
	else if (!strcmp(str, "short"))
		return explicit_sign ? (sign ? &t_sshort : &t_ushort) : &t_short;
	else if (!strcmp(str, "int"))
		return explicit_sign ? (sign ? &t_sint : &t_uint) : &t_int;
	else if (!strcmp(str, "long"))
		return explicit_sign ? (sign ? &t_slong : &t_ulong) : &t_long;
	else if (!strcmp(str, "long long"))
		return explicit_sign ? (sign ? &t_sllong : &t_ullong) : &t_llong;

	/* Fallback to {u,s}{8,16,32,64} for all other cases. */
	switch (size) {
	case 1:
		return sign ? &t_s8 : &t_u8;
	case 2:
		return sign ? &t_s16 : &t_u16;
	case 4:
		return sign ? &t_s32 : &t_u32;
	case 8:
		return sign ? &t_s64 : &t_u64;
	}

	/* TODO: We should probably mark pointers as such, rather than
	 * treating it as a u32/u64. */
	return NULL;
}

static ssize_t tracepoint_parse_field(char *line, struct tfield *f)
{
	char *type, *name, *array, *offs_s, *size_s, *sign_s, *save;
	unsigned long offs, size, sign, len = 0;
	struct type *t;

	type   = strtok_r(line, ";", &save);
	offs_s = strtok_r(NULL, ";", &save);
	size_s = strtok_r(NULL, ";", &save);
	sign_s = strtok_r(NULL, ";", &save);
	if (!(type && offs_s && size_s && sign_s))
		return -EINVAL;

	type   += sizeof("field:");
	offs_s += sizeof("offset:");
	size_s += sizeof("size:");
	sign_s += sizeof("signed:");

	offs = strtoul(offs_s, NULL, 0);
	size = strtoul(size_s, NULL, 0);
	sign = strtoul(sign_s, NULL, 0);
	if ((offs == ULONG_MAX) || (size == ULONG_MAX) || (sign == ULONG_MAX))
		return -EINVAL;

	name = rindex(type, ' ');
	*name++ = '\0';

	array = index(name, '[');
	if (array) {
		*array++ = '\0';
		len = strtoul(array, NULL, 0);
		if (len == ULONG_MAX)
			return -EINVAL;

		size /= len;
	}

	/* _d("type:%s name:%s len:%lu offs:%lu size:%lu sign:%lu\n", */
	/*    type, name, len, offs, size, sign); */

	t = tracepoint_parse_type(type, size, sign);
	if (!t)
		return -EINVAL;

	f->name = strdup(name);
	f->type = len ? type_array_of(t, len) : t;
	return offs;
	
}

static int tracepoint_parse(struct ply_probe *pb)
{
	struct tracepoint *tp = pb->provider_data;
	struct type *t = tp->data_func.type->ptr.type;
	FILE *fmt;
	char line[0x80];
	ssize_t offs;
	int n = 0;

	fmt = fopenf("r", "%s/format", tp->path);
	if (!fmt)
		return -ENOENT;

	while (fgets(line, sizeof(line), fmt)) {
		if (!strstr(line, "field:"))
			continue;

		t->sou.fields = realloc(t->sou.fields,
					sizeof(*t->sou.fields)*(++n));
		assert(t->sou.fields);

		offs = tracepoint_parse_field(line, &t->sou.fields[n - 1]);
		if (offs < 0) {
			free(t->sou.fields);
			return offs;
		}

		assert(offs == type_offsetof(t, t->sou.fields[n - 1].name));
	}

	t->sou.fields = realloc(t->sou.fields, sizeof(*t->sou.fields)*(++n));
	t->sou.fields[n -1] = (struct tfield) { .name = NULL, .type = NULL };

	return 0;
}

static int tracepoint_attach(struct ply_probe *pb)
{
	struct tracepoint *tp = pb->provider_data;

	tp->evfd = perf_event_attach(pb, tp->path, 0);
	if (tp->evfd < 0)
		return tp->evfd;

	return 0;
}

static int tracepoint_detach(struct ply_probe *pb)
{
	return 0;
}

static int tracepoint_probe(struct ply_probe *pb)
{
	struct tracepoint *tp;
	struct type *data_t, *datap_t;
	const char *name;
	size_t pathsz;
	FILE *fp;
	int err;

	tp = xcalloc(1, sizeof(*tp));
	pb->provider_data = tp;

	name = strchr(pb->probe, ':');
	assert(name);
	name++;

	fp = open_memstream(&tp->path, &pathsz);
	fprintf(fp, TRACEPATH "events/%s", name);
	fclose(fp);

	tp->data_func = tracepoint_data_func;

	data_t  = xcalloc(1, sizeof(*data_t));
	*data_t = (struct type) {
		.ttype = T_STRUCT,
		.sou = { .name = "data" },
	};

	datap_t = xcalloc(1, sizeof(*datap_t));
	*datap_t = (struct type) {
		.ttype = T_POINTER,
		.ptr = { .type = data_t, .bpf = 1 },
	};

	tp->data_func.type = datap_t;

	err = tracepoint_parse(pb);
	if (err) {
		_e("%s: Unable to parse tracepoint at %s\n",
		   pb->probe, tp->path);
		goto err_free;
	}
	return 0;

err_free:

	free(tp->data_func.type->ptr.type);
	free(tp->data_func.type);
	free(tp->path);
	free(tp);
	return err;
}

struct provider tracepoint = {
	.name = "tracepoint",
	.prog_type = BPF_PROG_TYPE_TRACEPOINT,

	.sym_alloc = tracepoint_sym_alloc,
	.probe     = tracepoint_probe,

	.attach = tracepoint_attach,
	.detach = tracepoint_detach,
};
