/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include <ply/ply.h>
#include <ply/internal.h>

#include "built-in.h"

SLIST_HEAD(built_in_list, func);
static struct built_in_list heads = SLIST_HEAD_INITIALIZER(heads);

static struct type t_ctx = {
	.ttype = T_POINTER,

	.ptr = {
		.type = &t_void,

		/* 'ctx' is a pointer, but the kernel verifier will
		 * mark 32-bit accesses as invalid even on 32-bit
		 * ISAs, so we always treat it as a 64-bit pointer */
		 .bpf = 1,
	},
};

static struct func ctx_func = {
	.name = "ctx",
	.type = &t_ctx,
	.static_ret = 1,
};


static struct type *num_type(struct node *n)
{
	switch (n->num.size) {
	case 8:
		return n->num.unsignd ? &t_u64 : &t_s64;
	case 4:
		return n->num.unsignd ? &t_u32 : &t_s32;
	case 0:
		break;
	default:
		assert(0);
	}
	if (n->num.unsignd) {
		if (n->num.u64 <= INT_MAX)
			return &t_int;
		else if (n->num.u64 <= UINT_MAX)
			return &t_uint;
		else if (n->num.u64 <= LONG_MAX)
			return &t_long;
		else if (n->num.u64 <= ULONG_MAX)
			return &t_ulong;
		else if (n->num.u64 <= LLONG_MAX)
			return &t_llong;
		else if (n->num.u64 <= ULLONG_MAX)
			return &t_ullong;
	} else {
		if (n->num.s64 >= INT_MIN && n->num.s64 <= INT_MAX)
			return &t_int;
		else if (n->num.s64 >= LONG_MIN && n->num.s64 <= LONG_MAX)
			return &t_long;
		else if (n->num.s64 >= LLONG_MIN && n->num.s64 <= LLONG_MAX)
			return &t_llong;
	}

	assert(0);
	return NULL;
}

static int num_ir_post(const struct func *func, struct node *n,
		       struct ply_probe *pb)
{
	struct irstate *irs = &n->sym->irs;

	if ((n->num.unsignd && (n->num.u64 <= INT32_MAX)) ||
	    (n->num.s64 >= INT32_MIN && n->num.s64 <= INT32_MAX)) {
		irs->loc = LOC_IMM;
		irs->imm = n->num.s64;
		irs->size = type_sizeof(n->sym->type);
		return 0;
	}

	/* we need to load the constant to a register, so ignore any
	 * advise about stack allocation. */
	irs->hint.stack = 0;

	ir_init_sym(pb->ir, n->sym);

	/* use special instruction pair to load 64-bit immediate to
	 * register. second instruction is a dummy except for the
	 * upper 32 bits of the immediate. */
	ir_emit_insn(pb->ir, LDDW_IMM((uint32_t)n->num.u64), irs->reg, 0);
	ir_emit_insn(pb->ir, INSN(0, 0, 0, 0, n->num.u64 >> 32), 0, 0);
	return 0;
}

static const struct func num_func = {
	.name = ":num",

	.ir_post = num_ir_post,	
};


static struct type *string_type(struct node *n)
{
	size_t len = ((strlen(n->string.data) ? : 1) + 7) & ~7;

	return type_array_of(&t_char, len);
}

static int string_ir_post(const struct func *func, struct node *n,
				 struct ply_probe *pb)
{
	struct irstate *irs = &n->sym->irs;

	if (n->string.virtual)
		return 0;

	ir_init_sym(pb->ir, n->sym);

	ir_emit_data(pb->ir, irs->stack, n->string.data,
		     type_sizeof(n->sym->type));
	return 0;
}

static const struct func string_func = {
	.name = ":string",

	.ir_post = string_ir_post,	
};


static int env_rewrite(const struct func *func, struct node *n,
		       struct ply_probe *pb)
{
	struct node *new;
	const char *val;
	int64_t num;
	char *end;

	val = getenv(n->expr.func + 1);
	if (!val || !val[0])
		goto string;

	errno = 0;
	num = strtoll(val, &end, 0);
	if (!errno && !*end) {
		new = node_num(&n->loc, strdup(val));
	} else {
	string:
		new = node_string(&n->loc, strdup(val ? : ""));
	}

	node_replace(n, new);
	return 1;
}

static const struct func env_func = {
	.name = ":env",
	.type = &t_void,
	.static_ret = 1,

	.rewrite = env_rewrite,
};


static int ident_ir_post(const struct func *func, struct node *n,
			 struct ply_probe *pb)
{
	if (n->sym->type->ttype == T_MAP && !n->sym->irs.hint.lval) {
		struct irstate *irs = &n->sym->irs;

		irs->hint.stack = 1;
		ir_init_sym(pb->ir, n->sym);

		/*
		 * It'd be nice if we can save the map fd to a register
		 * and then move it to the stack for the symbol.
		 * But it was rejected by the kernel:
		 *
		 *   error: output from kernel bpf verifier:
		 *   0: (bf) r6 = r1
		 *   1: (18) r1 = 0xffff9271503e5400
		 *   3: (63) *(u32 *)(r10 -4) = r1
		 *   invalid size of register spill
		 *
		 * Actually, it doesn't matter which value we pass it
		 * to the (async) print.  All we need is a type info
		 * and it's provided already.
		 *
		 * So let's just fill it by zero.
		 */
		ir_emit_insn(pb->ir, ST_IMM(bpf_width(irs->size), irs->stack, 0),
			     BPF_REG_BP, 0);
	}

	return 0;
}

static const struct func ident_func = {
	.name = ":ident",

	.ir_post = ident_ir_post,
};


static struct func block_func = {
	.name = "{}",
	.type = &t_vargs_func,
	.static_ret = 1,
};


static const struct func *built_in_func_get(struct node *n)
{
	const struct func *func;
	int err;

	SLIST_FOREACH(func, &heads, entry) {
		if (!strcmp(func->name, n->expr.func))
			return func;
	}

	return NULL;
}

static int built_in_sym_alloc(struct ply_probe *pb, struct node *n)
{
	const struct func *func = NULL;
	int err;

	switch (n->ntype) {
	case N_EXPR:
		func = built_in_func_get(n);
		if (func)
			break;

		if (!n->expr.args) {
			switch (n->expr.func[0]) {
			case '$':
				func = &env_func;
				break;
			default:
				n->expr.ident = 1;
				func = &ident_func;
			}
		}
		break;
	case N_NUM:
		func = &num_func;
		break;
	case N_STRING:
		func = &string_func;
		break;
	}

	if (!func)
		return -ENOENT;

	err = func_static_validate(func, n);
	if (err)
		return err;

	if (func == &ctx_func) {
		n->expr.ident = 1;
		n->sym = sym_alloc(&pb->locals, n, func);
	} else {
		n->sym = sym_alloc(&pb->ply->globals, n, func);
	}

	/* infer statically known types early */
	if (n->ntype == N_NUM)
		n->sym->type = num_type(n);
	else if (n->ntype == N_STRING)
		n->sym->type = string_type(n);
	else if (func->static_ret)
		n->sym->type = func_return_type(func);
	return 0;
}

static int built_in_probe(struct ply_probe *pb)
{
	return 0;
}

int built_in_ir_pre(struct ply_probe *pb)
{
	struct sym **sym;

	symtab_foreach(&pb->locals, sym) {
		if ((*sym)->name && (*sym)->func == &ctx_func) {
			ir_init_sym(pb->ir, *sym);

			/* Kernel sets r1 to the address of the probe
			 * context (i.e. a struct pt_regs for
			 * {k,u}probes etc.). If we're using it we
			 * need to get a reference to it before it is
			 * clobbered. */
			ir_emit_reg_to_sym(pb->ir, *sym, BPF_REG_1);
		}
	}

	return 0;
}

struct provider built_in = {
	.name = "!built-in",

	.sym_alloc = built_in_sym_alloc,
	.probe = built_in_probe,

	.ir_pre = built_in_ir_pre,

};

void built_in_register(struct func *func)
{
	SLIST_INSERT_HEAD(&heads, func, entry);
}

void built_in_init(void)
{
	built_in_register(&ctx_func);
	built_in_register(&block_func);

	aggregation_init();
	buffer_init();
	flow_init();
	math_init();
	memory_init();
	print_init();
	proc_init();
}
