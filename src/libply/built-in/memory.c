/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <assert.h>
#include <errno.h>

#include <ply/ply.h>
#include <ply/internal.h>

#include "built-in.h"

static void strcmp_emit(struct ir *ir, uint16_t dst,
			ssize_t a, ssize_t b, const char *blit, size_t len)
{
	int16_t done;
	int literal = blit ? 1 : 0;

	done = ir_alloc_label(ir);

	for (; len; len--, a++, b++, blit++) {
		ir_emit_insn(ir, LDX(BPF_B, a), dst, BPF_REG_BP);

		if (literal) {
			ir_emit_insn(ir, ALU_IMM(BPF_SUB, *blit), dst, 0);
		} else {
			ir_emit_insn(ir, LDX(BPF_B, b), BPF_REG_1, BPF_REG_BP);
			ir_emit_insn(ir, ALU(BPF_SUB), dst, BPF_REG_1);
		}

		if (len == 1)
			break;

		if (!literal)
			ir_emit_insn(ir, JMP_IMM(BPF_JEQ, 0, done), BPF_REG_1, 0);
		else if (!*blit)
			break;

		ir_emit_insn(ir, JMP_IMM(BPF_JNE, 0, done), dst, 0);
	}

	ir_emit_label(ir, done);
}

static int strcmp_ir_post(const struct func *func, struct node *n,
				struct ply_probe *pb)
{
	struct node *a, *b;
	ssize_t len;
	int16_t done;
	uint16_t dst;
	int invert = 0;
	const char *blit = NULL;

	a = n->expr.args;
	b = a->next;

	if (a->ntype == N_STRING) {
		struct node *tmp = a;

		a = b;
		b = tmp;
		invert = 1;
	}

	if (b->ntype == N_STRING)
		blit = b->string.data;

	/* TODO: Short strings could be in registers or immediate
	 * values I suppose, but let's not deal with that for now */
	assert(sym_on_stack(a->sym));
	if (!blit)
		assert(sym_on_stack(b->sym));

	ir_init_sym(pb->ir, n->sym);

	len = min(type_sizeof(a->sym->type), type_sizeof(b->sym->type));

	dst = sym_in_reg(n->sym) ? n->sym->irs.reg : BPF_REG_0;
	strcmp_emit(pb->ir, dst, a->sym->irs.stack, b->sym->irs.stack,
		    blit, len);

	if (invert)
		ir_emit_insn(pb->ir, ALU_IMM(BPF_NEG, 0), dst, 0);

	ir_emit_reg_to_sym(pb->ir, n->sym, dst);
	return 0;
}

static int strcmp_type_infer(const struct func *func, struct node *n)
{
	struct node *s[2];
	struct tfield *f;
	int i;

	if (n->sym->type)
		return 0;

	s[0] = n->expr.args;
	s[1] = s[0]->next;

	if (!(s[0]->sym->type && s[1]->sym->type))
		return 0;

	for (i = 0; i < 2; i++) {
		if (s[i]->ntype == N_STRING) {
			s[i]->string.virtual = 1;
			continue;
		}

		if (!type_is_string(s[i]->sym->type))
			_nw(n, "'%N' is of type '%T', a string was expected.",
			    s[i], s[i]->sym->type);
	}

	n->sym->type = &t_int;
	return 0;
}

static struct func strcmp_func = {
	.name = "strcmp",
	.type = &t_vargs_func,
	.type_infer = strcmp_type_infer,
	.ir_post = strcmp_ir_post,
};

static int str_ir_post(const struct func *func, struct node *n,
		       struct ply_probe *pb)
{
	struct node *ptr = n->expr.args;
	struct ir *ir = pb->ir;

	n->sym->irs.hint.stack = 1;
	ir_init_sym(ir, n->sym);

	ir_emit_bzero(ir, n->sym->irs.stack, (size_t)type_sizeof(n->sym->type));

	ir_emit_ldbp(pb->ir, BPF_REG_1, n->sym->irs.stack);
	ir_emit_insn(ir, MOV_IMM((int32_t)type_sizeof(n->sym->type)), BPF_REG_2, 0);
	ir_emit_sym_to_reg(ir, BPF_REG_3, ptr->sym);
	ir_emit_insn(ir, CALL(BPF_FUNC_probe_read_str), 0, 0);
	return 0;
}

static int mem_ir_post(const struct func *func, struct node *n,
		       struct ply_probe *pb)
{
	struct node *ptr = n->expr.args;

	n->sym->irs.hint.stack = 1;
	ir_init_sym(pb->ir, n->sym);

	ir_emit_sym_to_reg(pb->ir, BPF_REG_3, ptr->sym);
	ir_emit_read_to_sym(pb->ir, n->sym, BPF_REG_3);
	return 0;
}

static int mem_type_infer(const struct func *func, struct node *n)
{
	struct node *arg, *len;
	struct type *t;
	size_t sz = ply_config.string_size;
	int i;

	if (n->sym->type)
		return 0;

	arg = n->expr.args;
	len = arg->next;

	if (!(arg->sym->type && (!len || len->sym->type)))
		return 0;

	if (type_sizeof(arg->sym->type) > (ssize_t)sizeof(void *)) {
		_ne(n, "can not cast '%N', of type '%T', to a pointer.",
		    arg, arg->sym->type);
		return -EINVAL;
	}

	if (len) {
		if (len->ntype != N_NUM) {
			_ne(n, "length must be a constant, "
			    "but '%N' is of type '%T'.", len, len->sym->type);
			return -EINVAL;
		}

		sz = (size_t)len->num.u64;
		if (sz > MAX_BPF_STACK) {
			_ne(n, "length is larger than the maximum "
			    "allowed stack size (%d).", MAX_BPF_STACK);
			return -EINVAL;
		}
	}

	n->sym->type = type_array_of(&t_char, sz);
	return 0;
}

static struct tfield f_1arg[] = {
	{ .type = &t_void },
	{ .type = NULL }
};

struct type t_mem_func = {
	.ttype = T_FUNC,
	.func = { .type = &t_void, .args = f_1arg, .vargs = 1 },
};

static struct func mem_func = {
	.name = "mem",
	.type = &t_mem_func,
	.type_infer = mem_type_infer,
	.ir_post = mem_ir_post,
};

static struct func str_func = {
	.name = "str",
	.type = &t_mem_func,
	.type_infer = mem_type_infer,
	.ir_post = str_ir_post,
};


static int struct_deref_rewrite(const struct func *func, struct node *n,
				 struct ply_probe *pb)
{
	struct node *new, *sou, *member;

	sou = n->expr.args;
	member = sou->next;
	
	/* sou->member => (*sou).member */
	new = node_expr(&n->loc, ".",
			node_expr(&n->loc, "u*", node_expr_ident(&sou->loc, sou->expr.func), NULL),
			node_string(&member->loc, member->string.data),
			NULL);

	/* TODO: n leaked */
	node_replace(n, new);
	return 1;
}

static int struct_deref_type_infer(const struct func *func, struct node *n)
{
	struct node *sou, *member;
	struct type *t;
	struct tfield *f;

	if (n->sym->type)
		return 0;

	sou = n->expr.args;
	member = sou->next;
	if (!sou->sym->type)
		return 0;

	t = type_base(sou->sym->type);

	if (t->ttype != T_POINTER) {
		_ne(n, "%N is not a pointer (type '%T').\n",
		    sou, sou->sym->type);
		return -EINVAL;
	}

	t = type_base(t->ptr.type);

	/* TODO: add union */
	if (t->ttype != T_STRUCT) {
		_ne(n, "%N is neither struct nor union (type '%T').\n",
		    sou, sou->sym->type);
		return -EINVAL;
	}

	f = tfields_get(t->sou.fields, member->string.data);
	if (!f) {
		_ne(n, "type '%T' has no member named %N.\n", t, member);
		return -EINVAL;
	}

	/* given `sou->member` where sou is a pointer to struct/union,
	 * infer that the expression's type is equal to the
	 * dereferenced member's type. */
	n->sym->type = f->type;
	return 0;
}

static struct func struct_deref_func = {
	.name = "->",
	.type = &t_binop_func,
	.type_infer = struct_deref_type_infer,
	.rewrite = struct_deref_rewrite,
};


static int struct_dot_ir_pre(const struct func *func, struct node *n,
				struct ply_probe *pb)
{
	struct node *sou = n->expr.args;

	if (node_is(sou, "u*")) {
		/* (*ptr).member, if *ptr is not already loaded let it
		 * know that we're only interested in one member */
		sou->sym->irs.hint.dot = 1;

		/* this also means we need to put ourselves on the
		 * stack since data will be loaded via probe_read */
		n->sym->irs.hint.stack = 1;
	}
	return 0;
}

static int struct_dot_ir_post(const struct func *func, struct node *n,
				struct ply_probe *pb)
{
	struct node *sou, *member;
	struct irstate *dst;
	ssize_t offset;

	sou = n->expr.args;
	member = sou->next;
	dst = &n->sym->irs;
	
	ir_init_sym(pb->ir, n->sym);

	offset = type_offsetof(type_base(sou->sym->type), member->string.data);
	assert(offset >= 0);

	if (!sou->sym->irs.loc) {
		/* sou is a u* which wasn't loaded by child, just
		 * read the member we're interested in. */
		struct node *ptr = sou->expr.args;

		ir_emit_sym_to_reg(pb->ir, BPF_REG_3, ptr->sym);
		ir_emit_insn(pb->ir, ALU64_IMM(BPF_ADD, offset), BPF_REG_3, 0);
		goto probe_read;
	}

	offset += sou->sym->irs.stack;

	if (dst->loc == LOC_REG) {
		ir_emit_insn(pb->ir, LDX(bpf_width(dst->size), offset),
			     dst->reg, BPF_REG_BP);
		return 0;
	}

	ir_emit_insn(pb->ir, ALU_IMM(BPF_ADD, offset), BPF_REG_3, 0);
probe_read:
	ir_emit_insn(pb->ir, MOV_IMM((int32_t)dst->size), BPF_REG_2, 0);
	ir_emit_ldbp(pb->ir, BPF_REG_1, dst->stack);
	ir_emit_insn(pb->ir, CALL(BPF_FUNC_probe_read), 0, 0);
	/* TODO if (r0) exit(r0); */
	return 0;
}

static int struct_dot_type_infer(const struct func *func, struct node *n)
{
	struct node *sou, *member;
	struct type *t;
	struct tfield *f;

	if (n->sym->type)
		return 0;

	sou = n->expr.args;
	member = sou->next;
	if (!sou->sym->type)
		return 0;

	t = type_base(sou->sym->type);

	/* TODO: add union */
	if (t->ttype != T_STRUCT) {
		_ne(n, "%N is neither struct nor union (type '%T').\n",
		    sou, sou->sym->type);
		return -EINVAL;
	}

	f = tfields_get(t->sou.fields, member->string.data);
	if (!f) {
		_ne(n, "type '%T' has no member named %N.\n", t, member);
		return -EINVAL;
	}

	member->string.virtual = 1;

	/* given `sou.member` where sou is a struct/union, infer that
	 * the expression's type is equal to member's type. */
	n->sym->type = f->type;
	return 0;
}

static struct func struct_dot_func = {
	.name = ".",
	.type = &t_binop_func,
	.type_infer = struct_dot_type_infer,

	.ir_pre  = struct_dot_ir_pre,
	.ir_post = struct_dot_ir_post,
};


static int deref_ir_post(const struct func *func, struct node *n,
				struct ply_probe *pb)
{
	struct node *ptr = n->expr.args;
	struct irstate *dst;
	size_t size;

	dst = &n->sym->irs;
	if (dst->hint.dot)
		/* (*ptr).member, ptr points to a struct and our
		 * parent is only interested in one member. don't load
		 * the struct, let the dot operaton steal the address
		 * from our argument */
		return 0;

	ir_init_sym(pb->ir, n->sym);

	if (dst->hint.lval)
		/* *ptr = val, whatever is in our storage now it will
                    be overwritten, so skip the load. */
		return 0;

	ir_emit_sym_to_reg(pb->ir, BPF_REG_0, ptr->sym);
	ir_emit_read_to_sym(pb->ir, n->sym, BPF_REG_0);
	return 0;
}


static int deref_type_infer(const struct func *func, struct node *n)
{
	struct node *ptr = n->expr.args;
	struct type *t;

	if (n->sym->type || !ptr->sym->type)
		return 0;

	t = type_base(ptr->sym->type);
	if (t->ttype != T_POINTER) {
		_ne(n, "can't dereference %N (type '%T').\n",
		    ptr, ptr->sym->type);
		return -EINVAL;
	}

	/* given `*p` where p is a pointer, infer that the
	 * expression's type is equal to p's concrete type. */
	n->sym->type = t->ptr.type;
	return 0;
}

static struct func deref_func = {
	.name = "u*",
	.type = &t_unary_func,
	.type_infer = deref_type_infer,

	.ir_post = deref_ir_post,
};


static int struct_ir_pre(const struct func *func, struct node *n,
			 struct ply_probe *pb)
{
	struct node *arg;
	struct type *t = type_base(n->sym->type);
	ssize_t stack;
	size_t offset = 0, size = 0, pad;
	struct tfield *f;

	n->sym->irs.hint.stack = 1;
	ir_init_sym(pb->ir, n->sym);
	stack = n->sym->irs.stack;

	arg = n->expr.args;
	tfields_foreach(f, t->sou.fields) {
		offset = type_offsetof(t, f->name);
		size = type_sizeof(f->type);

		if (!arg->sym->irs.loc) {
			arg->sym->irs.hint.stack = 1;
			arg->sym->irs.stack = stack + offset;
		}

		if (arg->next) {
			pad = type_offsetof(t, f[1].name) - (offset + size);
			if (pad)
				ir_emit_bzero(pb->ir,
					      stack + offset + size, pad);
		}
		arg = arg->next;
	}

	pad = type_sizeof(t) - (offset + size);
	if (pad)
		ir_emit_bzero(pb->ir, stack + offset + size, pad);
	return 0;
}

static int struct_ir_post(const struct func *func, struct node *n,
			  struct ply_probe *pb)
{
	struct node *arg;
	struct type *t = type_base(n->sym->type);
	ssize_t stack = n->sym->irs.stack;
	size_t offset;
	struct tfield *f;

	arg = n->expr.args;
	tfields_foreach(f, t->sou.fields) {
		offset = type_offsetof(t, f->name);
		ir_emit_sym_to_stack(pb->ir, stack + offset, arg->sym);
		arg = arg->next;
	}
	return 0;
}

static int struct_type_infer(const struct func *func, struct node *n)
{
	struct node *arg;
	struct type *t;
	struct tfield *fields, *f;
	int i, nargs = node_nargs(n);
	char *kname;

	for (arg = n->expr.args; arg; arg = arg->next) {
		if (type_sizeof(arg->sym->type) < 0)
			return 0;
	}

	t = xcalloc(1, sizeof(*t));
	fields = xcalloc(nargs + 1, sizeof(*fields));

	for (arg = n->expr.args, f = fields, i = 0; arg;
	     arg = arg->next, f++, i++) {
		asprintf(&f->name, "f%d", i);
		f->type = arg->sym->type;
	}

	asprintf(&t->sou.name, ":anon_%p", n);
	t->ttype = T_STRUCT;
	t->sou.fields = fields;

	type_add(t);
	n->sym->type = t;
	return 0;
}

static struct func struct_func = {
	.name = ":struct",
	.type = &t_vargs_func,
	.type_infer = struct_type_infer,

	.ir_pre  = struct_ir_pre,
	.ir_post = struct_ir_post,
};


static int map_ir_update(struct node *n, struct ply_probe *pb)
{
	struct node *map, *key;

	map = n->expr.args;
	key = map->next;

	ir_emit_ldmap(pb->ir, BPF_REG_1, map->sym);
	ir_emit_ldbp(pb->ir, BPF_REG_2, key->sym->irs.stack);
	ir_emit_ldbp(pb->ir, BPF_REG_3, n->sym->irs.stack);
	ir_emit_insn(pb->ir, MOV_IMM(0), BPF_REG_4, 0);
	ir_emit_insn(pb->ir, CALL(BPF_FUNC_map_update_elem), 0, 0);
	/* TODO: if (r0) exit(r0); */
	return 0;
}


static int map_ir_post(const struct func *func, struct node *n,
		       struct ply_probe *pb)
{
	struct node *map, *key;
	ssize_t stack;
	size_t offset;
	struct tfield *f;
	int16_t lmiss, lhit;

	map = n->expr.args;
	key = map->next;
	stack = key->sym->irs.stack;

	n->sym->irs.hint.stack = 1;
	ir_init_sym(pb->ir, n->sym);

	if (n->sym->irs.hint.lval)
		/* map[key] = val, whatever is in our storage now it
                    will be overwritten, so skip the load. */
		return 0;

	ir_emit_ldmap(pb->ir, BPF_REG_1, map->sym);
	ir_emit_ldbp(pb->ir, BPF_REG_2, stack);
	ir_emit_insn(pb->ir, CALL(BPF_FUNC_map_lookup_elem), 0, 0);

	lmiss = ir_alloc_label(pb->ir);
	lhit  = ir_alloc_label(pb->ir);

	ir_emit_insn(pb->ir, JMP_IMM(BPF_JEQ, 0, lmiss), BPF_REG_0, 0);
	ir_emit_read_to_sym(pb->ir, n->sym, BPF_REG_0);
	ir_emit_insn(pb->ir, JMP_IMM(BPF_JA, 0, lhit), 0, 0);

	ir_emit_label(pb->ir, lmiss);
	ir_emit_bzero(pb->ir, n->sym->irs.stack, n->sym->irs.size);
	
	ir_emit_label(pb->ir, lhit);
	return 0;
}

static int map_type_validate(struct node *n)
{
	/* TODO */
	return 0;
}

static int map_type_infer(const struct func *func, struct node *n)
{
	struct node *map, *key;
	struct type *ktype;

	map = n->expr.args;
	key = map->next;
	if (!map->sym)
		return 0;

	if (map->sym->type) {
		if (!n->sym->type)
			/* given `m[key]` where m's type is known,
			 * infer that the expression's type is equal
			 * to m's value type. */
			n->sym->type = map->sym->type->map.vtype;

		return map_type_validate(n);
	}

	if (!(n->sym->type && key->sym->type))
		return 0;

	map->sym->type = type_map_of(key->sym->type, n->sym->type,
				     BPF_MAP_TYPE_HASH, 0);
	return 0;
}

static int map_static_validate(const struct func *func, struct node *n)
{
	if (n->expr.args->ntype != N_EXPR || !n->expr.args->expr.ident) {
		_ne(n, "can't lookup a key in %N, which is not a map.\n", n);
		return -EINVAL;
	}

	return 0;
}

static struct func map_func = {
	.name = "[]",
	.type_infer = map_type_infer,
	.static_validate = map_static_validate,

	.ir_post = map_ir_post,
};


static int assign_ir_pre(const struct func *func, struct node *n,
				struct ply_probe *pb)
{
	struct node *lval, *rval;

	lval = n->expr.args;
	rval = lval->next;

	n->sym->irs.hint.stack = 1;
	ir_init_irs(pb->ir, &n->sym->irs, lval->sym->type);

	lval->sym->irs.hint.lval = 1;
	lval->sym->irs.hint.stack = 1;
	lval->sym->irs.stack = n->sym->irs.stack;

	rval->sym->irs.hint.stack = 1;
	rval->sym->irs.stack = n->sym->irs.stack;
	return 0;
}

static int assign_ir_post(const struct func *func, struct node *n,
				 struct ply_probe *pb)
{
	struct node *lval, *rval;

	lval = n->expr.args;
	rval = lval->next;

	ir_emit_sym_to_sym(pb->ir, lval->sym, rval->sym);
	if (!node_is(lval, "[]"))
		return 0;

	return map_ir_update(lval, pb);
}

static int assign_type_infer(const struct func *func, struct node *n)
{
	struct node *lval, *rval;
	int err;

	if (n->sym->type)
		return 0;

	lval = n->expr.args;
	rval = lval->next;

	if (!rval->sym->type)
		return 0;

	if (!lval->sym->type) {
		/* given `a = b` where b's type is known but not a's,
		 * infer that a's type must be equal to b's */
		lval->sym->type = rval->sym->type;

		/* TODO do we need assignment expressions? */
		n->sym->type = &t_void;
		
		if (!node_is(lval, "[]"))
			return 0;

		err = map_type_infer(lval->sym->func, lval);
		if (err)
			return err;
	}

	if (type_compatible(lval->sym->type, rval->sym->type)) {
		n->sym->type = &t_void;
		return 0;
	}

	_ne(n, "can't assign %N (type '%T'), to %N (type '%T').\n",
	    rval, rval->sym->type, lval, lval->sym->type);

	return -EINVAL;
}

static int assign_static_validate(const struct func *func, struct node *n)
{
	struct node *lval;

	lval = n->expr.args;

	if (node_is(lval, "[]"))
		return 0;

	_ne(n, "can't assign a value to %N.\n", lval);
	return -EINVAL;
}

static struct func assign_func = {
	.name = "=",
	.type = &t_binop_func,
	.type_infer = assign_type_infer,
	.static_validate = assign_static_validate,

	.ir_pre  = assign_ir_pre,
	.ir_post = assign_ir_post,
};


static int agg_ir_post(const struct func *func, struct node *n,
			      struct ply_probe *pb)
{
	return map_ir_update(n->expr.args, pb);
}

static struct func agg_func = {
	.name = "@=",
	.type = &t_binop_func,
	.type_infer = assign_type_infer,
	.static_validate = assign_static_validate,

	.ir_post = agg_ir_post,
};


static int delete_ir_pre(const struct func *func, struct node *n,
				struct ply_probe *pb)
{
	struct node *arg;

	arg = n->expr.args;
	arg->sym->irs.hint.lval = 1;
	arg->sym->irs.hint.stack = 1;
	return 0;
}

static int delete_ir_post(const struct func *func, struct node *n,
				 struct ply_probe *pb)
{
	struct node *map, *key;

	map = n->expr.args->expr.args;
	key = map->next;

	ir_emit_ldmap(pb->ir, BPF_REG_1, map->sym);
	ir_emit_ldbp(pb->ir, BPF_REG_2, key->sym->irs.stack);
	ir_emit_insn(pb->ir, CALL(BPF_FUNC_map_delete_elem), 0, 0);
	/* TODO: if (r0) exit(r0); */
	return 0;
}

static int delete_static_validate(const struct func *func, struct node *n)
{
	struct node *arg;

	arg = n->expr.args;

	if (node_is(arg, "[]"))
		return 0;

	_ne(n, "can't delete %N, a map was expected.\n", arg);
	return -EINVAL;
}

static struct func delete_func = {
	.name = "delete",
	.type = &t_unary_func,
	.static_ret = 1,
	.static_validate = delete_static_validate,

	.ir_pre  = delete_ir_pre,
	.ir_post = delete_ir_post,
};


struct clear_ev_data {
	struct node *n;
	struct ply *ply;
};

static struct ply_return clear_ev_handler(struct buffer_ev *ev, void *_n)
{
	struct clear_ev_data *data = _n;
	struct node *n = data->n;
	struct type *t = n->sym->type;
	struct tfield *f;
	struct sym **symp, *sym;

	tfields_foreach(f, t->sou.fields) {
		if (f->type->ttype != T_MAP)
			continue;

		symtab_foreach(&data->ply->globals, symp) {
			sym = *symp;

			if (sym->type == f->type)
				ply_map_clear(data->ply, sym);
		}
	}

	return (struct ply_return){ };
}

static int clear_type_infer(const struct func *func, struct node *n)
{
	struct buffer_evh *evh;

	if (n->sym->priv)
		return 0;

	evh = xcalloc(1, sizeof(*evh));

	evh->handle = clear_ev_handler;
	buffer_evh_register(evh);

	/* TODO: leaked */
	n->sym->priv = evh;
	return 0;
}

static int clear_rewrite(const struct func *func, struct node *n,
			struct ply_probe *pb)
{
	struct node *bwrite, *exprs, *ev;
	struct buffer_evh *evh;
	struct clear_ev_data *data;
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

static int clear_static_validate(const struct func *func, struct node *n)
{
	struct node *arg = n->expr.args;

	if (arg->sym->type == NULL || arg->sym->type->ttype == T_MAP)
		return 0;

	_ne(n, "can't delete %N, a map was expected.\n", arg);
	return -EINVAL;
}

static struct func clear_func = {
	.name = "clear",
	.type = &t_unary_func,
	.static_ret = 1,
	.static_validate = clear_static_validate,

	.type_infer = clear_type_infer,
	.rewrite = clear_rewrite,
};

void memory_init(void)
{
	built_in_register(&strcmp_func);
	built_in_register(&str_func);
	built_in_register(&mem_func);
	built_in_register(&struct_deref_func);
	built_in_register(&struct_dot_func);
	built_in_register(&deref_func);
	built_in_register(&struct_func);
	built_in_register(&map_func);
	built_in_register(&assign_func);
	built_in_register(&agg_func);
	built_in_register(&delete_func);
	built_in_register(&clear_func);
}
