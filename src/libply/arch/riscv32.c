/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <assert.h>

#include <ply/internal.h>

#define arch_typedef(_a, _t) {					\
		.ttype = T_TYPEDEF,				\
		.tdef = { .name = #_a, .type = _t },		\
	}

struct type t_s8  = arch_typedef(s8,  &t_schar);
struct type t_u8  = arch_typedef(u8,  &t_uchar);
struct type t_s16 = arch_typedef(s16, &t_sshort);
struct type t_u16 = arch_typedef(u16, &t_ushort);
struct type t_s32 = arch_typedef(s32, &t_sint);
struct type t_u32 = arch_typedef(u32, &t_uint);
struct type t_s64 = arch_typedef(s64, &t_sllong);
struct type t_u64 = arch_typedef(u64, &t_ullong);

static int reg_fprint(struct type *t, FILE *fp, const void *data)
{
	return fprintf(fp, "%#lx", *((unsigned long *)data));
}

struct type t_reg_t = {
	.ttype = T_TYPEDEF,
	.tdef = {
		.name = "reg_t",
		.type = &t_ulong,
	},

	.fprint = reg_fprint,
};

struct tfield f_pt_regs_fields[] = {
	{ .name = "pc",      .type = &t_reg_t },
	{ .name = "ra",      .type = &t_reg_t },
	{ .name = "sp",      .type = &t_reg_t },
	{ .name = "gp",      .type = &t_reg_t },
	{ .name = "tp",      .type = &t_reg_t },
	{ .name = "t0",      .type = &t_reg_t },
	{ .name = "t1",      .type = &t_reg_t },
	{ .name = "t2",      .type = &t_reg_t },
	{ .name = "s0",      .type = &t_reg_t },
	{ .name = "s1",      .type = &t_reg_t },
	{ .name = "a0",      .type = &t_reg_t },
	{ .name = "a1",      .type = &t_reg_t },
	{ .name = "a2",      .type = &t_reg_t },
	{ .name = "a3",      .type = &t_reg_t },
	{ .name = "a4",      .type = &t_reg_t },
	{ .name = "a5",      .type = &t_reg_t },
	{ .name = "a6",      .type = &t_reg_t },
	{ .name = "a7",      .type = &t_reg_t },
	{ .name = "s2",      .type = &t_reg_t },
	{ .name = "s3",      .type = &t_reg_t },
	{ .name = "s4",      .type = &t_reg_t },
	{ .name = "s5",      .type = &t_reg_t },
	{ .name = "s6",      .type = &t_reg_t },
	{ .name = "s7",      .type = &t_reg_t },
	{ .name = "s8",      .type = &t_reg_t },
	{ .name = "s9",      .type = &t_reg_t },
	{ .name = "s10",     .type = &t_reg_t },
	{ .name = "s11",     .type = &t_reg_t },
	{ .name = "t3",      .type = &t_reg_t },
	{ .name = "t4",      .type = &t_reg_t },
	{ .name = "t5",      .type = &t_reg_t },
	{ .name = "t6",      .type = &t_reg_t },

	{ .type = NULL }
};

struct type t_pt_regs = {
	.ttype = T_STRUCT,

	.sou = {
		.name = "pt_regs",
		.fields = f_pt_regs_fields,
	},
};

struct type *arch_types[] = {
	&t_s8, &t_u8,
	&t_s16, &t_u16,
	&t_s32, &t_u32,
	&t_s64, &t_u64,
	&t_reg_t, &t_pt_regs,

	NULL
};

const char *arch_register_argument(int num)
{
	switch (num) {
	case 0: return "a0";
	case 1: return "a1";
	case 2: return "a2";
	case 3: return "a3";
	case 4: return "a4";
	case 5: return "a5";
	case 6: return "a6";
	}

	return NULL;
}

const char *arch_register_pc(void)
{
	return "pc";
}

const char *arch_register_return(void)
{
	return "a0";
}

__attribute__((constructor))
static void arch_init(void)
{
	type_struct_layout(&t_pt_regs);
	type_add_list(arch_types);
}
