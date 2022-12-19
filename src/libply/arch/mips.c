/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 * Copyright Ye Jiaqiang <yejq.jiaqiang@gmail.com>
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
#ifdef __mips64
struct type t_s64 = arch_typedef(s64, &t_slong);
struct type t_u64 = arch_typedef(u64, &t_ulong);
#else
struct type t_s64 = arch_typedef(s64, &t_sllong);
struct type t_u64 = arch_typedef(u64, &t_ullong);
#endif

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
#ifndef __mips64
	{ .name = "uarg0",        .type = &t_reg_t },
	{ .name = "uarg1",        .type = &t_reg_t },
	{ .name = "uarg2",        .type = &t_reg_t },
	{ .name = "uarg3",        .type = &t_reg_t },
	{ .name = "uarg4",        .type = &t_reg_t },
	{ .name = "uarg5",        .type = &t_reg_t },
	{ .name = "uarg6",        .type = &t_reg_t },
	{ .name = "uarg7",        .type = &t_reg_t },
#endif
	{ .name = "zero",         .type = &t_reg_t },    /* $0  */
	{ .name = "at",           .type = &t_reg_t },    /* $1  */
	{ .name = "v0",           .type = &t_reg_t },    /* $2  */
	{ .name = "v1",           .type = &t_reg_t },    /* $3  */
	{ .name = "a0",           .type = &t_reg_t },    /* $4  */
	{ .name = "a1",           .type = &t_reg_t },    /* $5  */
	{ .name = "a2",           .type = &t_reg_t },    /* $6  */
	{ .name = "a3",           .type = &t_reg_t },    /* $7  */
#ifdef _ABIO32
	{ .name = "t0",           .type = &t_reg_t },    /* $8  */
	{ .name = "t1",           .type = &t_reg_t },    /* $9  */
	{ .name = "t2",           .type = &t_reg_t },    /* $10 */
	{ .name = "t3",           .type = &t_reg_t },    /* $11 */
#else /* n32 or native 64-bit ABI */
	{ .name = "a4",           .type = &t_reg_t },    /* $8  */
	{ .name = "a5",           .type = &t_reg_t },    /* $9  */
	{ .name = "a6",           .type = &t_reg_t },    /* $10 */
	{ .name = "a7",           .type = &t_reg_t },    /* $11 */
#endif
	{ .name = "t4",           .type = &t_reg_t },    /* $12 */
	{ .name = "t5",           .type = &t_reg_t },    /* $13 */
	{ .name = "t6",           .type = &t_reg_t },    /* $14 */
	{ .name = "t7",           .type = &t_reg_t },    /* $15 */
	{ .name = "s0",           .type = &t_reg_t },    /* $16 */
	{ .name = "s1",           .type = &t_reg_t },    /* $17 */
	{ .name = "s2",           .type = &t_reg_t },    /* $18 */
	{ .name = "s3",           .type = &t_reg_t },    /* $19 */
	{ .name = "s4",           .type = &t_reg_t },    /* $20 */
	{ .name = "s5",           .type = &t_reg_t },    /* $21 */
	{ .name = "s6",           .type = &t_reg_t },    /* $22 */
	{ .name = "s7",           .type = &t_reg_t },    /* $23 */
	{ .name = "t8",           .type = &t_reg_t },    /* $24 */
	{ .name = "t9",           .type = &t_reg_t },    /* $25 */
	{ .name = "k0",           .type = &t_reg_t },    /* $26 */
	{ .name = "k1",           .type = &t_reg_t },    /* $27 */
	{ .name = "gp",           .type = &t_reg_t },    /* $28 */
	{ .name = "sp",           .type = &t_reg_t },    /* $29 */
	{ .name = "fp",           .type = &t_reg_t },    /* $30, or s8 */
	{ .name = "ra",           .type = &t_reg_t },    /* $31 */

	{ .name = "cp0_status",   .type = &t_reg_t },
	{ .name = "hi",           .type = &t_reg_t },
	{ .name = "lo",           .type = &t_reg_t },

#ifdef __mips_smartmips
	{ .name = "acx",          .type = &t_reg_t },
#endif
	{ .name = "cp0_badvaddr", .type = &t_reg_t },
	{ .name = "cp0_cause",    .type = &t_reg_t },
	{ .name = "cp0_epc",      .type = &t_reg_t },

#ifdef __OCTEON__
	{ .name = "mpl0",      .type = &t_reg_t },
	{ .name = "mpl1",      .type = &t_reg_t },
	{ .name = "mpl2",      .type = &t_reg_t },
	{ .name = "mpl3",      .type = &t_reg_t },
	{ .name = "mpl4",      .type = &t_reg_t },
	{ .name = "mpl5",      .type = &t_reg_t },
	{ .name = "mtp0",      .type = &t_reg_t },
	{ .name = "mtp1",      .type = &t_reg_t },
	{ .name = "mtp2",      .type = &t_reg_t },
	{ .name = "mtp3",      .type = &t_reg_t },
	{ .name = "mtp4",      .type = &t_reg_t },
	{ .name = "mtp5",      .type = &t_reg_t },
#endif
	{ .name = NULL,           .type = NULL }
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
#ifndef _ABIO32 /* n32 or native 64-bit ABI */
	case 4: return "a4";
	case 5: return "a5";
	case 6: return "a6";
	case 7: return "a7";
#endif
	default:
		break;
	}

	return NULL;
}

const char *arch_register_pc(void)
{
	return "cp0_epc";
}

const char *arch_register_return(void)
{
	return "v0";
}

__attribute__((constructor))
static void arch_init(void)
{
	type_struct_layout(&t_pt_regs);
	type_add_list(arch_types);
}
