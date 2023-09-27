/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <linux/bpf.h>

#include <ply/ply.h>
#include <ply/internal.h>

const uint16_t vreg_base = 0x8000;

static const char *bpf_func_name(enum bpf_func_id id)
{
	switch (id) {
	case BPF_FUNC_get_current_comm:
		return "get_current_comm";
	case BPF_FUNC_get_current_pid_tgid:
		return "get_current_pid_tgid";
	case BPF_FUNC_get_current_uid_gid:
		return "get_current_uid_gid";
	case BPF_FUNC_get_stackid:
		return "get_stackid";
	case BPF_FUNC_ktime_get_ns:
		return "ktime_get_ns";
	case BPF_FUNC_map_delete_elem:
		return "map_delete_elem";
	case BPF_FUNC_map_lookup_elem:
		return "map_lookup_elem";
	case BPF_FUNC_map_update_elem:
		return "map_update_elem";
	case BPF_FUNC_perf_event_output:
		return "perf_event_output";
	case BPF_FUNC_probe_read_kernel:
		return "probe_read_kernel";
	case BPF_FUNC_probe_read_kernel_str:
		return "probe_read_kernel_str";
	case BPF_FUNC_trace_printk:
		return "trace_printk";
	default:
		return NULL;
	}
}

static void reg_name(uint16_t reg, char *name)
{
        if (reg & vreg_base) {
		sprintf(name, "v%u", reg & ~vreg_base);		
	} else if (reg == BPF_REG_10) {
		strcpy(name, "bp");
	} else {
		sprintf(name, "r%u", reg);
	}
}

static void reg_dump(uint16_t reg, int16_t off, FILE *fp)
{
	char name[8];

	reg_name(reg, name);

	if (off < 0)
		fprintf(fp, "[%s - 0x%x]", name, -off);
	else if (off > 0)
		fprintf(fp, "[%s + 0x%x]", name, off);
	else
		fprintf(fp, "%s", name);
}

static char size_name(uint8_t code)
{
	switch (BPF_SIZE(code)) {
	case BPF_B:  return 'b';
	case BPF_H:  return 'h';
	case BPF_W:  return 'w';
	case BPF_DW: return 'q';
	}

	return '?';
}		

static void alu_dump(uint8_t code, FILE *fp)
{
	switch (BPF_OP(code)) {
	case BPF_MOV: fputs("mov", fp); break;
	case BPF_ADD: fputs("add", fp); break;
	case BPF_SUB: fputs("sub", fp); break;
	case BPF_MUL: fputs("mul", fp); break;
	case BPF_DIV: fputs("div", fp); break;
	case BPF_OR : fputs("or",  fp); break;
	case BPF_AND: fputs("and", fp); break;
	case BPF_LSH: fputs("lsh", fp); break;
	case BPF_RSH: fputs("rsh", fp); break;
	case BPF_NEG: fputs("neg", fp); break;
	case BPF_MOD: fputs("mod", fp); break;
	case BPF_XOR: fputs("xor", fp); break;
	}

	switch (BPF_CLASS(code)) {
	case BPF_ALU:   fputc(size_name(BPF_W), fp); break;
	case BPF_ALU64: fputc(size_name(BPF_DW), fp); break;
	}
}

static void offset_dump(int16_t off, FILE *fp)
{
	if (off < 0)
		fprintf(fp, "L%d", -off);
	else
		fprintf(fp, "+%d", off);
}

static void __insn_dump(const struct bpf_insn insn, uint16_t dst, uint16_t src,
			FILE *fp)
{
	const char *name;
	enum {
		OFF_NONE,
		OFF_DST,
		OFF_SRC,
		OFF_EXP,
	} off = OFF_NONE;

	switch (BPF_CLASS(insn.code)) {
	case BPF_LD:
	case BPF_LDX:
		off = OFF_SRC;
		fprintf(fp, "ld%c", size_name(insn.code));
		break;

	case BPF_ST:
	case BPF_STX:
		off = OFF_DST;
		fprintf(fp, "st%c", size_name(insn.code));
		break;

	case BPF_ALU:
	case BPF_ALU64:
		alu_dump(insn.code, fp);
		break;

	case BPF_JMP:
		off = OFF_EXP;

		switch (BPF_OP(insn.code)) {
		case BPF_EXIT:
			fputs("exit", fp);
			return;
		case BPF_CALL:
			fputs("call\t", fp);

			name = bpf_func_name(insn.imm);
			if (name)
				fputs(name, fp);
			else
				fprintf(fp, "%d", insn.imm);
			return;
		case BPF_JA:
			fputs("ja\t", fp);
			offset_dump(insn.off, fp);
			return;

		case BPF_JEQ:  fputs("jeq", fp); break;
		case BPF_JNE:  fputs("jne", fp); break;
		case BPF_JLT:  fputs("jlt", fp); break;
		case BPF_JGT:  fputs("jgt", fp); break;
		case BPF_JLE:  fputs("jle", fp); break;
		case BPF_JGE:  fputs("jge", fp); break;
		case BPF_JSLT: fputs("jslt", fp); break;
		case BPF_JSLE: fputs("jsle", fp); break;
		case BPF_JSGT: fputs("jsgt", fp); break;
		case BPF_JSGE: fputs("jsge", fp); break;
		default:
			goto unknown;
		}
		break;

	default:
		goto unknown;
	}

	fputc('\t', fp);
	reg_dump(dst, off == OFF_DST ? insn.off : 0, fp);		
	fputs(", ", fp);

	if ((BPF_CLASS(insn.code) == BPF_LDX) || (BPF_CLASS(insn.code) == BPF_STX))
		goto reg_src;
	else if ((BPF_CLASS(insn.code) == BPF_LD) || (BPF_CLASS(insn.code) == BPF_ST))
		goto imm_src;

	switch (BPF_SRC(insn.code)) {
	case BPF_K:
	imm_src:
		fprintf(fp, "#%s0x%x", insn.imm < 0 ? "-" : "",
			insn.imm < 0 ? -insn.imm : insn.imm);
		break;
	case BPF_X:
	reg_src:
		reg_dump(src, off == OFF_SRC ? insn.off : 0, fp);		
		break;
	}

	if (off == OFF_EXP) {
		fputs(", ", fp);
		offset_dump(insn.off, fp);
	}

	return;

unknown:
	fprintf(fp, "data\t0x%16.16" PRIx64 "\n", *((uint64_t *)&insn));	
}

void insn_dump(struct bpf_insn insn, FILE *fp)
{
	__insn_dump(insn, insn.dst_reg, insn.src_reg, fp);
}

void vinsn_dump(struct vinsn *vi, FILE *fp)
{
	switch (vi->vitype) {
	case VI_INSN:
		__insn_dump(vi->insn.bpf, vi->insn.dst, vi->insn.src, fp);
		return;
	case VI_LDMAP:
		fputs("ldmap\t", fp); reg_dump(vi->map.reg, 0, fp);
		fprintf(fp, ", %s", vi->map.sym->name);
		return;
	case VI_LABEL:
		offset_dump(vi->label, fp);
		fputc(':', fp);
		return;
	case VI_COMMENT:
		fputs(";; ", fp);
		fputs(vi->comment, fp);
	}
}

void ir_dump(struct ir *ir, FILE *fp)
{
	size_t i;
	int n = 0;

	for (i = 0; i < ir->len; i++) {
		struct vinsn *vi = &ir->vi[i];

		switch (vi->vitype) {
		case VI_INSN:
		case VI_LDMAP:
			fprintf(fp, "%3d\t", n++);
			break;
		default:
			break;
		}

		vinsn_dump(vi, fp);

		fputc('\n', fp);
	}
}

static void ir_emit(struct ir *ir, struct vinsn *vi)
{
	ir->vi = realloc(ir->vi, (++ir->len)*sizeof(*vi));
	assert(ir->vi);

	ir->vi[ir->len - 1] = *vi;
}

void ir_emit_insn(struct ir *ir, struct bpf_insn bpf, uint16_t dst, uint16_t src)
{
	struct vinsn vi;

	vi.vitype = VI_INSN;
	vi.insn.bpf = bpf;
	vi.insn.dst = dst;
	vi.insn.src = src;
	ir_emit(ir, &vi);
}

void ir_emit_ldmap(struct ir *ir, uint16_t dst, struct sym *map)
{
	struct vinsn vi;

	vi.vitype = VI_LDMAP;
	vi.map.reg = dst;
	vi.map.sym = map;
	ir_emit(ir, &vi);

	/* second part of the load 64-bit immediate instruction, used
	 * to store the 32 MSBs of the map fd */
	ir_emit_insn(ir, INSN(0, 0, 0, 0, 0), 0, 0);
}

void ir_emit_label(struct ir *ir, int16_t label)
{
	struct vinsn vi;

	vi.vitype = VI_LABEL;
	vi.label = label;
	ir_emit(ir, &vi);
}

void ir_emit_comment(struct ir *ir, const char *comment)
{
	struct vinsn vi;

	vi.vitype = VI_COMMENT;
	vi.comment = comment;
	ir_emit(ir, &vi);
}

void ir_emit_sym_to_reg(struct ir *ir, uint16_t dst, struct sym *src)
{
	struct irstate *irs = &src->irs;

	switch (irs->loc) {
	case LOC_IMM:
		ir_emit_insn(ir, MOV_IMM(irs->imm), dst, 0);
		break;
	case LOC_REG:
		if (dst == irs->reg)
			break;

		if (irs->size == 8)
			ir_emit_insn(ir, MOV64, dst, irs->reg);
		else
			ir_emit_insn(ir, MOV, dst, irs->reg);
		break;
	case LOC_STACK:
		ir_emit_insn(ir, LDX(bpf_width(irs->size), irs->stack),
			     dst, BPF_REG_BP);
		break;
	default:
		ir_dump(ir, stderr);
		assert(0);
	}
}

void ir_emit_reg_to_sym(struct ir *ir, struct sym *dst, uint16_t src)
{
	struct irstate *irs = &dst->irs;

	switch (irs->loc) {
	case LOC_REG:
		if (irs->reg == src)
			break;

		if (irs->size == 8)
			ir_emit_insn(ir, MOV64, irs->reg, src);
		else
			ir_emit_insn(ir, MOV, irs->reg, src);
		break;
	case LOC_STACK:
		ir_emit_insn(ir, STX(bpf_width(irs->size), irs->stack),
			     BPF_REG_BP, src);
		break;
	default:
		ir_dump(ir, stderr);
		assert(0);
	}
}

void ir_emit_sym_to_stack(struct ir *ir, ssize_t offset, struct sym *src)
{
	struct irstate *irs = &src->irs;

	switch (irs->loc) {
	case LOC_IMM:
		ir_emit_insn(ir, ST_IMM(bpf_width(irs->size), offset, irs->imm),
			     BPF_REG_BP, 0);
		break;
	case LOC_REG:
		ir_emit_insn(ir, STX(bpf_width(irs->size), offset),
			     BPF_REG_BP, irs->reg);
		break;
	case LOC_STACK:
		ir_emit_memcpy(ir, offset, irs->stack, irs->size);
		break;
	default:
		ir_dump(ir, stderr);
		assert(0);
	}
}

void ir_emit_sym_to_sym(struct ir *ir, struct sym *dst, struct sym *src)
{
	switch (dst->irs.loc) {
	case LOC_REG:
		ir_emit_sym_to_reg(ir, dst->irs.reg, src);
		break;
	case LOC_STACK:
		ir_emit_sym_to_stack(ir, dst->irs.stack, src);
		break;
	default:
		ir_dump(ir, stderr);
		assert(0);
	}
}

void ir_emit_read_to_sym(struct ir *ir, struct sym *dst, uint16_t src)
{
	struct irstate *irs = &dst->irs;

	assert(irs->loc == LOC_STACK);

	ir_emit_ldbp(ir, BPF_REG_1, irs->stack);
	ir_emit_insn(ir, MOV_IMM((int32_t)irs->size), BPF_REG_2, 0);
	if (src != BPF_REG_3)
		ir_emit_insn(ir, MOV, BPF_REG_3, src);

	ir_emit_insn(ir, CALL(BPF_FUNC_probe_read_kernel), 0, 0);
	/* TODO if (r0) exit(r0); */
}

void ir_emit_data(struct ir *ir, ssize_t dst, const char *src, size_t size)
{
	while (size) {
		if ((size >= 4) && !(dst & 3)) {
			uint32_t imm32 = *((uint32_t *)src);

			ir_emit_insn(ir, ST_IMM(BPF_W, dst, imm32), BPF_REG_BP, 0);
			size -= 4, dst += 4, src += 4;
		} else if ((size >= 2) && !(dst & 1)) {
			uint16_t imm16 = *((uint16_t *)src);

			ir_emit_insn(ir, ST_IMM(BPF_H, dst, imm16), BPF_REG_BP, 0);
			size -= 2, dst += 2, src += 2;
		} else {
			uint8_t imm8 = *((uint8_t *)src);

			ir_emit_insn(ir, ST_IMM(BPF_B, dst, imm8), BPF_REG_BP, 0);
			size -= 1, dst += 1, src += 1;
		}
	}
}

void ir_emit_memcpy(struct ir *ir, ssize_t dst, ssize_t src, size_t size)
{
	if (dst == src)
		return;

	while (size) {
		if ((size >= 8) && !(dst & 7) && !(src & 7)) {
			ir_emit_insn(ir, LDX(BPF_DW, src), BPF_REG_0, BPF_REG_BP);
			ir_emit_insn(ir, STX(BPF_DW, dst), BPF_REG_BP, BPF_REG_0);
			size -= 8, dst += 8, src += 8;
		} else if ((size >= 4) && !(dst & 3) && !(src & 3)) {
			ir_emit_insn(ir, LDX(BPF_W, src), BPF_REG_0, BPF_REG_BP);
			ir_emit_insn(ir, STX(BPF_W, dst), BPF_REG_BP, BPF_REG_0);
			size -= 4, dst += 4, src += 4;
		} else if ((size >= 2) && !(dst & 1) && !(src & 1)) {
			ir_emit_insn(ir, LDX(BPF_H, src), BPF_REG_0, BPF_REG_BP);
			ir_emit_insn(ir, STX(BPF_H, dst), BPF_REG_BP, BPF_REG_0);
			size -= 2, dst += 2, src += 2;
		} else {
			ir_emit_insn(ir, LDX(BPF_B, src), BPF_REG_0, BPF_REG_BP);
			ir_emit_insn(ir, STX(BPF_B, dst), BPF_REG_BP, BPF_REG_0);
			size -= 1, dst += 1, src += 1;
		}
	}
}

void ir_emit_bzero(struct ir *ir, ssize_t offset, size_t size)
{
	while (size) {
		if ((size >= 8) && !(offset & 7)) {
			ir_emit_insn(ir, ST_IMM(BPF_DW, offset, 0), BPF_REG_BP, 0);
			size -= 8;
			offset += 8;
		} else if ((size >= 4) && !(offset & 3)) {
			ir_emit_insn(ir, ST_IMM(BPF_W, offset, 0), BPF_REG_BP, 0);
			size -= 4;
			offset += 4;
		} else if ((size >= 2) && !(offset & 1)) {
			ir_emit_insn(ir, ST_IMM(BPF_H, offset, 0), BPF_REG_BP, 0);
			size -= 2;
			offset += 2;
		} else {
			ir_emit_insn(ir, ST_IMM(BPF_B, offset, 0), BPF_REG_BP, 0);
			size -= 1;
			offset++;
		}
	}
}

void ir_emit_perf_event_output(struct ir *ir,
			       struct sym *map, struct sym *regs, struct sym *ev)
{
	assert(ev->irs.loc == LOC_STACK);

	ir_emit_sym_to_reg(ir, BPF_REG_1, regs);
	ir_emit_ldmap(ir, BPF_REG_2, map);
	ir_emit_insn(ir, MOV32_IMM(BPF_F_CURRENT_CPU), BPF_REG_3, 0);
	ir_emit_ldbp(ir, BPF_REG_4, ev->irs.stack);
	ir_emit_insn(ir, MOV_IMM(ev->irs.size), BPF_REG_5, 0);
	ir_emit_insn(ir, CALL(BPF_FUNC_perf_event_output), 0, 0);
}


int16_t ir_alloc_label (struct ir *ir)
{
	return ir->next_label--;
}

uint16_t ir_alloc_register(struct ir *ir)
{
	return ir->next_reg++;
}

ssize_t ir_alloc_stack(struct ir *ir, size_t size, size_t align)
{
	ir->sp -= size;

	if (ir->sp % align)
		ir->sp &= ~(align - 1);

	assert(ir->sp > INT16_MIN);

	return ir->sp;
}

void ir_init_irs(struct ir *ir, struct irstate *irs, struct type *t)
{
	t = type_base(t);

	if (irs->loc)
		return;

	irs->size = type_sizeof(t);

	if ((!irs->hint.stack)
	    && ((t->ttype == T_SCALAR) || (t->ttype == T_POINTER))) {
		irs->loc = LOC_REG;
		irs->reg = ir_alloc_register(ir);
		return;
	}
	
	irs->loc = LOC_STACK;

	/* a parent may already have filled in a stack position.
	 * usually this is when we're part of a map key. */
	if (!irs->stack)
		irs->stack = ir_alloc_stack(ir, irs->size, type_alignof(t));
}

void ir_init_sym(struct ir *ir, struct sym *sym)
{
	return ir_init_irs(ir, &sym->irs, sym->type);
}

struct ir *ir_new(void)
{
	struct ir *ir;

	ir = xcalloc(1, sizeof(*ir));

	ir->next_reg = vreg_base;
	ir->next_label = -1;
	return ir;
}


/* ir->bpf generation */

static void ir_bpf_vreg_replace(struct ir *ir, struct vinsn *last,
				uint16_t vreg, int reg)
{
	struct vinsn *vi;

	_d("ir_bpf_generate: v%d -> r%d\n", vreg & ~vreg_base, reg);

	for (vi = ir->vi; vi <= last; vi++) {
		if (vi->vitype != VI_INSN)
			continue;

		if (vi->insn.dst == vreg)
			vi->insn.dst = reg;
		if (vi->insn.src == vreg)
			vi->insn.src = reg;
	}	
}


static int ir_bpf_registerize_one(struct ir *ir, struct vinsn *last,
				  uint16_t vreg)
{
	struct vinsn *vi;
	uint16_t clean = 0x3ff;

	for (vi = ir->vi; clean && (vi < last); vi++) {
		if (vi->vitype != VI_INSN)
			continue;

		if (!(vi->insn.src & vreg_base))
			clean &= ~(1 << vi->insn.src);
		if (!(vi->insn.dst & vreg_base))
			clean &= ~(1 << vi->insn.dst);
		if ((BPF_CLASS(vi->insn.bpf.code) == BPF_JMP)
		    && (BPF_OP(vi->insn.bpf.code) == BPF_CALL))
			clean &= ~BPF_REG_CALLER_SAVE;
	}

	if (clean) {
		int reg;

		for (reg = BPF_REG_0; !(clean & 1); clean >>= 1, reg++);

		ir_bpf_vreg_replace(ir, last, vreg, reg);
		return 0;
	}

	/* TODO ir_bpf_vreg_spill(ir, last); */
	return -1;
}

static int ir_bpf_registerize(struct ir *ir)
{
	struct vinsn *vi;
	int err = 0;

	if (!ir->len)
		return 0;
	
	for (vi = &ir->vi[ir->len - 1]; vi >= ir->vi; vi--) {
		if (vi->vitype != VI_INSN)
			continue;

		if (vi->insn.dst & vreg_base) {
			err = ir_bpf_registerize_one(ir, vi, vi->insn.dst);
			if (err)
				return err;
		}

		if (vi->insn.src & vreg_base) {
			err = ir_bpf_registerize_one(ir, vi, vi->insn.src);
			if (err)
				return err;
		}
	}
	return err;
}

static int ir_bpf_jmp_resolve_one(struct ir *ir, struct vinsn *jmp)
{
	struct vinsn *vi;
	int off = 0;

	for (vi = jmp + 1; vi <= &ir->vi[ir->len - 1]; vi++) {
		switch (vi->vitype) {
		case VI_INSN:
		case VI_LDMAP:
			off++;
			break;
		case VI_LABEL:
			if (vi->label != jmp->insn.bpf.off)
				break;

			jmp->insn.bpf.off = off;
			return 0;
		default:
			break;
		}
	}

	return -ENOENT;
}

static int ir_bpf_jmp_resolve(struct ir *ir)
{
	struct vinsn *vi;
	int err;

	for (vi = ir->vi; vi <= &ir->vi[ir->len - 1]; vi++) {
		if (vi->vitype != VI_INSN)
			continue;

		if ((BPF_CLASS(vi->insn.bpf.code) == BPF_JMP)
		    && (vi->insn.bpf.off < 0)) {
			err = ir_bpf_jmp_resolve_one(ir, vi);
			if (err)
				return err;
		}
	}

	return 0;
}

int ir_bpf_generate(struct ir *ir)
{
	int err;

	err = ir_bpf_registerize(ir);
	if (err)
		return err;

	/* no instructions will be added/removed to the program after
	 * this point, thus it is now safe to convert labeled jumps to
	 * fixed offsets. */
	
	err = ir_bpf_jmp_resolve(ir);
	if (err)
		return err;

	return 0;
}

/* Final conversion from IR to real BPF, this is what we will load in to
 * the kernel. Thus, all maps must have been setup at this time. Most of
 * the heavy lifting has been done by ir_bpf_generate. All that's left
 * to do is to resolve map fd loads and remove all labels and
 * comments. */
int ir_bpf_extract(struct ir *ir, struct bpf_insn **insnsp, int *n_insnsp)
{
	struct bpf_insn *insns = NULL;
	struct vinsn *vi;
	int n_insns = 0;

	for (vi = ir->vi; vi <= &ir->vi[ir->len - 1]; vi++) {
		switch (vi->vitype) {
		case VI_INSN:
			insns = realloc(insns, (n_insns + 1) * sizeof(*insns));
			insns[n_insns] = vi->insn.bpf;
			insns[n_insns].dst_reg = vi->insn.dst;
			insns[n_insns].src_reg = vi->insn.src;
			n_insns++;
			break;
		case VI_LDMAP:
			assert(vi->map.sym->mapfd >= 0);

			insns = realloc(insns, (n_insns + 1) * sizeof(*insns));
			insns[n_insns] = LDDW_IMM(vi->map.sym->mapfd);
			insns[n_insns].dst_reg = vi->map.reg;
			insns[n_insns].src_reg = BPF_PSEUDO_MAP_FD;
			n_insns++;
			break;

		case VI_LABEL:
		case VI_COMMENT:
			break;
		}
	}

	*insnsp = insns;
	*n_insnsp = n_insns;
	return 0;
	
}
