/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>

#include <ply/internal.h>
#include <ply/ply.h>

#include "grammar.h"
#include "lexer.h"

struct ply_config ply_config = {
	.map_elems   =  0x400,
	.string_size =   0x80,
	.buf_pages   =      1,
	.stack_depth =   0x20,

	.sort = 1,
	.ksyms = 1,
	.strict = 1,
};

static void ply_map_print(struct ply *ply, struct sym *sym)
{
	struct type *t = sym->type;
	size_t key_size, val_size, row_size, n_elems;
	char *key, *val, *row, *data;
	int err;

	key_size = type_sizeof(t->map.ktype);
	val_size = type_sizeof(t->map.vtype);
	row_size = key_size + val_size;

	/* TODO: if (!ply_config.sort) => call printers directly from
	 * bpf_map_next loop. In that case we only need space for two
	 * keys and one value. This means we can get unsorted output
	 * in low memory environments. */
	data = calloc(ply_config.map_elems, row_size);
	if (!data) {
		_e("not enough memory to dump '%s'\n", sym->name);
		return;
	}

	key = data;
	val = data + key_size;

	for (n_elems = 0, err = bpf_map_next(sym->mapfd, NULL, key); !err;
	     err = bpf_map_next(sym->mapfd, key - row_size, key)) {
		err = bpf_map_lookup(sym->mapfd, key, val);
		if (err)
			goto err_free;

		key += row_size;
		val += row_size;
		n_elems++;
	}

	if (ply_config.sort)
		qsort_r(data, n_elems, row_size, type_cmp, t);

	printf("\n%s:\n", sym->name);
	for (row = data; n_elems > 0; row += row_size, n_elems--) {
		type_fprint(t, stdout, row);
		fputc('\n', stdout);
	}

err_free:
	free(data);
}

void ply_maps_print(struct ply *ply)
{
	struct sym **symp, *sym;

	symtab_foreach(&ply->globals, symp) {
		sym = *symp;

		if (sym->type->ttype == T_MAP
		    && sym->type->map.mtype != BPF_MAP_TYPE_PERF_EVENT_ARRAY
		    && sym->type->map.mtype != BPF_MAP_TYPE_STACK_TRACE)
			ply_map_print(ply, sym);
	}	
}

void ply_probe_free(struct ply *ply, struct ply_probe *pb)
{
	/* TODO */
	free(pb);
}

int __ply_probe_alloc(struct ply *ply, struct node *pspec, struct node *ast)
{
	struct ply_probe *pb, *last;
	int err;

	pb = xcalloc(1, sizeof(*pb));

	pb->ply = ply;
	pb->ast = ast;
	pb->probe = strdup(pspec->string.data);
	free(pspec);
	
	pb->provider = provider_get(pb->probe);
	if (!pb->provider) {
		_e("%#N: no provider found for %N.\n", pspec, pspec);
		err = -EINVAL;
		goto err_free_probe;
	}

	pb->ir = ir_new();

	err = pb->provider->probe(pb);
	if (err)
		goto err_free_ir;

	if (!ply->probes) {
		ply->probes = pb;
		return 0;
	}

	for (last = ply->probes; last->next; last = last->next);
	pb->prev = last;
	last->next = pb;
	return 0;

err_free_ir:
	free(pb->ir);
err_free_probe:
	free(pb->probe);
	free(pb);
	return err;
}

int ply_fparse(struct ply *ply, FILE *fp)
{
	yyscan_t scanner;
	
	if (yylex_init(&scanner))
		return -EINVAL;

	yyset_in(fp, scanner);
	if (yyparse(scanner, ply))
		return -EINVAL;
 
	yylex_destroy(scanner); 
	return 0;
}

int ply_parsef(struct ply *ply, const char *fmt, ...)
{
	va_list ap;
	size_t bufsz;
	char *buf;
	FILE *fp;
	int err;

	fp = open_memstream(&buf, &bufsz);

	va_start(ap, fmt);
	vfprintf(fp, fmt, ap);
	va_end(ap);

	rewind(fp);
	err = ply_fparse(ply, fp);
	fclose(fp);
	free(buf);
	return err;
}

static int ply_unload_map(struct ply *ply)
{
	struct sym **symp, *sym;

	symtab_foreach(&ply->globals, symp) {
		sym = *symp;

		if (sym->type->ttype != T_MAP)
			continue;

		if (sym->mapfd >= 0)
			close(sym->mapfd);
	}
	
	return 0;
}

static int ply_unload_bpf(struct ply *ply)
{
	struct ply_probe *pb;
	int err;

	ply_probe_foreach(ply, pb) {
		close(pb->bpf_fd);
	}

	return 0;
}

static int ply_unload_detach(struct ply *ply)
{
	struct ply_probe *pb;
	int err;

	ply_probe_foreach(ply, pb) {
		if (pb->special)
			continue;

		err = pb->provider->detach(pb);
		if (err)
			return err;
	}

	return 0;
}

int ply_unload(struct ply *ply)
{
	int err;

	err  = ply_unload_bpf(ply);
	err |= ply_unload_map(ply);
	return err;
}

static int ply_load_map(struct ply *ply)
{
	struct sym **symp, *sym;
	struct type *t;

	symtab_foreach(&ply->globals, symp) {
		sym = *symp;
		t = sym->type;

		if (t->ttype != T_MAP)
			continue;

		sym->mapfd = bpf_map_create(t->map.mtype,
					    type_sizeof(t->map.ktype),
					    type_sizeof(t->map.vtype),
					    t->map.len ? : ply_config.map_elems);
		if (sym->mapfd < 0) {
			_e("unable to create map '%s', errno:%d\n", sym->name, errno);
			return -errno;
		}

		if (t->map.mtype == BPF_MAP_TYPE_PERF_EVENT_ARRAY) {
			sym->priv = buffer_new(sym->mapfd);
			if (!sym->priv) {
				_e("unable to create buffer '%s'\n", sym->name);
				return -EINVAL;
			}

			if (!strcmp("stdbuf", sym->name))
				ply->stdbuf = sym;
		}
	}

	return 0;
}

static int ply_load_bpf(struct ply *ply)
{
	struct ply_probe *pb;
	size_t vlog_sz = 0;
	char *vlog = NULL;
	int err = 0;

	if (ply_config.verify) {
		/* According to libbpf, the recommended buffer size is
		 * 16MB (!) */
		vlog = malloc(16 << 20);
		if (vlog) {
			vlog_sz = 16 << 20;
			goto load;
		}

		_w("not enough memory for the recommended 16M verifier "
		   "buffer, trying 1M\n");

		vlog = malloc(1 << 20);
		if (vlog) {
			vlog_sz = 1 << 20;
			goto load;
		}

		_w("not enough memory to enable the kernel verifier output\n");
	}

load:
	ply_probe_foreach(ply, pb) {
		struct bpf_insn *insns;
		int n_insns;

		err = ir_bpf_extract(pb->ir, &insns, &n_insns);
		if (err)
			break;

		pb->bpf_fd = bpf_prog_load(pb->provider->prog_type,
					   insns, n_insns, vlog, vlog_sz);
		free(insns);
		if (pb->bpf_fd < 0) {
			_e("unable to load %s, errno:%d\n", pb->probe, errno);
			if ((errno == EINVAL) && vlog && !vlog[0])
				_w("was ply built against the running kernel?\n");
			else if (vlog && vlog[0])
				_e("output from kernel bpf verifier:\n%s\n", vlog);
			else
				_e("no output from kernel bpf verifier, "
				   "retry with debugging enabled\n");

			err = -errno;
			break;
		}
	}

	if (vlog)
		free(vlog);

	return err;
}

static int ply_load_attach(struct ply *ply)
{
	struct ply_probe *pb;
	int err;

	ply_probe_foreach(ply, pb) {
		if (!pb->special || strcmp(pb->provider->name, "BEGIN"))
			continue;

		err = pb->provider->attach(pb);
		if (err)
			return err;

		trigger_begin_probe(pb);

		err = pb->provider->detach(pb);
		if (err)
			return err;

		/* read buffer for BEGIN trigger */
		if (ply->stdbuf)
			buffer_loop((struct buffer *)ply->stdbuf->priv, 0);
	}

	ply_probe_foreach(ply, pb) {
		if (pb->special)
			continue;

		err = pb->provider->attach(pb);
		if (err)
			return err;
	}

	return 0;
}

int ply_load(struct ply *ply)
{
	int err;

	/* Maps has to be allocated first, since we need those fds
	 * before calling ir_bpf_extract. */
	err = ply_load_map(ply);
	if (err)
		goto err_free_evp;

	/* Load programs in to the kernel. */
	err = ply_load_bpf(ply);
	if (err)
		goto err_free_map;

	err = ply_load_attach(ply);
	if (err)
		goto err_free_prog;

	return 0;
err_free_prog:
	ply_unload_bpf(ply);
err_free_map:
	ply_unload_map(ply);
err_free_evp:
	/* TODO evpipe_free(&ply->evp); */
err:
	return err;

}

struct ply_return ply_loop(struct ply *ply)
{
	if (!ply->stdbuf) {
		pause();
		return (struct ply_return){ .err = 1, .val = EINTR };
	}

	return buffer_loop((struct buffer *)ply->stdbuf->priv, -1);
}

int ply_stop(struct ply *ply)
{
	struct ply_probe *pb;
	int err;

	err = perf_event_disable(ply->group_fd);
	if (err)
		return err;

	err = ply_unload_detach(ply);
	if (err)
		return err;

	/* flush existing buffer entries */
	if (ply->stdbuf)
		buffer_loop((struct buffer *)ply->stdbuf->priv, 0);

	/* run END probe at last */
	ply_probe_foreach(ply, pb) {
		if (!pb->special || strcmp(pb->provider->name, "END"))
			continue;

		err = pb->provider->attach(pb);
		if (err)
			return err;

		trigger_end_probe(pb);

		err = pb->provider->detach(pb);
		if (err)
			return err;

		/* read buffer again for END trigger */
		if (ply->stdbuf)
			buffer_loop((struct buffer *)ply->stdbuf->priv, 0);
	}
	return 0;
}

int ply_start(struct ply *ply)
{
	return perf_event_enable(ply->group_fd);
}

void ply_free(struct ply *ply)
{
	struct ply_probe *pb, *next;

	for (pb = ply->probes; pb;) {
		next = pb->next;
		ply_probe_free(ply, pb);
		pb = next;
	}

	if (ply->ksyms)
		ksyms_free(ply->ksyms);

	/* TODO: evpipe_free(&ply->evp); */

	free(ply);
}

int ply_alloc(struct ply **plyp)
{
	struct ply *ply;
	int err = -ENOMEM;
	
	ply = calloc(1, sizeof(*ply));
	if (!ply)
		goto err;

	ply->globals.global = 1;
	asprintf(&ply->group, "ply%d", getpid());
	ply->group_fd = -1;

	if (ply_config.ksyms)
		ply->ksyms = ksyms_new();

	*plyp = ply;
	return 0;
err_free:
	free(ply);
err:
	return err;
}

extern int register_special_probes(special_probe_t begin, special_probe_t end);

void ply_init(special_probe_t begin, special_probe_t end)
{
	static int init_done = 0;

	if (init_done)
		return;

	provider_init();
	built_in_init();

	register_special_probes(begin, end);

	init_done = 1;
}
