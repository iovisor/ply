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

#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/version.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ply/ply.h>
#include <ply/kallsyms.h>

#define KSYMS_CACHE "/tmp/ply.ksyms"

static int ksym_cmp(const void *_key, const void *_member)
{
	const ksym_t *key = _key, *member = _member;

	if (key->start < member->start)
		return -1;
	else if (key->end > member->end)
		return 1;

	return 0;
}

/* Compare two members: for this qsort operation it is sufficient to compare
 * start addresses.
 */
static int ksym_membercmp(const void *_m1, const void *_m2)
{
	const ksym_t *m1 = _m1, *m2 = _m2;

	if (m1->start < m2->start)
		return -1;
	if (m1->start > m2->start)
		return 1;
	return 0;
}

const ksym_t *ksym_get(ksyms_t *ks, uintptr_t addr)
{
	ksym_t key = { .start = addr, .end = addr };

	return bsearch(&key, ks->cache->sym,
		       ks->cache->hdr.n_syms, sizeof(key), ksym_cmp);
}

static int ksym_prepare(FILE *fp, struct ksym *ksym)
{
	char line[0x80];
	char *p;

	while (fgets(line, sizeof(line), fp)) {
		ksym->start = strtoul(line, &p, 16);
		if (ksym->start == ULONG_MAX)
			continue;

		p++;
		if (*p != 't' && *p != 'T')
			continue;

		p += 2;
		p = strtok(p, " \t\n");
		if (!p)
			continue;

		strncpy(ksym->sym, p, sizeof(ksym->sym) - 1);
		return 0;
	}

	return EOF;
}

static int ksyms_cache_build(const char *in, const char *out)
{
	struct ksym_cache_hdr hdr = { .version = LINUX_VERSION_CODE };
	struct ksym ksym[2];
	FILE *cfp, *kfp;
	int err, i;

	kfp = fopen(in, "r");
	if (!kfp) {
		err = -errno;
		goto out;
	}

	cfp = fopen(out, "w");
	if (!cfp) {
		err = -errno;
		goto close_kfp;
	}

	if (fseek(cfp, sizeof(hdr), SEEK_CUR)) {
		err = -errno;
		goto close_cfp;
	}

	err = ksym_prepare(kfp, &ksym[0]);
	if (err)
		goto close_cfp;

	for (i = 1;; i = !i) {
		err = ksym_prepare(kfp, &ksym[i]);
		if (err == EOF) {
			err = 0;
			break;
		} else if (err)
			goto close_cfp;

		ksym[!i].end = ksym[i].start - 1;
		if (!fwrite(&ksym[!i], sizeof(ksym[!i]), 1, cfp)) {
			err = -EIO;
			goto close_cfp;
		}

		hdr.n_syms++;
	}

	/* assume no function larger than 4k */
	ksym[i].end = ksym[i].start + 0x1000;
	if (!fwrite(&ksym[i], sizeof(ksym[i]), 1, cfp)) {
		err = -EIO;
		goto close_cfp;
	}

	rewind(cfp);
	if (!fwrite(&hdr, sizeof(hdr), 1, cfp))
		err = -EIO;

close_cfp:
	fclose(cfp);
	if (err) {
		_e("failed: %s", strerror(-err));
		unlink(out);
	}
close_kfp:
	fclose(kfp);
out:
	return err;
}

static int ksyms_cache_open(ksyms_t *ks)
{
	struct stat st;
	int err;

	if (stat(KSYMS_CACHE, &st)) {
		err = ksyms_cache_build("/proc/kallsyms", KSYMS_CACHE);
		if (err)
			return err;

		if (stat(KSYMS_CACHE, &st))
			return -errno;
	}

	ks->cache_fd = open(KSYMS_CACHE, O_RDONLY);
	if (ks->cache_fd < 0)
		return -errno;

	ks->cache = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE,
			 ks->cache_fd, 0);

	/* For bsearch() to work properly, our cache must be sorted by
	 * start address.  kallsyms is not guaranteed to be in order from
	 * low address to high; modules seem to be particularly problematic.
	 * Question: do we need to sort prior to cache creation?  Might make
	 * that code a bit uglier but implicit assumption of ordering is used
	 * to figure out end addresses.
	 */
	if (ks->cache)
		qsort(ks->cache->sym, ks->cache->hdr.n_syms, sizeof(ksym_t),
		      ksym_membercmp);

	return ks->cache ? 0 : -ENOENT;
}

ksyms_t *ksyms_new(void)
{
	ksyms_t *ks;
	int err;

	ks = calloc(1, sizeof(*ks));
	assert(ks);

	err = ksyms_cache_open(ks);
	if (err)
		goto err;

	return ks;
err:
	free(ks);
	return NULL;
}
