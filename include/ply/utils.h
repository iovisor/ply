/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef _PLY_UTILS_H
#define _PLY_UTILS_H

#include <assert.h>

int strtonum(const char *_str, int64_t *s64, uint64_t *u64);
int isstring(const char *data, size_t len);

FILE *fopenf(const char *mode, const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3)));

void ast_fprint(FILE *fp, struct node *root);

/* This variable controls debug output for non-DEBUG build. */
extern int ply_debug;

#include "printxf.h"

#ifdef DEBUG
#define _l(_prefix, _fmt, ...)					\
	fprintxf(NULL, stderr, "\e[2m%s:%d\e[0m " _prefix _fmt,		\
		 __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define _l(_prefix, _fmt, ...)					\
	fprintxf(NULL, stderr, _prefix _fmt, ##__VA_ARGS__)
#endif

#ifdef DEBUG
#define _d(fmt, ...) _l("debug: ", fmt, ##__VA_ARGS__)
#else
#define _d(fmt, ...) if (ply_debug) _l("debug: ", fmt, ##__VA_ARGS__)
#endif

#define _i(fmt, ...) _l("info: ",    fmt, ##__VA_ARGS__)
#define _w(fmt, ...) _l("warning: ", fmt, ##__VA_ARGS__)
#define _e(fmt, ...) _l("error: ",   fmt, ##__VA_ARGS__)

#define _ne(_n, fmt, ...) _l("%#N: \e[31merror:\e[0m ", fmt, _n, ##__VA_ARGS__)
#define _nw(_n, fmt, ...) _l("%#N: \e[33mwarning:\e[0m ", fmt, _n, ##__VA_ARGS__)


#define container_of(ptr, type, member) ({			     \
                const typeof( ((type *)0)->member ) *__mptr = (ptr); \
                (type *)( (char *)__mptr - offsetof(type,member) );})

#define max(a, b)				\
	({					\
		__typeof__ (a) _a = (a);	\
		__typeof__ (b) _b = (b);	\
		_a > _b ? _a : _b;		\
	})

#define min(a, b)				\
	({					\
		__typeof__ (a) _a = (a);	\
		__typeof__ (b) _b = (b);	\
		_a < _b ? _a : _b;		\
	})

static inline void *xcalloc(size_t nmemb, size_t size)
{
	void *mem = calloc(nmemb, size);

	assert(mem);
	return mem;
}

#ifndef HAVE_QSORT_R
void qsort_r(void *base, size_t nmemb, size_t size,
	     int (*compar)(const void *, const void *, void *), void *arg);
#endif

#endif	/* _PLY_UTILS_H */
