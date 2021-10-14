/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef _PLY_INTERNAL_H
#define _PLY_INTERNAL_H

#include "arch.h"
#include "buffer.h"
#include "func.h"
#include "ir.h"
#include "node.h"
#include "provider.h"
#include "sym.h"
#include "type.h"


#include "kallsyms.h"
#include "perf_event.h"
#include "printxf.h"
#include "syscall.h"
#include "utils.h"

void built_in_init(void);

#define ARRAY_SIZE(a)  (sizeof(a) / sizeof(a[0]))

#endif	/* _PLY_INTERNAL_H */
