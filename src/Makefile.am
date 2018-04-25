AUTOMAKE_OPTIONS = subdir-objects
SUFFIXES         = .c .h .y
sbin_PROGRAMS    = ply
ACLOCAL_AMFLAGS  = -I ../m4
AM_YFLAGS        = -d -Wall
ply_CFLAGS       = -I$(top_srcdir)/src/include
ply_CFLAGS      += -DGIT_VERSION=\"$(shell git describe --always --dirty)\"

lang/lex.h: lang/lex.c
lang/lex.c: lang/lex.l
	@echo "  LEX      $@"
	@flex --header-file=lang/lex.h --outfile=$@ $<

BUILT_SOURCES = lang/lex.h lang/parse.h
ply_SOURCES   = lang/lex.c lang/parse.y lang/ast.c
ply_SOURCES  += module/module.c module/common.c module/method.c module/printf.c \
		module/probe.c module/quantize.c module/trace.c
ply_SOURCES  += pvdr/pvdr.c pvdr/kprobe.c pvdr/tracepoint.c pvdr/profile.c \
		pvdr/uprobe.c
ply_SOURCES  += annotate.c bpf-syscall.c compile.c evpipe.c kallsyms.c \
		map.c ply.c symtable.c utils.c

ply_SOURCES  += arch/arch-null.c
if ARCH_ARM
ply_SOURCES  += arch/arch-arm.c
endif
if ARCH_AARCH64
ply_SOURCES  += arch/arch-aarch64.c
endif
if ARCH_X86_64
ply_SOURCES  += arch/arch-x86_64.c
endif

if KERNEL_DIR
BUILT_SOURCES += .kernel/include/linux/version.h
ply_CFLAGS    += -I .kernel/include

kernelenv := ARCH=@host_cpu@
kernelenv += INSTALL_HDR_PATH=$(shell pwd)/.kernel

.kernel/include/linux/version.h:
	@echo "  HEADERS  @kerneldir@(@host_cpu@)"
	make -C @kerneldir@ $(kernelenv) headers_install

distclean-local:
	rm -rf .kernel
endif

clean-local:
	rm -f lang/lex.[ch] lang/parse.[ch]
