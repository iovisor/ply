lib_LTLIBRARIES       = libply.la

libply_la_CPPFLAGS    = -include $(top_builddir)/config.h -I $(top_srcdir)/include
libply_la_CFLAGS      = -Wall -Wextra -Wno-unused -Wno-unused-result
libply_la_LDFLAGS     = $(AM_LDFLAGS) -version-info 0:0:0

AM_YFLAGS = -d -Wall
AM_LFLAGS = --header-file=lexer.h

EXTRA_DIST = grammar.c grammar.h lexer.c lexer.h \
	arch/aarch64.c \
	arch/arm.c     \
	arch/mips.c    \
	arch/powerpc.c \
	arch/riscv32.c \
	arch/riscv64.c \
	arch/x86_64.c

BUILT_SOURCES = grammar.h lexer.h

libply_la_SOURCES     = 	\
	arch/@arch@.c		\
	\
	aux/kallsyms.c		\
	aux/perf_event.c	\
	aux/printxf.c		\
	aux/syscall.c		\
	aux/utils.c		\
	\
	built-in/aggregation.c	\
	built-in/built-in.c	\
	built-in/built-in.h	\
	built-in/buffer.c	\
	built-in/flow.c		\
	built-in/math.c		\
	built-in/memory.c	\
	built-in/print.c	\
	built-in/proc.c		\
	\
	provider/interval.c	\
	provider/kprobe.c	\
	provider/kprobe.h	\
	provider/kretprobe.c	\
	provider/profile.c	\
	provider/special.c	\
	provider/tracepoint.c	\
	provider/xprobe.c	\
	provider/xprobe.h	\
	\
	compile.c		\
	func.c			\
	grammar.y		\
	ir.c			\
	lexer.l			\
	node.c			\
	provider.c		\
	sym.c			\
	type.c			\
	\
	libply.c

libply_la_LIBADD = $(LTLIBOBJS)

lexer.h: lexer.c
