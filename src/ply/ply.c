/*
 * Copyright Tobias Waldekranz <tobias@waldekranz.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */
#include <assert.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/version.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include <ply/ply.h>

/* Embedded self-test.sh */
extern char _binary_self_test_sh_start;
extern char _binary_self_test_sh_end;

static void usage()
{
	fputs("ply - Dynamic tracing utility\n"
	      "\n"
	      "Usage:\n"
	      "  ply [options] <ply-text>\n"
	      "  ply [options] <ply-file>\n"
	      "\n"
	      "Options:\n"
	      "  -c COMMAND     Run COMMAND in a shell, exit upon completion.\n"
	      "  -d             Enable debug output.\n"
	      "  -e             Exit after compiling.\n"
	      "  -h             Print usage message and exit.\n"
	      "  -k             Keep going in face of trace buffer overruns.\n"
	      "  -S             Show generated BPF.\n"
	      "  -T             Run self-test.\n"
	      "  -v             Print version information.\n",
	      stderr);
}

static void self_test(char *plybin)
{
	size_t self_test_sz;
	char *cmd;
	FILE *sh;

	self_test_sz = &_binary_self_test_sh_end - &_binary_self_test_sh_start;

	asprintf(&cmd, "PLYBIN=%s /bin/sh", plybin);
	sh = popen(cmd, "w");
	free(cmd);
	if (!sh)
		goto err;

	if (fwrite(&_binary_self_test_sh_start, self_test_sz, 1, sh) != 1)
		goto err;

	exit(pclose(sh) ? 1 : 0);

err:
	_e("unable to run self-test\n");
	exit(1);
}

static void memlock_uncap(void)
{
	struct rlimit limit;
	rlim_t current;
	int err;

	err = getrlimit(RLIMIT_MEMLOCK, &limit);
	if (err) {
		_e("unable to retrieve memlock limit, "
		   "maps are likely limited in size\n");
		return;
	}

	current = limit.rlim_cur;

	/* The total size of all maps that ply is allowed to create is
	 * limited by the amount of memory that can be locked into
	 * RAM. By default, this limit can be quite low (64kB on a
	 * standard x86_64 box running a recent kernel). So this
	 * simply tells the kernel to allow ply to use as much as it
	 * needs. */
	limit.rlim_cur = limit.rlim_max = RLIM_INFINITY;
	err = setrlimit(RLIMIT_MEMLOCK, &limit);
	if (err) {
		const char *suffix = "B";

		if (!(current & 0xfffff)) {
			suffix = "MB";
			current >>= 20;
		} else if (!(current & 0x3ff)) {
			suffix = "kB";
			current >>= 10;
		}

		_w("could not remove memlock size restriction\n");
		_w("total map size is limited to %lu%s\n", current, suffix);
		return;
	}

	_d("unlimited memlock\n");
}

void dump(struct ply *ply)
{
	struct ply_probe *pb;

	if (!ply->probes) {
		printf("NO PROBES\n");
		return;
	}

	printf("\n\n-- globals\n");
	symtab_dump(&ply->globals, stdout);

	ply_probe_foreach(ply, pb) {
		printf("%s\n", pb->probe ? : "<null>");

		if (pb->ast)
			ast_fprint(stdout, pb->ast);
		else
			printf("NO AST\n");

		printf("\n-- locals\n");
		symtab_dump(&pb->locals, stdout);
		printf("-- ir\n");
		ir_dump(pb->ir, stdout);
	}
}

static void version()
{
	printf("%s (linux-version:%u~%u.%u.%u)\n",
	       PACKAGE_STRING, LINUX_VERSION_CODE,
	       (LINUX_VERSION_CODE >> 16) & 0xff,
	       (LINUX_VERSION_CODE >>  8) & 0xff,
	       (LINUX_VERSION_CODE >>  0) & 0xff);
}

static const char *sopts = "c:dehkSTv";
static struct option lopts[] = {
	{ "command",    required_argument, 0, 'c' },
	{ "debug",      no_argument,       0, 'd' },
	{ "dry-run",    no_argument,       0, 'e' },
	{ "help",       no_argument,       0, 'h' },
	{ "keep-going", no_argument,       0, 'k' },
	{ "dump",       no_argument,       0, 'S' },
	{ "self-test",  no_argument,       0, 'T' },
	{ "version",    no_argument,       0, 'v' },

	{ NULL }
};

FILE *get_src(int argc, char **argv)
{
	if (!argc)
		return NULL;

	/* if the argument names an existing file that we have access
	 * to, use it as the source. */
	if (!access(argv[0], R_OK))
		return fopen(argv[0], "r");

	/* TODO concat multiple argvs to one string and parse that as
	 * a ply script */

	/* otherwise, parse the argument as a ply script. */
	return fmemopen(argv[0], strlen(argv[0]), "r");
}

int inferior_prep(const char *cmd, int *infpid, int *inftrig)
{
	int err, pid, trig[2];

	err = pipe(trig);
	if (err)
		return err;

	*inftrig = trig[1];

	pid = fork();
	if (pid < 0)
		return pid;

	if (pid) {
		char str[16];

		*infpid = pid;

		/* allow scripts to reference the pid of the inferior
		 * as $target. */
		snprintf(str, sizeof(str), "%d", pid);
		setenv("target", str, 0);
		return 0;
	}

	/* wait for parent to compile and get ready */
	if (read(trig[0], &err, sizeof(err)) != sizeof(err))
		return -EINVAL;

	/* if parent sends us an error, don't run the command. most
	 * probably the script did not compile. */
	if (err)
		exit(0);

	return execl("/bin/sh", "sh", "-c", cmd, NULL);
}

static int term_sig = 0;
static void term(int sig)
{
	term_sig = sig;
	return;
}
static const struct sigaction term_action = {
	.sa_handler = term,
	.sa_flags = 0,
};

void __attribute__((noinline)) ply_begin_trigger(void) { asm volatile (""); }
void __attribute__((noinline)) ply_end_trigger(void) { asm volatile (""); }

int main(int argc, char **argv)
{
	struct ply *ply;
	struct ply_return ret = { .err = 1 };
	int opt, infpid, inftrig;
	int f_dryrun, f_dump;
	FILE *src;
	char *cmd = NULL;

	f_dryrun = f_dump = 0;
	while ((opt = getopt_long(argc, argv, sopts, lopts, NULL)) > 0) {
		switch (opt) {
		case 'c':
			cmd = optarg;
			break;
		case 'd':
			ply_config.verify = 1;
			break;
		case 'e':
			f_dryrun = 1;
			ply_config.ksyms = 0;
			break;
		case 'h':
			usage(); exit(0);
			break;
		case 'k':
			ply_config.strict = 0;
			break;
		case 'S':
			f_dump = 1;
			break;
		case 'T':
			self_test(argv[0]); exit(1);
			break;
		case 'v':
			version(); exit(0);
			break;

		default:
			_e("unknown option '%c'\n", opt);
			usage(); exit(1);
			break;
		}
	}

	src = get_src(argc - optind, &argv[optind]);
	if (!src) {
		_e("no input\n");
		usage(); exit(1);
	}

	if (cmd && inferior_prep(cmd, &infpid, &inftrig))
		exit(1);

	/* TODO figure this out dynamically. terminfo? */
	ply_config.unicode = 1;

	ply_init(ply_begin_trigger, ply_end_trigger);

	ply_alloc(&ply);
	ret.val = ply_fparse(ply, src);
	if (ret.val)
		goto err;

	ret.val = ply_compile(ply);

	if (f_dump)
		dump(ply);

	if (ret.val)
		goto err;

	if (f_dryrun)
		goto unload;

	memlock_uncap();

	ret.val = ply_load(ply);
	if (ret.val)
		goto err;

	ply_start(ply);
	_d("ply: active\n");

	sigaction(SIGINT, &term_action, NULL);
	sigaction(SIGCHLD, &term_action, NULL);

	if (cmd) {
		int err = 0;

		if (write(inftrig, &err, sizeof(err)) != sizeof(err)) {
			fprintf(stderr, "ply: unable to start command\n");
			ret.err = 1;
			ret.val = -EIO;
			goto stop;
		}
	}

	ret = ply_loop(ply);
	if (ret.err && (ret.val == EINTR) && term_sig)
		ret.err = 0;
stop:
	_d("ply: deactivating\n");
	ply_stop(ply);

	ply_maps_print(ply);

unload:
	ply_unload(ply);

err:
	ply_free(ply);

	if (ret.err) {
		if (ret.val)
			printf("ERR:%d\n", ret.val);

		return 1;
	}

	return ret.exit ? ret.val : 0;
}
