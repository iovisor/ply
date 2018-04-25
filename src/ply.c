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

#include <getopt.h>
#include <linux/version.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>

#include <ply/ast.h>
#include <ply/evpipe.h>
#include <ply/map.h>
#include <ply/ply.h>
#include <ply/pvdr.h>

#include "config.h"

FILE *scriptfp;

struct globals G;

static const char *sopts = "AcdDhPt:v";
static struct option lopts[] = {
	{ "ascii",     no_argument,       0, 'A' },
	{ "command",   no_argument,       0, 'c' },
	{ "debug",     no_argument,       0, 'd' },
	{ "dump",      no_argument,       0, 'D' },
	{ "help",      no_argument,       0, 'h' },
	{ "providers", no_argument,       0, 'P' },
	{ "timeout",   required_argument, 0, 't' },
	{ "version",   no_argument,       0, 'v' },

	{ NULL }
};

static void usage()
{
	puts("ply - Dynamic tracing utility\n"
	     "\n"
	     "Usage:\n"
	     "  ply [options] <script_file>\n"
	     "  ply [options] -c <script_string>\n"
	     "\n"
	     "Options:\n"
	     "  -A                  ASCII output only, no Unicode.\n"
	     "  -c <script_string>  Execute script literate.\n"
	     "  -d                  Enable debug output.\n"
	     "  -D                  Dump generated BPF and exit.\n"
	     "  -h                  Print usage message and exit.\n"
		 "  -P                  Print available Providers.\n"
	     "  -t <timeout>        Terminate trace after <timeout> seconds.\n"
	     "  -v                  Print version information.\n"
		);
}

static void version()
{
	fputs(PACKAGE "-" VERSION, stdout);
	if (strcmp(VERSION, GIT_VERSION))
		fputs("(" GIT_VERSION ")", stdout);

	printf(" (linux-version:%u~%u.%u.%u)\n",
	       LINUX_VERSION_CODE,
	       (LINUX_VERSION_CODE >> 16) & 0xff,
	       (LINUX_VERSION_CODE >>  8) & 0xff,
	       (LINUX_VERSION_CODE >>  0) & 0xff);
}

static int parse_opts(int argc, char **argv, FILE **sfp)
{
	int cmd = 0;
	int opt;

	G.map_nelem = 0x400;

	while ((opt = getopt_long(argc, argv, sopts, lopts, NULL)) > 0) {
		switch (opt) {
		case 'A':
			G.ascii = 1;
			break;
		case 'c':
			cmd = 1;
			break;
		case 'd':
			G.debug = 1;
			break;
		case 'D':
			G.dump = 1;
			break;
		case 'h':
			usage(); exit(0);
			break;
		case 'P':
			pvdr_print();
			exit(0);
			break;
		case 't':
			G.timeout = strtol(optarg, NULL, 0);
			if (G.timeout <= 0) {
				_e("timeout must be a positive integer");
				usage(); exit(1);
			}
			break;
		case 'v':
			version(); exit(0);
			break;

		default:
			_e("unknown option '%c'", opt);
			usage(); exit(1);
			break;
		}
	}

	if (cmd)
		*sfp = fmemopen(argv[optind], strlen(argv[optind]), "r");
	else if (optind < argc)
		*sfp = fopen(argv[optind], "r");
	else {
		_e("no input");
		usage(); exit(1);
	}

	if (!*sfp) {
		_eno("unable to read script");
		usage(); exit(1);
	}

	return 0;
}

static void memlock_uncap(void)
{
	struct rlimit limit;
	rlim_t current;
	int err;

	err = getrlimit(RLIMIT_MEMLOCK, &limit);
	if (err) {
		_eno("unable to retrieve memlock limit, "
		     "maps are likely limited in size");
		return;
	}

	current = limit.rlim_cur;

	/* The total size of all maps that ply is allowed to create is
	 * limited by the amount of memory that can be locked into
	 * RAM. By default, this limit can be quite low (64kB on the
	 * author's system). So this simply tells the kernel to allow
	 * ply to use as much as it needs. */
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

		_eno("could not remove memlock size restriction");
		_w("total map size is limited to %lu%s", current, suffix);
		return;
	}

	_d("unlimited memlock");
}

static int term_sig = 0;
static void term(int sig)
{
	term_sig = sig;
	return;
}

int main(int argc, char **argv)
{
	evpipe_t *evp;
	node_t *probe, *script;
	prog_t *prog = NULL;
	pvdr_t *pvdr;
	FILE *sfp;
	int err = 0, num, total;

	G.self = getpid();
	scriptfp = stdin;
	err = parse_opts(argc, argv, &sfp);
	if (err)
		goto err;

	G.ksyms = ksyms_new();
	memlock_uncap();

	script = node_script_parse(sfp);
	if (!script) {
		err = -EINVAL;
		goto err;
	}

	err = pvdr_resolve(script);
	if (err)
		goto err;

	err = annotate_script(script);
	if (err)
		goto err;

	evp = calloc(1, sizeof(*evp));
	assert(evp);
	script->dyn->script.evp = evp;

	err = evpipe_init(evp, 4 << 10);
	if (err)
		goto err;

	err = map_setup(script);
	if (err)
		goto err;
		
	if (G.dump)
		node_ast_dump(script);

	total = 0;
	node_foreach(probe, script->script.probes) {
		err = -EINVAL;
		prog = compile_probe(probe);
		if (!prog)
			break;

		if (G.dump)
			continue;

		pvdr = node_get_pvdr(probe);
		num = pvdr->setup(probe, prog);
		if (num < 0)
			break;

		total += num;
	}

	if (G.dump)
		goto done;
	
	if (num < 0) {
		err = num;
		goto err;
	}

	if (G.timeout) {
		siginterrupt(SIGALRM, 1);
		signal(SIGALRM, term);
		alarm(G.timeout);
	}

	siginterrupt(SIGINT, 1);
	signal(SIGINT, term);
	
	fprintf(stderr, "%d probe%s active\n", total, (total == 1) ? "" : "s");
	err = evpipe_loop(evp, &term_sig, 0);

	fprintf(stderr, "de-activating probes\n");

	map_teardown(script);

	node_foreach(probe, script->script.probes) {
		pvdr = node_get_pvdr(probe);
		err = pvdr->teardown(probe);
		if (err)
			break;
	}

done:
err:
	if (prog)
		free(prog);
	if (script)
		node_free(script);

	return err ? 1 : 0;
}
