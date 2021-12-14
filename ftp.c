/*
 * Copyright (c) 2021 Omar Polo <op@omarpolo.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "compat.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <netdb.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <tls.h>
#include <unistd.h>

#if HAVE_READLINE
#include <readline/readline.h>
#include <readline/history.h>
#endif

#include "9pclib.h"
#include "kamid.h"
#include "utils.h"
#include "log.h"

/* flags */
int		 tls;
const char	*crtpath;
const char	*keypath;

/* state */
struct tls_config	*tlsconf;
struct tls		*ctx;
int			 sock;

#define PWDFID		0

#if HAVE_READLINE
static char *
read_line(const char *prompt)
{
	char *line;

again:
	if ((line = readline(prompt)) == NULL)
		return NULL;
	/* XXX: trim spaces? */
	if (*line == '\0') {
		free(line);
		goto again;
	}

	add_history(line);
	return line;
}
#else
static char *
read_line(const char *prompt)
{
	char *ch, *line = NULL;
	size_t linesize = 0;
	ssize_t linelen;

	linelen = getline(&line, &linesize, stdin);
	if (linelen == -1)
		return NULL;

	if ((ch = strchr(line, '\n')) != NULL)
		*ch = '\0';
	return line;
}
#endif

static void ATTR_DEAD
usage(int ret)
{
	fprintf(stderr, "usage: %s [-c] host[:port] [path]\n",
	    getprogname());
	fprintf(stderr, PACKAGE_NAME " suite version " PACKAGE VERSION "\n");
	exit(ret);
}

static void
do_version(void)
{
	tversion(VERSION9P, MSIZE9P);
	/* TODO: get reply */
}

static void
do_attach(const char *path)
{
	if (path == NULL)
		path = "/";

	/* TODO: do attach */
}

static void
do_connect(const char *connspec, const char *path)
{
	int handshake;
	char *host, *colon;
	const char *port;

	host = xstrdup(connspec);
	if ((colon = strchr(host, ':')) != NULL) {
		*colon = '\0';
		port = ++colon;
	} else
		port = "1337";

	if (!tls)
		fatalx("non-tls mode is not supported");

	if ((tlsconf = tls_config_new()) == NULL)
		fatalx("tls_config_new");
	tls_config_insecure_noverifycert(tlsconf);
	tls_config_insecure_noverifyname(tlsconf);
	if (tls_config_set_keypair_file(tlsconf, crtpath, keypath) == -1)
		fatalx("can't load certs (%s, %s)", crtpath, keypath);

	if ((ctx = tls_client()) == NULL)
		fatal("tls_client");
	if (tls_configure(ctx, tlsconf) == -1)
		fatalx("tls_configure: %s", tls_error(ctx));

	printf("connecting to %s:%s...", host, port);
	fflush(stdout);

	if (tls_connect(ctx, host, port) == -1)
		fatalx("can't connect to %s:%s: %s", host, port,
		    tls_error(ctx));

	for (handshake = 0; !handshake;) {
		switch (tls_handshake(ctx)) {
		case -1:
			fatalx("tls_handshake: %s", tls_error(ctx));
		case 0:
			handshake = 1;
			break;
		}
	}

	printf(" done!\n");

	do_version();
	do_attach(path);

	free(host);
}

int
main(int argc, char **argv)
{
	int	ch;

	log_init(1, LOG_DAEMON);
	log_setverbose(1);
	log_procinit(getprogname());

	while ((ch = getopt(argc, argv, "C:cK:")) != -1) {
		switch (ch) {
		case 'C':
			crtpath = optarg;
			break;
		case 'c':
			tls = 1;
			break;
		case 'K':
			keypath = optarg;
			break;
		default:
			usage(1);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc == 0)
		usage(1);

	if ((evb = evbuffer_new()) == NULL)
		fatal("evbuffer_new");

	do_connect(argv[0], argv[1]);

	for (;;) {
		char *line;

		if ((line = read_line("ftp> ")) == NULL)
			break;
		printf("read: %s\n", line);
	}

	printf("\n");
}
