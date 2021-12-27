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

#include <assert.h>
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
struct evbuffer		*buf;
uint32_t		 msize;

#define PWDFID		0

#define ASSERT_EMPTYBUF() assert(EVBUFFER_LENGTH(buf) == 0)

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

	printf("%s", prompt);
	fflush(stdout);

	linelen = getline(&line, &linesize, stdin);
	if (linelen == -1)
		return NULL;

	if ((ch = strchr(line, '\n')) != NULL)
		*ch = '\0';
	return line;
}
#endif

static void __dead
usage(int ret)
{
	fprintf(stderr, "usage: %s [-c] host[:port] [path]\n",
	    getprogname());
	fprintf(stderr, PACKAGE_NAME " suite version " PACKAGE VERSION "\n");
	exit(ret);
}

static void
do_send(void)
{
	ssize_t r;

	while (EVBUFFER_LENGTH(evb) != 0) {
		r = tls_write(ctx, EVBUFFER_DATA(evb), EVBUFFER_LENGTH(evb));
		switch (r) {
		case TLS_WANT_POLLIN:
		case TLS_WANT_POLLOUT:
			continue;
		case -1:
			errx(1, "tls: %s", tls_error(ctx));
		default:
			evbuffer_drain(evb, r);
		}
	}
}

static void
mustread(void *d, size_t len)
{
	ssize_t r;

	while (len != 0) {
		switch (r = tls_read(ctx, d, len)) {
		case TLS_WANT_POLLIN:
		case TLS_WANT_POLLOUT:
			continue;
		case -1:
			errx(1, "tls: %s", tls_error(ctx));
		default:
			d += r;
			len -= r;
		}
	}
}

static void
recv_msg(void)
{
	uint32_t	len;
	ssize_t		r;
	char		tmp[BUFSIZ];

	mustread(&len, sizeof(len));
	len = le32toh(len);
	if (len < HEADERSIZE)
		errx(1, "read message of invalid length %d", len);

	len -= 4; /* skip the length just read */

	while (len != 0) {
		switch (r = tls_read(ctx, tmp, sizeof(tmp))) {
		case TLS_WANT_POLLIN:
		case TLS_WANT_POLLOUT:
			continue;
		case -1:
			errx(1, "tls: %s", tls_error(ctx));
		default:
			len -= r;
			evbuffer_add(buf, tmp, r);
		}
	}
}

static uint64_t
np_read64(void)
{
	uint64_t n;

	evbuffer_remove(buf, &n, sizeof(n));
	return le64toh(n);
}

static uint32_t
np_read32(void)
{
	uint32_t n;

	evbuffer_remove(buf, &n, sizeof(n));
	return le32toh(n);
}

static uint16_t
np_read16(void)
{
	uint16_t n;

	evbuffer_remove(buf, &n, sizeof(n));
	return le16toh(n);
}

static uint16_t
np_read8(void)
{
	uint8_t n;

	evbuffer_remove(buf, &n, sizeof(n));
	return n;
}

static char *
np_readstr(void)
{
	uint16_t	 len;
	char		*str;

	len = np_read16();
	assert(EVBUFFER_LENGTH(buf) >= len);

	if ((str = calloc(1, len+1)) == NULL)
		err(1, "calloc");
	evbuffer_remove(buf, str, len);
	return str;
}

static void
np_read_qid(struct qid *qid)
{
	assert(EVBUFFER_LENGTH(buf) >= QIDSIZE);

	qid->type = np_read8();
	qid->vers = np_read32();
	qid->path = np_read64();
}

static void
expect(uint8_t type)
{
	uint8_t t;

	t = np_read8();
	if (t == type)
		return;

	if (t == Terror) {
		char *err;

		err = np_readstr();
		errx(1, "expected %s, got error %s",
		    pp_msg_type(type), err);
	}

	errx(1, "expected %s, got msg type %s",
	    pp_msg_type(type), pp_msg_type(t));
}

static void
expect2(uint8_t type, uint16_t tag)
{
	uint16_t t;

	expect(type);

	t = np_read16();
	if (t == tag)
		return;

	errx(1, "expected tag 0x%x, got 0x%x", tag, t);
}

static void
do_version(void)
{
	char		*version;

	tversion(VERSION9P, MSIZE9P);
	do_send();
	recv_msg();
	expect2(Rversion, NOTAG);

	msize = np_read32();
	version = np_readstr();

	if (msize > MSIZE9P)
		errx(1, "got unexpected msize: %d", msize);
	if (strcmp(version, VERSION9P))
		errx(1, "unexpected 9p version: %s", version);

	free(version);
	ASSERT_EMPTYBUF();
}

static void
do_attach(const char *path)
{
	const char *user;
	struct qid qid;

	if (path == NULL)
		path = "/";
	if ((user = getenv("USER")) == NULL)
		user = "flan";

	tattach(PWDFID, NOFID, user, path);
	do_send();
	recv_msg();
	expect2(Rattach, iota_tag);
	np_read_qid(&qid);
	ASSERT_EMPTYBUF();
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

	if ((buf = evbuffer_new()) == NULL)
		fatal("evbuffer_new");

	do_connect(argv[0], argv[1]);

	for (;;) {
		char *line;

		if ((line = read_line("kamiftp> ")) == NULL)
			break;
		printf("read: %s\n", line);
		free(line);
	}

	printf("\n");
}
