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
#include <errno.h>
#include <netdb.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <tls.h>
#include <unistd.h>

#if HAVE_LIBREADLINE
#include <readline/readline.h>
#include <readline/history.h>
#endif

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
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
struct evbuffer		*dirbuf;
uint32_t		 msize;
int			 bell;

#define PWDFID		0

#define ASSERT_EMPTYBUF() assert(EVBUFFER_LENGTH(buf) == 0)

#if HAVE_LIBREADLINE
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
	const void	*buf;
	size_t		 nbytes;
	ssize_t		 r;

	while (EVBUFFER_LENGTH(evb) != 0) {
		buf = EVBUFFER_DATA(evb);
		nbytes = EVBUFFER_LENGTH(evb);

		if (ctx == NULL) {
			r = write(sock, buf, nbytes);
			if (r == 0 || r == -1)
				errx(1, "EOF");
		} else {
			r = tls_write(ctx, buf, nbytes);
			if (r == TLS_WANT_POLLIN || r == TLS_WANT_POLLOUT)
				continue;
			if (r == -1)
				errx(1, "tls: %s", tls_error(ctx));
		}

		evbuffer_drain(evb, r);
	}
}

static void
mustread(void *d, size_t len)
{
	ssize_t r;

	while (len != 0) {
		if (ctx == NULL) {
			r = read(sock, d, len);
			if (r == 0 || r == -1)
				errx(1, "EOF");
		} else {
			r = tls_read(ctx, d, len);
			if (r == TLS_WANT_POLLIN || r == TLS_WANT_POLLOUT)
				continue;
			if (r == -1)
				errx(1, "tls: %s", tls_error(ctx));
		}

		d += r;
		len -= r;
	}
}

static void
recv_msg(void)
{
	uint32_t	len, l;
	char		tmp[BUFSIZ];

	mustread(&len, sizeof(len));
	len = le32toh(len);
	if (len < HEADERSIZE)
		errx(1, "read message of invalid length %d", len);

	len -= 4; /* skip the length just read */

	while (len != 0) {
		l = MIN(len, sizeof(tmp));
		mustread(tmp, l);
		len -= l;
		evbuffer_add(buf, tmp, l);
	}
}

static uint64_t
np_read64(struct evbuffer *buf)
{
	uint64_t n;

	evbuffer_remove(buf, &n, sizeof(n));
	return le64toh(n);
}

static uint32_t
np_read32(struct evbuffer *buf)
{
	uint32_t n;

	evbuffer_remove(buf, &n, sizeof(n));
	return le32toh(n);
}

static uint16_t
np_read16(struct evbuffer *buf)
{
	uint16_t n;

	evbuffer_remove(buf, &n, sizeof(n));
	return le16toh(n);
}

static uint16_t
np_read8(struct evbuffer *buf)
{
	uint8_t n;

	evbuffer_remove(buf, &n, sizeof(n));
	return n;
}

static char *
np_readstr(struct evbuffer *buf)
{
	uint16_t	 len;
	char		*str;

	len = np_read16(buf);
	assert(EVBUFFER_LENGTH(buf) >= len);

	if ((str = calloc(1, len+1)) == NULL)
		err(1, "calloc");
	evbuffer_remove(buf, str, len);
	return str;
}

static void
np_read_qid(struct evbuffer *buf, struct qid *qid)
{
	assert(EVBUFFER_LENGTH(buf) >= QIDSIZE);

	qid->type = np_read8(buf);
	qid->vers = np_read32(buf);
	qid->path = np_read64(buf);
}

static void
expect(uint8_t type)
{
	uint8_t t;

	t = np_read8(buf);
	if (t == type)
		return;

	if (t == Terror) {
		char *err;

		err = np_readstr(buf);
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

	t = np_read16(buf);
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

	msize = np_read32(buf);
	version = np_readstr(buf);

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
	np_read_qid(buf, &qid);

	ASSERT_EMPTYBUF();
}

static uint32_t
do_open(uint32_t fid, uint8_t mode)
{
	struct qid qid;
	uint32_t iounit;

	topen(fid, mode);
	do_send();
	recv_msg();
	expect2(Ropen, iota_tag);

	np_read_qid(buf, &qid);
	iounit = np_read32(buf);

	ASSERT_EMPTYBUF();

	return iounit;
}

static void
do_clunk(uint32_t fid)
{
	tclunk(fid);
	do_send();
	recv_msg();
	expect2(Rclunk, iota_tag);

	ASSERT_EMPTYBUF();
}

static void
dup_fid(int fid, int nfid)
{
	uint16_t nwqid;

	twalk(fid, nfid, NULL, 0);
	do_send();
	recv_msg();
	expect2(Rwalk, iota_tag);

	nwqid = np_read16(buf);
	assert(nwqid == 0);

	ASSERT_EMPTYBUF();
}

static void
do_tls_connect(const char *host, const char *port)
{
	int handshake;

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
}

static void
do_ctxt_connect(const char *host, const char *port)
{
	struct addrinfo hints, *res, *res0;
	int error, saved_errno;
	const char *cause = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	error = getaddrinfo(host, port, &hints, &res0);
	if (error)
		errx(1, "%s", gai_strerror(error));

	sock = -1;
	for (res = res0; res != NULL; res = res->ai_next) {
		sock = socket(res->ai_family, res->ai_socktype,
		    res->ai_protocol);
		if (sock == -1) {
			cause = "socket";
			continue;
		}

		if (connect(sock, res->ai_addr, res->ai_addrlen) == -1) {
			cause = "connect";
			saved_errno = errno;
			close(sock);
			errno = saved_errno;
			sock = -1;
			continue;
		}

		break;
	}

	if (sock == -1)
		err(1, "%s", cause);
	freeaddrinfo(res0);
}

static void
do_connect(const char *connspec, const char *path)
{
	char *host, *colon;
	const char *port;

	host = xstrdup(connspec);
	if ((colon = strchr(host, ':')) != NULL) {
		*colon = '\0';
		port = ++colon;
	} else
		port = "1337";

	printf("connecting to %s:%s...", host, port);
	fflush(stdout);

	if (tls)
		do_tls_connect(host, port);
	else
		do_ctxt_connect(host, port);

	printf(" done!\n");

	do_version();
	do_attach(path);

	free(host);
}

static void
cmd_bell(int argc, const char **argv)
{
	if (argc == 0) {
		bell = !bell;
		if (bell)
			puts("bell mode enabled");
		else
			puts("bell mode disabled");
		return;
	}

	if (argc != 1)
		goto usage;

	if (!strcmp(*argv, "on")) {
		bell = 1;
		puts("bell mode enabled");
		return;
	}

	if (!strcmp(*argv, "off")) {
		bell = 0;
		puts("bell mode disabled");
		return;
	}

usage:
	printf("bell [on | off]\n");
}

static void
cmd_bye(int argc, const char **argv)
{
	log_warnx("bye\n");
	exit(0);
}

static void
cmd_ls(int argc, const char **argv)
{
	uint64_t off = 0;
	uint32_t len;

	if (argc != 0) {
		printf("ls don't take arguments (yet)\n");
		return;
	}

	dup_fid(PWDFID, 1);
	do_open(1, KOREAD);

	evbuffer_drain(dirbuf, EVBUFFER_LENGTH(dirbuf));

	for (;;) {
		tread(1, off, BUFSIZ);
		do_send();
		recv_msg();
		expect2(Rread, iota_tag);

		len = np_read32(buf);
		if (len == 0)
			break;

		evbuffer_add_buffer(dirbuf, buf);
		off += len;

		ASSERT_EMPTYBUF();
	}

	while (EVBUFFER_LENGTH(dirbuf) != 0) {
		struct qid	 qid;
		uint64_t	 len;
		uint16_t	 size;
		char		*name;

		size = np_read16(dirbuf);
		assert(size <= EVBUFFER_LENGTH(dirbuf));

		np_read16(dirbuf); /* skip type */
		np_read32(dirbuf); /* skip dev */

		np_read_qid(dirbuf, &qid);
		printf("%s ", pp_qid_type(qid.type));

		np_read32(dirbuf); /* skip mode */
		np_read32(dirbuf); /* skip atime */
		np_read32(dirbuf); /* skip mtime */

		len = np_read64(dirbuf);
		printf("%llu ", (unsigned long long)len);

		name = np_readstr(dirbuf);
		printf("%s\n", name);
		free(name);

		free(np_readstr(dirbuf)); /* skip uid */
		free(np_readstr(dirbuf)); /* skip gid */
		free(np_readstr(dirbuf)); /* skip muid */
	}

	do_clunk(1);
}

static void
cmd_verbose(int argc, const char **argv)
{
	if (argc == 0) {
		log_setverbose(!log_getverbose());
		if (log_getverbose())
			puts("verbose mode enabled");
		else
			puts("verbose mode disabled");
		return;
	}

	if (argc != 1)
		goto usage;

	if (!strcmp(*argv, "on")) {
		log_setverbose(1);
		puts("verbose mode enabled");
		return;
	}

	if (!strcmp(*argv, "off")) {
		log_setverbose(0);
		puts("verbose mode disabled");
		return;
	}

usage:
	printf("verbose [on | off]\n");
}

static void
excmd(int argc, const char **argv)
{
	struct cmd {
		const char	*name;
		void		(*fn)(int, const char **);
	} cmds[] = {
		{"bell",	cmd_bell},
		{"bye",		cmd_bye},
		{"ls",		cmd_ls},
		{"quit",	cmd_bye},
		{"verbose",	cmd_verbose},
	};
	size_t i;

	if (argc == 0)
		return;
	for (i = 0; i < nitems(cmds); ++i) {
		if (!strcmp(cmds[i].name, *argv)) {
			cmds[i].fn(argc-1, argv+1);
			return;
		}
	}

	log_warnx("unknown command %s", *argv);
}

int
main(int argc, char **argv)
{
	int	ch;

	log_init(1, LOG_DAEMON);
	log_setverbose(0);
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

	if ((dirbuf = evbuffer_new()) == NULL)
		fatal("evbuferr_new");

	do_connect(argv[0], argv[1]);

	/* cmd_ls(0, NULL); */

	for (;;) {
		int argc = 0;
		char *line, *argv[16] = {0}, **ap;

		if ((line = read_line("kamiftp> ")) == NULL)
			break;

		for (argc = 0, ap = argv; ap < &argv[15] &&
		    (*ap = strsep(&line, " \t")) != NULL;) {
			if (**ap != '\0')
				ap++, argc++;
		}
		excmd(argc, (const char **)argv);

		if (bell) {
			printf("\a");
			fflush(stdout);
		}

		free(line);
	}

	printf("\n");
}
