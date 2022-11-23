/*
 * Copyright (c) 2021, 2022 Omar Polo <op@omarpolo.com>
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

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <libgen.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <tls.h>
#include <unistd.h>

#ifdef HAVE_READLINE
#include <readline/readline.h>
#include <readline/history.h>
#endif

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

#include "kami.h"
#include "utils.h"
#include "log.h"
#include "9pclib.h"

#define TMPFSTR		"/tmp/kamiftp.XXXXXXXXXX"
#define TMPFSTRLEN	sizeof(TMPFSTR)

/* flags */
int		 tls;
const char	*crtpath;
const char	*keypath;

/* state */
FILE			*fp;
struct evbuffer		*buf;
struct evbuffer		*dirbuf;
uint32_t		 msize;
int			 bell;

volatile sig_atomic_t	 resized;
int			 tty_p;
int			 tty_width;
int			 xdump;

struct progress {
	uint64_t	max;
	uint64_t	done;
};

int pwdfid;

#define ASSERT_EMPTYBUF() assert(EVBUFFER_LENGTH(buf) == 0)

#if !HAVE_READLINE
char *
readline(const char *prompt)
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

void
add_history(const char *line)
{
	return;
}
#endif

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

static void
spawn(const char *argv0, ...)
{
	pid_t pid;
	size_t i;
	int status;
	const char *argv[16], *last;
	va_list ap;

	memset(argv, 0, sizeof(argv));

	va_start(ap, argv0);
	argv[0] = argv0;
	for (i = 1; i < nitems(argv); ++i) {
		last = va_arg(ap, const char *);
		if (last == NULL)
			break;
		argv[i] = last;
	}
	va_end(ap);

	assert(last == NULL);

	switch (pid = fork()) {
	case -1:
		err(1, "fork");
	case 0: /* child */
		execvp(argv[0], (char *const *)argv);
		err(1, "execvp");
	default:
		waitpid(pid, &status, 0);
	}
}

static int
stdio_tls_write(void *arg, const char *buf, int len)
{
	struct tls	*ctx = arg;
	ssize_t		 ret;

	do {
		ret = tls_write(ctx, buf, len);
	} while (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT);

	if (ret == -1)
		warn("tls_write: %s", tls_error(ctx));

	return ret;
}

static int
stdio_tls_read(void *arg, char *buf, int len)
{
	struct tls	*ctx = arg;
	ssize_t		 ret;

	do {
		ret = tls_read(ctx, buf, len);
	} while (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT);

	if (ret == -1)
		warn("tls_read: %s", tls_error(ctx));

	return ret;
}

static int
stdio_tls_close(void *arg)
{
	struct tls	*ctx = arg;
	int		 ret;

	do {
		ret = tls_close(ctx);
	} while (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT);

	return ret;
}

static void
tty_resized(int signo)
{
	resized = 1;
}

static void __dead
usage(int ret)
{
	fprintf(stderr, "usage: %s [-c] [-C cert] [-K key] "
	    "[user@]host[:port][/path]\n", getprogname());
	fprintf(stderr, "kamid suite version " KAMID_VERSION "\n");
	exit(ret);
}

static int
nextfid(void)
{
	uint32_t i;

	for (i = 0; ; ++i) {
		if (i != pwdfid)
			return i;
	}
}

static void
do_send(void)
{
	size_t		 r;

	if (xdump)
		hexdump("outgoing message", EVBUFFER_DATA(evb),
		    EVBUFFER_LENGTH(evb));

	while (EVBUFFER_LENGTH(evb) != 0) {
		r = fwrite(EVBUFFER_DATA(evb), 1, EVBUFFER_LENGTH(evb), fp);
		if (r == 0)
			fatalx("unexpected EOF");
		evbuffer_drain(evb, r);
	}
}

static void
mustread(void *d, size_t len)
{
	size_t r;

	r = fread(d, 1, len, fp);
	if (r != len)
		errx(1, "unexpected EOF");
}

static void
recv_msg(void)
{
	size_t		r;
	uint32_t	len, l;
	char		tmp[BUFSIZ];

	r = fread(&len, 1, sizeof(len), fp);
	if (r != sizeof(len))
		errx(1, "unexpected EOF");

	len = le32toh(len);
	if (len < HEADERSIZE)
		errx(1, "read message of invalid length %d", len);

	len -= 4; /* skip the length just read */

	while (len != 0) {
		l = MIN(len, sizeof(tmp));

		r = fread(tmp, 1, l, fp);
		if (r != l)
			errx(1, "unexpected EOF");
		len -= r;
		evbuffer_add(buf, tmp, r);
	}

	if (xdump)
		hexdump("incoming packet", EVBUFFER_DATA(buf),
		    EVBUFFER_LENGTH(buf));
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

static int
np_read_stat(struct evbuffer *buf, struct np_stat *st)
{
	uint16_t size;

	memset(st, 0, sizeof(*st));

	size = np_read16(buf);
	if (size > EVBUFFER_LENGTH(buf))
		return -1;

	st->type = np_read16(buf);
	st->dev = np_read32(buf);
	np_read_qid(buf, &st->qid);
	st->mode = np_read32(buf);
	st->atime = np_read32(buf);
	st->mtime = np_read32(buf);
	st->length = np_read64(buf);
	st->name = np_readstr(buf);
	st->uid = np_readstr(buf);
	st->gid = np_readstr(buf);
	st->muid = np_readstr(buf);

	return 0;
}

static void
expect(uint8_t type)
{
	uint8_t t;

	t = np_read8(buf);
	if (t == type)
		return;

	if (t == Rerror) {
		char *err;

		/* skip tag */
		np_read16(buf);

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

static char *
check(uint8_t type, uint16_t tag)
{
	uint16_t rtag;
	uint8_t rtype;

	rtype = np_read8(buf);
	rtag = np_read16(buf);
	if (rtype == type) {
		if (rtag != tag)
			errx(1, "expected tag 0x%x, got 0x%x", tag, rtag);
		return NULL;
	}

	if (rtype == Rerror)
		return np_readstr(buf);

	errx(1, "expected %s, got msg type %s",
	    pp_msg_type(type), pp_msg_type(rtype));
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

	if (msize > MSIZE9P || msize < 256)
		errx(1, "got unexpected msize: %d", msize);
	if (strcmp(version, VERSION9P))
		errx(1, "unexpected 9p version: %s", version);

	free(version);
	ASSERT_EMPTYBUF();
}

static void
do_attach(const char *user)
{
	struct qid qid;

	tattach(pwdfid, NOFID, user, "/");
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

static uint32_t
do_create(uint32_t fid, const char *name, uint32_t perm, uint8_t mode)
{
	struct qid qid;
	uint32_t iounit;

	tcreate(fid, name, perm, mode);
	do_send();
	recv_msg();
	expect2(Rcreate, iota_tag);

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

static char *
dup_fid(int fid, int nfid)
{
	uint16_t nwqid;
	char *errstr;

	twalk(fid, nfid, NULL, 0);
	do_send();
	recv_msg();

	if ((errstr = check(Rwalk, iota_tag)) != NULL)
		return errstr;

	nwqid = np_read16(buf);
	assert(nwqid == 0);

	ASSERT_EMPTYBUF();

	return NULL;
}

static char *
walk_path(int fid, int newfid, const char *path, int *missing,
    struct qid *qid)
{
	char *wnames[MAXWELEM], *p, *t, *errstr;
	size_t nwname, i;
	uint16_t nwqid;

	if ((p = strdup(path)) == NULL)
		err(1, "strdup");
	t = p;

	/* strip initial ./ */
	if (t[0] == '.' && t[1] == '/')
		t += 2;

	for (nwname = 0; nwname < nitems(wnames) &&
	    (wnames[nwname] = strsep(&t, "/")) != NULL;) {
		if (*wnames[nwname] != '\0')
			nwname++;
	}

	twalk(fid, newfid, (const char **)wnames, nwname);
	do_send();
	recv_msg();

	*missing = nwname;
	if ((errstr = check(Rwalk, iota_tag)) != NULL) {
		free(p);
		return errstr;
	}

	nwqid = np_read16(buf);
	assert(nwqid <= nwname);

	/* consume all qids */
	for (i = 0; i < nwqid; ++i)
		np_read_qid(buf, qid);

	free(p);

	*missing = nwname - nwqid;
	return NULL;
}

static void
do_stat(int fid, struct np_stat *st)
{
	tstat(fid);
	do_send();
	recv_msg();
	expect2(Rstat, iota_tag);

	/* eat up the first two byte length */
	np_read16(buf);

	if (np_read_stat(buf, st) == -1)
		errx(1, "invalid stat struct read");

	ASSERT_EMPTYBUF();
}

static char *
do_wstat(int fid, const struct np_stat *st)
{
	char *errstr;

	twstat(fid, st);
	do_send();
	recv_msg();

	if ((errstr = check(Rwstat, iota_tag)) != NULL)
		return errstr;

	ASSERT_EMPTYBUF();

	return NULL;
}

static size_t
do_read(int fid, uint64_t off, uint32_t count, void *data)
{
	uint32_t r;

	tread(fid, off, count);
	do_send();
	recv_msg();
	expect2(Rread, iota_tag);

	r = np_read32(buf);
	assert(r == EVBUFFER_LENGTH(buf));
	assert(r <= count);
	evbuffer_remove(buf, data, r);

	ASSERT_EMPTYBUF();

	return r;
}

static size_t
do_write(int fid, uint64_t off, uint32_t count, void *data)
{
	uint32_t r;

	twrite(fid, off, data, count);
	do_send();
	recv_msg();
	expect2(Rwrite, iota_tag);

	r = np_read32(buf);
	assert(r <= count);

	ASSERT_EMPTYBUF();

	return r;
}

static void
draw_progress(const char *pre, const struct progress *p)
{
	struct winsize ws;
	int i, l, w;
	double perc;

	if (xdump)
		return;

	perc = 100.0 * p->done / p->max;
	if (!tty_p) {
		fprintf(stderr, "%s: %d%%\n", pre, (int)perc);
		return;
	}

	if (resized) {
		resized = 0;

		if (ioctl(0, TIOCGWINSZ, &ws) == -1)
			return;
		tty_width = ws.ws_col;
	}
	w = tty_width;

	if (pre == NULL ||
	    ((l = printf("\r%s ", pre)) == -1 || l >= w))
		return;

	w -= l + 2 + 5; /* 2 for |, 5 for percentage + \n */
	if (w < 0) {
		printf("%4d%%\n", (int)perc);
		return;
	}

	printf("|");

	l = w * MIN(100.0, perc) / 100.0;
	for (i = 0; i < l; i++)
		printf("*");
	for (; i < w; i++)
		printf(" ");
	printf("|%4d%%", (int)perc);

	fflush(stdout);
}

static int
fetch_fid(int fid, int fd, const char *name)
{
	static char buf[MSIZE9P];
	struct progress p = {0};
	struct np_stat st;
	size_t r;
	int ret = 0;

	do_stat(fid, &st);
	do_open(fid, KOREAD);

	p.max = st.length;
	for (;;) {
		size_t len, off;
		ssize_t nw;

		len = MIN(sizeof(buf), msize);
		len -= IOHDRSZ; /* for the request' fields */

		r = do_read(fid, p.done, len, buf);
		if (r == 0)
			break;

		for (off = 0; off < r; off += nw)
			if ((nw = write(fd, buf + off, r - off)) == 0 ||
			    nw == -1) {
				ret = -1;
				goto end;
			}

		p.done += r;
		draw_progress(name, &p);

#if 0
		/* throttle, for debugging purpose */
		{
			struct timespec ts = { 0, 500000000 };
			nanosleep(&ts, NULL);
		}
#endif
	}

end:
	putchar('\n');

	do_clunk(fid);
	return ret;
}

static void
send_fid(int fid, const char *fnam, int open_flags, int fd, const char *name)
{
	static char buf[MSIZE9P];
	struct progress p = {0};
	struct stat sb;
	ssize_t r;
	size_t w, len;

	if (fstat(fd, &sb) == -1)
		err(1, "fstat");

	if (fnam != NULL)
		do_create(fid, fnam, 0644, KOWRITE);
	else
		do_open(fid, open_flags | KOWRITE);

	p.max = sb.st_size;
	for (;;) {
		len = MIN(sizeof(buf), msize);
		len -= HEADERSIZE + 4 + 4 + 8; /* for the request' fields */

		r = read(fd, buf, len);
		if (r == 0)
			break;
		if (r == -1)
			err(1, "read");

		w = do_write(fid, p.done, r, buf);
		p.done += w;

		draw_progress(name, &p);

#if 0
		/* throttle, for debugging purpose */
		{
			struct timespec ts = { 0, 500000000 };
			nanosleep(&ts, NULL);
		}
#endif
	}

	putchar('\n');
	do_clunk(fid);
}

static int
woc_file(int fd, const char *prompt, const char *path)
{
	struct qid qid;
	const char *n = NULL;
	char *errstr;
	int nfid, miss;

	nfid = nextfid();
	errstr = walk_path(pwdfid, nfid, path, &miss, &qid);
	if (errstr != NULL && miss > 1) {
		printf("%s: %s\n", path, errstr);
		free(errstr);
		return -1;
	}

	if (errstr != NULL || miss == 1) {
		char p[PATH_MAX], *dn;

		/*
		 * If it's only one component missing (the file name), walk
		 * to the parent directory and try to create the file.
		 */

		if (strlcpy(p, path, sizeof(p)) >= sizeof(p)) {
			printf("path too long: %s\n", path);
			return -1;
		}
		dn = dirname(p);

		if (!strcmp(dn, ".")) {
			errstr = dup_fid(pwdfid, nfid);
			miss = 0;
		} else
			errstr = walk_path(pwdfid, nfid, dn, &miss, &qid);

		if (errstr != NULL) {
			printf("%s: %s\n", dn, errstr);
			free(errstr);
			return -1;
		}

		if (miss != 0) {
			printf("%s: not a directory\n", dn);
			return -1;
		}

		if ((n = strrchr(path, '/')) != NULL)
			n++;
		else
			n = path;
	}

	free(errstr);

	if (miss > 1) {
		printf("can't create %s: missing %d path component(s)\n",
		    path, miss);
		return -1;
	}

	send_fid(nfid, n, KOTRUNC, fd, prompt);
	return 0;
}

static int
dial(const char *host, const char *port)
{
	struct addrinfo hints, *res, *res0;
	int sock, error, saved_errno;
	const char *cause = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	error = getaddrinfo(host, port, &hints, &res0);
	if (error)
		errx(1, "%s", gai_strerror(error));

	sock = -1;
	for (res = res0; res != NULL; res = res->ai_next) {
		sock = socket(res->ai_family, res->ai_socktype|SOCK_CLOEXEC,
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
	freeaddrinfo(res0);
	if (sock == -1)
		err(1, "%s", cause);
	return sock;
}

static void
do_connect(const char *host, const char *port, const char *user)
{
	struct qid qid;
	int nfid, miss, fd;
	char *errstr;

	printf("connecting to %s:%s...", host, port);
	fflush(stdout);

	if (tls) {
		struct tls_config	*conf;
		struct tls		*ctx;
		int			 r;

		if ((conf = tls_config_new()) == NULL)
			fatalx("failed to create TLS config");
		tls_config_insecure_noverifycert(conf);
		tls_config_insecure_noverifyname(conf);

		if (keypath == NULL)
			keypath = crtpath;

		if (tls_config_set_keypair_file(conf, crtpath, keypath) == -1)
			fatalx("failed to load certs: (%s, %s)", crtpath,
			    keypath);

		if ((ctx = tls_client()) == NULL)
			fatalx("failed to create TLS client");
		if (tls_configure(ctx, conf) == -1)
			fatalx("failed to configure TLS client");
		tls_config_free(conf);

		if (tls_connect(ctx, host, port) == -1)
			fatalx("failed to connect to %s:%s: %s", host, port,
			    tls_error(ctx));

		do {
			r = tls_handshake(ctx);
		} while (r == TLS_WANT_POLLIN || r == TLS_WANT_POLLOUT);
		fp = funopen(ctx, stdio_tls_read, stdio_tls_write, NULL,
		    stdio_tls_close);
		if (fp == NULL)
			fatal("funopen");
	} else {
		int fd;

		fd = dial(host, port);
		if ((fp = fdopen(fd, "r+")) == NULL)
			fatal("fdopen");
	}

	printf(" done!\n");

	do_version();
	do_attach(user);
}

static int
tmp_file(char sfn[TMPFSTRLEN])
{
	int tmpfd;

	strlcpy(sfn, TMPFSTR, TMPFSTRLEN);
	if ((tmpfd = mkstemp(sfn)) == -1) {
		warn("mkstemp %s", sfn);
		return -1;
	}

	/* set the close-on-exec flag */
	if (fcntl(tmpfd, F_SETFD, FD_CLOEXEC) == -1) {
		warn("fcntl");
		close(tmpfd);
		return -1;
	}

	return tmpfd;
}

static inline const char *
pp_perm(uint8_t x)
{
	switch (x & 0x7) {
	case 0x0:
		return "---";
	case 0x1:
		return "--x";
	case 0x2:
		return "-w-";
	case 0x3:
		return "-wx";
	case 0x4:
		return "r--";
	case 0x5:
		return "r-x";
	case 0x6:
		return "rw-";
	case 0x7:
		return "rwx";
	default:
		/* unreachable, just for the compiler' happiness */
		return "???";
	}
}

static inline void
prepare_wstat(struct np_stat *st)
{
	memset(st, 0xFF, sizeof(*st));
	st->name = NULL;
	st->uid = NULL;
	st->gid = NULL;
	st->muid = NULL;
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
	fclose(fp);
	exit(0);
}

static void
cmd_cd(int argc, const char **argv)
{
	struct qid qid;
	int nfid, miss;
	char *errstr;

	if (argc != 1) {
		printf("usage: cd remote-path\n");
		return;
	}

	nfid = nextfid();
	errstr = walk_path(pwdfid, nfid, argv[0], &miss, &qid);
	if (errstr != NULL) {
		printf("%s: %s\n", argv[0], errstr);
		free(errstr);
		return;
	}

	if (miss != 0 || !(qid.type & QTDIR)) {
		printf("%s: not a directory\n", argv[0]);
		if (miss == 0)
			do_clunk(nfid);
		return;
	}

	do_clunk(pwdfid);
	pwdfid = nfid;
}

static void
cmd_edit(int argc, const char **argv)
{
	struct qid qid;
	int nfid, tmpfd, miss;
	char sfn[TMPFSTRLEN], p[PATH_MAX], *name, *errstr;
	const char *ed;

	if (argc != 1) {
		puts("usage: edit file");
		return;
	}

	if ((ed = getenv("VISUAL")) == NULL &&
	    (ed = getenv("EDITOR")) == NULL)
		ed = "ed";

	nfid = nextfid();
	errstr = walk_path(pwdfid, nfid, *argv, &miss, &qid);
	if (errstr != NULL) {
		printf("%s: %s\n", *argv, errstr);
		free(errstr);
		return;
	}

	if (miss != 0 || qid.type != 0) {
		printf("%s: not a file\n", *argv);
		if (miss == 0)
			do_clunk(nfid);
		return;
	}

	if ((tmpfd = tmp_file(sfn)) == -1) {
		do_clunk(nfid);
		return;
	}

	strlcpy(p, *argv, sizeof(p));
	name = basename(p);

	if (fetch_fid(nfid, tmpfd, name)) {
		warn("failed fetch or can't write %s", sfn);
		goto end;
	}
	close(tmpfd);

	spawn(ed, sfn, NULL);

	/*
	 * Re-open the file because it's not guaranteed that the
	 * file descriptor tmpfd is still associated with the file
	 * pointed by sfn: it's not uncommon for editor to write
	 * a backup file and then rename(2) it to the file name.
	 */
	if ((tmpfd = open(sfn, O_RDONLY)) == -1) {
		warn("can't open %s", sfn);
		goto end;
	}

	woc_file(tmpfd, *argv, name);
	close(tmpfd);

end:
	unlink(sfn);
}

static void
cmd_get(int argc, const char **argv)
{
	struct qid qid;
	const char *l;
	char *errstr;
	int nfid, fd, miss;

	if (argc != 1 && argc != 2) {
		printf("usage: get remote-file [local-file]\n");
		return;
	}

	if (argc == 2)
		l = argv[1];
	else if ((l = strrchr(argv[0], '/')) != NULL)
		l++; /* skip / */
	else
		l = argv[0];

	nfid = nextfid();
	errstr = walk_path(pwdfid, nfid, argv[0], &miss, &qid);
	if (errstr != NULL) {
		printf("%s: %s\n", argv[0], errstr);
		free(errstr);
		return;
	}

	if (miss != 0 || qid.type != 0) {
		printf("%s: not a file\n", argv[0]);
		if (miss == 0)
			do_clunk(nfid);
		return;
	}

	if ((fd = open(l, O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0644)) == -1) {
		warn("can't open %s", l);
		do_clunk(nfid);
		return;
	}

	if (fetch_fid(nfid, fd, l) == -1)
		warn("write %s", l);
	close(fd);
}

static void
cmd_hexdump(int argc, const char **argv)
{
	if (argc == 0) {
		xdump = !xdump;
		if (xdump)
			puts("hexdump mode enabled");
		else
			puts("hexdump mode disabled");
		return;
	}

	if (argc > 1)
		goto usage;

	if (!strcmp(*argv, "on")) {
		xdump = 1;
		puts("hexdump mode enabled");
		return;
	}

	if (!strcmp(*argv, "off")) {
		xdump = 0;
		puts("hexdump mode disabled");
		return;
	}

usage:
	puts("usage: hexdump [on | off]");
}

static void
cmd_lcd(int argc, const char **argv)
{
	const char *dir;

	if (argc > 1) {
		printf("usage: lcd [local-directory]\n");
		return;
	}

	if (argc == 1)
		dir = *argv;

	if (argc == 0 && (dir = getenv("HOME")) == NULL) {
		printf("HOME is not defined\n");
		return;
	}

	if (chdir(dir) == -1)
		printf("cd: %s: %s\n", dir, strerror(errno));
}

static void
cmd_lpwd(int argc, const char **argv)
{
	char path[PATH_MAX];

	if (argc != 0) {
		printf("usage: lpwd\n");
		return;
	}

	if (getcwd(path, sizeof(path)) == NULL) {
		printf("lpwd: %s\n", strerror(errno));
		return;
	}

	printf("%s\n", path);
}

static void
cmd_ls(int argc, const char **argv)
{
	struct np_stat st;
	time_t now, mtime;
	struct tm *tm;
	uint64_t off = 0;
	uint32_t len;
	int nfid;
	const char *timfmt;
	char fmt[FMT_SCALED_STRSIZE], tim[13], *errstr;

	if (argc != 0) {
		printf("ls don't take arguments (yet)\n");
		return;
	}

	now = time(NULL);

	nfid = nextfid();
	if ((errstr = dup_fid(pwdfid, nfid)) != NULL) {
		printf(".: %s\n", errstr);
		free(errstr);
		return;
	}

	do_open(nfid, KOREAD);

	evbuffer_drain(dirbuf, EVBUFFER_LENGTH(dirbuf));

	for (;;) {
		tread(nfid, off, msize - IOHDRSZ);
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
		if (np_read_stat(dirbuf, &st) == -1)
			errx(1, "invalid stat struct read");

		if (fmt_scaled(st.length, fmt) == -1)
			strlcpy(fmt, "xxx", sizeof(fmt));

		mtime = st.mtime;

		if (now > mtime && (now - mtime) < 365/2 * 24 * 12 * 60)
			timfmt = "%b %e %R";
		else
			timfmt = "%b %e  %Y";

		if ((tm = localtime(&mtime)) == NULL ||
		    strftime(tim, sizeof(tim), timfmt, tm) == 0)
			strlcpy(tim, "unknown", sizeof(tim));

		if (st.qid.type & QTDIR)
			printf("d");
		else
			printf("-");
		printf("%s", pp_perm(st.mode >> 6));
		printf("%s", pp_perm(st.mode >> 3));
		printf("%s", pp_perm(st.mode));
		printf(" %8s %12s %s%s\n", fmt, tim, st.name,
		    st.qid.type & QTDIR ? "/" : "");

		free(st.name);
		free(st.uid);
		free(st.gid);
		free(st.muid);
	}

	do_clunk(nfid);
}

static void
cmd_page(int argc, const char **argv)
{
	struct qid qid;
	int nfid, tmpfd, miss, r;
	char sfn[TMPFSTRLEN], p[PATH_MAX], *name, *errstr;
	const char *pager;

	if (argc != 1) {
		puts("usage: page file");
		return;
	}

	if ((pager = getenv("PAGER")) == NULL)
		pager = "less";

	nfid = nextfid();
	errstr = walk_path(pwdfid, nfid, *argv, &miss, &qid);
	if (errstr != NULL) {
		printf("%s: %s\n", *argv, errstr);
		free(errstr);
		return;
	}

	if (miss != 0 || qid.type != 0) {
		printf("%s: not a file\n", *argv);
		if (miss == 0)
			do_clunk(nfid);
		return;
	}

	if ((tmpfd = tmp_file(sfn)) == -1) {
		do_clunk(nfid);
		return;
	}

	strlcpy(p, *argv, sizeof(p));
	name = basename(p);
	if ((r = fetch_fid(nfid, tmpfd, name)) == -1)
		warn("write %s", sfn);
	close(tmpfd);
	if (r != -1)
		spawn(pager, sfn, NULL);
	unlink(sfn);
}

static void
cmd_pipe(int argc, const char **argv)
{
	struct qid qid;
	pid_t pid;
	int nfid, tmpfd, miss, status;
	int filedes[2]; /* read end, write end */
	char *errstr;

	if (argc < 2) {
		puts("usage: pipe remote-file cmd [args...]");
		return;
	}

	nfid = nextfid();
	errstr = walk_path(pwdfid, nfid, *argv, &miss, &qid);
	if (errstr != NULL) {
		printf("%s: %s\n", *argv, errstr);
		free(errstr);
		return;
	}

	if (miss != 0 || qid.type != 0) {
		printf("%s: not a file\n", *argv);
		if (miss == 0)
			do_clunk(nfid);
		return;
	}

	if (pipe(filedes) == -1)
		err(1, "pipe");

	switch (pid = vfork()) {
	case -1:
		err(1, "vfork");
	case 0:
		close(filedes[1]);
		if (dup2(filedes[0], 0) == -1)
			err(1, "dup2");
		execvp(argv[1], (char *const *)argv + 1);
		err(1, "execvp");
	}

	close(filedes[0]);
	if (fetch_fid(nfid, filedes[1], *argv) == -1)
		warnx("failed to fetch all the file");
	close(filedes[1]);

	waitpid(pid, &status, 0);
}

static void
cmd_put(int argc, const char **argv)
{
	struct qid qid;
	const char *l;
	int fd;

	if (argc != 1 && argc != 2) {
		printf("usage: put local-file [remote-file]\n");
		return;
	}

	if (argc == 2)
		l = argv[1];
	else if ((l = strrchr(argv[0], '/')) != NULL)
		l++; /* skip / */
	else
		l = argv[0];

	if ((fd = open(argv[0], O_RDONLY)) == -1) {
		warn("%s", argv[0]);
		return;
	}

	woc_file(fd, argv[0], l);
	close(fd);
}

static void
cmd_rename(int argc, const char **argv)
{
	struct np_stat st;
	struct qid qid;
	char *errstr;
	int nfid, miss;

	if (argc != 2) {
		puts("usage: rename remote-file new-remote-name");
		return;
	}

	nfid = nextfid();
	errstr = walk_path(pwdfid, nfid, argv[0], &miss, &qid);
	if (errstr != NULL) {
		printf("%s: %s\n", argv[0], errstr);
		free(errstr);
		return;
	}

	if (miss != 0) {
		printf("%s: not such file or directory\n", argv[0]);
		return;
	}

	prepare_wstat(&st);
	st.name = (char *)argv[1];
	if ((errstr = do_wstat(nfid, &st)) != NULL) {
		printf("rename: %s\n", errstr);
		free(errstr);
	}

	do_clunk(nfid);
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
		{"cd",		cmd_cd},
		{"edit",	cmd_edit},
		{"get",		cmd_get},
		{"hexdump",	cmd_hexdump},
		{"lcd",		cmd_lcd},
		{"lpwd",	cmd_lpwd},
		{"ls",		cmd_ls},
		{"page",	cmd_page},
		{"pipe",	cmd_pipe},
		{"put",		cmd_put},
		{"quit",	cmd_bye},
		{"rename",	cmd_rename},
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

static void
cd_or_fetch(const char *path)
{
	struct qid	 qid;
	const char	*l;
	char		*errstr;
	int		 fd, nfid, miss;

	while (*path == '/')
		path++;
	if (*path == '\0')
		return;

	nfid = nextfid();
	errstr = walk_path(pwdfid, nfid, path, &miss, &qid);
	if (errstr)
		errx(1, "walk %s: %s", path, errstr);
	if (miss)
		errc(1, ENOENT, "walk %s", path);

	if (qid.type & QTDIR) {
		do_clunk(pwdfid);
		pwdfid = nfid;
		return;
	}

	if ((l = strrchr(path, '/')) == NULL)
		l = path;
	else
		l++;
	if (*l == '\0')
		errx(1, "invalid path: missing file name: %s", path);

	if ((fd = open(l, O_WRONLY|O_CREAT, 0644)) == -1)
		err(1, "can't open for writing %s", l);
	if (fetch_fid(nfid, fd, l) == -1)
		err(1, "write %s", l);
	close(fd);
	fclose(fp);
	exit(0);
}

static const char *
parse_addr(const char *url, const char **user,
    const char **port, const char **path)
{
	static char	 buf[PATH_MAX];
	char		*host, *t;

	*user = *port = *path = NULL;
	host = buf;

	if (strlcpy(buf, url, sizeof(buf)) >= sizeof(buf))
		errx(1, "connection string too long");

	if ((t = strchr(host, '/')) != NULL) {
		if (t == host)
			errx(1, "invalid connection string: %s", url);
		*t++ = '\0';
		if (*t != '\0')
			*path = t;
	}

	if ((t = strchr(host, '@')) != NULL) {
		if (t == host)
			errx(1, "invalid connection string: %s", url);
		*t++ = '\0';
		*user = host;
		host = t;
	} else if ((*user = getenv("USER")) == NULL)
		errx(1, "USER not defined");

	if ((t = strchr(host, ':')) != NULL) {
		*t++ = '\0';
		if (*t != '\0')
			*port = t;
	}
	if (*port == NULL)
		*port = "1337";

	return host;
}

int
main(int argc, char **argv)
{
	const char	*user, *host, *port, *path;
	int		 ch;

	log_init(1, LOG_DAEMON);
	log_setverbose(0);
	log_procinit(getprogname());

	while ((ch = getopt(argc, argv, "C:cK:")) != -1) {
		switch (ch) {
		case 'C':
			tls = 1;
			crtpath = optarg;
			break;
		case 'c':
			tls = 1;
			break;
		case 'K':
			tls = 1;
			keypath = optarg;
			break;
		default:
			usage(1);
		}
	}
	argc -= optind;
	argv += optind;

	if (argc == 0 || (tls && crtpath == NULL))
		usage(1);

	host = parse_addr(argv[0], &user, &port, &path);
	if (path == NULL && argv[1] != NULL)
		path = argv[1];

	signal(SIGPIPE, SIG_IGN);
	if (isatty(1)) {
		tty_p = 1;
		resized = 1;
		signal(SIGWINCH, tty_resized);
	}

	if ((evb = evbuffer_new()) == NULL)
		fatal("evbuffer_new");

	if ((buf = evbuffer_new()) == NULL)
		fatal("evbuffer_new");

	if ((dirbuf = evbuffer_new()) == NULL)
		fatal("evbuferr_new");

	do_connect(host, port, user);
	if (path)
		cd_or_fetch(path);

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
	fclose(fp);
}
