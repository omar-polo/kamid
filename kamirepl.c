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

#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <tls.h>
#include <unistd.h>

#include "kamid.h"
#include "log.h"
#include "utils.h"

#define PROMPT "=% "

/* flags */
int			 verbose;
int			 tls;
const char		*keypath;
const char		*crtpath;
const char		*host;
const char		*port;

/* state */
struct tls_config	*tlsconf;
struct tls		*ctx;
struct bufferevent	*bev, *inbev;

static void ATTR_DEAD	 usage(int);

static void		 sig_handler(int, short, void *);

static int		 openconn(void);
static void		 mark_nonblock(int);

static void		 tls_readcb(int, short, void *);
static void		 tls_writecb(int, short, void *);

static void		 client_read(struct bufferevent *, void *);
static void		 client_write(struct bufferevent *, void *);
static void		 client_error(struct bufferevent *, short, void *);

static void		 repl_read(struct bufferevent *, void *);
static void		 repl_error(struct bufferevent *, short, void *);
static void		 write_hdr(uint32_t, uint8_t, uint16_t);
static void		 write_str(uint16_t, const char *);
static void		 write_fid(uint32_t);

static void		 excmd_version(const char **, int);
static void		 excmd_attach(const char **, int);
static void		 excmd(const char **, int);

static const char	*pp_qid_type(uint8_t);
static void		 pp_qid(const uint8_t *, uint32_t);
static void		 pp_msg(uint32_t, uint8_t, uint16_t, const uint8_t *);
static void		 handle_9p(const uint8_t *, size_t);
static void		 clr(void);
static void		 prompt(void);

static void ATTR_DEAD
usage(int ret)
{
	fprintf(stderr,
	    "usage: %s [-chv] [-C crt] [-K key] [-H host] [-P port]\n",
	    getprogname());
	fprintf(stderr, PACKAGE_NAME " suite version " PACKAGE_VERSION "\n");
	exit(ret);
}

static void
sig_handler(int sig, short event, void *d)
{
	/*
	 * Normal signal handler rules don't apply because libevent
	 * decouples for us.
	 */

	switch (sig) {
	case SIGINT:
	case SIGTERM:
		clr();
		log_warnx("Shutting down...");
		event_loopbreak();
		return;
	default:
		fatalx("unexpected signal %d", sig);
	}
}

static int
openconn(void)
{
	struct addrinfo hints, *res, *res0;
	int error;
	int save_errno;
	int s;
	const char *cause = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if ((error = getaddrinfo(host, port, &hints, &res0))) {
		warnx("%s", gai_strerror(error));
		return -1;
	}

	s = -1;
	for (res = res0; res; res = res->ai_next) {
		s = socket(res->ai_family, res->ai_socktype,
		    res->ai_protocol);
		if (s == -1) {
			cause = "socket";
			continue;
		}

		if (connect(s, res->ai_addr, res->ai_addrlen) == -1) {
			cause = "connect";
			save_errno = errno;
			close(s);
			errno = save_errno;
			s = -1;
			continue;
		}

		break;
	}

	freeaddrinfo(res0);

	if (s == -1)
		warn("%s", cause);

	return s;
}

static void
mark_nonblock(int fd)
{
	int flags;

	if ((flags = fcntl(fd, F_GETFL)) == -1)
		fatal("fcntl(F_GETFL)");
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
		fatal("fcntl(F_SETFL)");
}

static void
tls_readcb(int fd, short event, void *d)
{
	struct bufferevent	*bufev = d;
	char			 buf[IBUF_READ_SIZE];
	int			 what = EVBUFFER_READ;
	int			 howmuch = IBUF_READ_SIZE;
	ssize_t			 ret;
	size_t			 len;

	if (event == EV_TIMEOUT) {
		what |= EVBUFFER_TIMEOUT;
		goto err;
	}

	if (bufev->wm_read.high != 0)
		howmuch = MIN(sizeof(buf), bufev->wm_read.high);

	switch (ret = tls_read(ctx, buf, howmuch)) {
	case TLS_WANT_POLLIN:
	case TLS_WANT_POLLOUT:
		goto retry;
	case -1:
		what |= EVBUFFER_ERROR;
		goto err;
	}
	len = ret;

	if (len == 0) {
		what |= EVBUFFER_EOF;
		goto err;
	}

	if (evbuffer_add(bufev->input, buf, len) == -1) {
		what |= EVBUFFER_ERROR;
		goto err;
	}

	event_add(&bufev->ev_read, NULL);

	len = EVBUFFER_LENGTH(bufev->input);
	if (bufev->wm_read.low != 0 && len < bufev->wm_read.low)
		return;
	if (bufev->readcb != NULL)
		(*bufev->readcb)(bufev, bufev->cbarg);
	return;

retry:
	event_add(&bufev->ev_read, NULL);
	return;

err:
	(*bufev->errorcb)(bufev, what, bufev->cbarg);
}

static void
tls_writecb(int fd, short event, void *d)
{
	struct bufferevent	*bufev = d;
	ssize_t			 ret;
	short			 what = EVBUFFER_WRITE;

	if (event == EV_TIMEOUT) {
		what |= EVBUFFER_TIMEOUT;
		goto err;
	}

	if (EVBUFFER_LENGTH(bufev->output) != 0) {
		ret = tls_write(ctx,
		    EVBUFFER_DATA(bufev->output),
		    EVBUFFER_LENGTH(bufev->output));
		switch (ret) {
		case TLS_WANT_POLLIN:
		case TLS_WANT_POLLOUT:
			goto retry;
		case -1:
			what |= EVBUFFER_ERROR;
			goto err;
		}
		evbuffer_drain(bufev->output, ret);
	}

	if (EVBUFFER_LENGTH(bufev->output) != 0)
		event_add(&bufev->ev_write, NULL);

	if (bufev->writecb != NULL &&
	    EVBUFFER_LENGTH(bufev->output) <= bufev->wm_write.low)
		(*bufev->writecb)(bufev, bufev->cbarg);
	return;

retry:
	event_add(&bufev->ev_write, NULL);
	return;
err:
	(*bufev->errorcb)(bufev, what, bufev->cbarg);
}

static void
client_read(struct bufferevent *bev, void *data)
{
	struct evbuffer	*src = EVBUFFER_INPUT(bev);
	uint32_t	 len;

	for (;;) {
		if (EVBUFFER_LENGTH(src) < sizeof(len))
			return;

		memcpy(&len, EVBUFFER_DATA(src), sizeof(len));
		len = le32toh(len);

		if (len > EVBUFFER_LENGTH(src))
			return;

		handle_9p(EVBUFFER_DATA(src), len);
		evbuffer_drain(src, len);
	}
}

static void
client_write(struct bufferevent *bev, void *data)
{
	return; /* nothing to do */
}

static void
client_error(struct bufferevent *bev, short err, void *data)
{
	if (err & EVBUFFER_ERROR)
		fatal("buffer event error");

	if (err & EVBUFFER_EOF) {
		clr();
		log_info("EOF");
		event_loopbreak();
		return;
	}

	clr();
	log_warnx("unknown event error");
	event_loopbreak();
}

static void
repl_read(struct bufferevent *bev, void *d)
{
	size_t		 len;
	int		 argc;
	const char	*argv[10], **ap;
	char		*line;

	line = evbuffer_readln(bev->input, &len, EVBUFFER_EOL_LF);
	if (line == NULL)
		return;

	for (argc = 0, ap = argv; ap < &argv[9] &&
	    (*ap = strsep(&line, " \t")) != NULL;) {
		if (**ap != '\0')
			ap++, argc++;
	}

	clr();
	excmd(argv, argc);
	prompt();

	free(line);
}

static void
repl_error(struct bufferevent *bev, short error, void *d)
{
	fatalx("an error occurred");
}

static void
write_hdr(uint32_t len, uint8_t type, uint16_t tag)
{
	len += HEADERSIZE;

	log_debug("enqueuing a packet; len=%"PRIu32" type=%d[%s] tag=%d",
	    len, type, pp_msg_type(type), tag);

	len = htole32(len);
	/* type is one byte, no endiannes issues */
	tag = htole16(tag);

	bufferevent_write(bev, &len, sizeof(len));
	bufferevent_write(bev, &type, sizeof(type));
	bufferevent_write(bev, &tag, sizeof(tag));
}

static void
write_str(uint16_t len, const char *str)
{
	uint16_t l = len;

	len = htole16(len);
	bufferevent_write(bev, &len, sizeof(len));
	bufferevent_write(bev, str, l);
}

static void
write_fid(uint32_t fid)
{
	fid = htole32(fid);
	bufferevent_write(bev, &fid, sizeof(fid));
}

/* version [version-str] */
static void
excmd_version(const char **argv, int argc)
{
	uint32_t	 len, msize;
	uint16_t	 sl;
	const char	*s;

	s = VERSION9P;
	if (argc == 2)
		s = argv[1];

	sl = strlen(s);

	/* msize[4] version[s] */
	len = 4 + sizeof(sl) + sl;
	write_hdr(len, Tversion, NOTAG);

	msize = htole32(MSIZE9P);
	bufferevent_write(bev, &msize, sizeof(msize));

	write_str(sl, s);
}

/* attach fid uname aname */
static void
excmd_attach(const char **argv, int argc)
{
	uint32_t	 len, fid;
	uint16_t	 sl, tl;
	const char	*s, *t, *errstr;

	if (argc != 4)
		goto usage;

        fid = strtonum(argv[1], 0, UINT32_MAX, &errstr);
	if (errstr != NULL) {
		log_warnx("fid is %s: %s", errstr, argv[1]);
		return;
	}

	s = argv[2];
	sl = strlen(s);
	t = argv[3];
	tl = strlen(t);

	/* fid[4] afid[4] uname[s] aname[s] */
	len = 4 + 4 + sizeof(sl) + sl + sizeof(tl) + tl;
	write_hdr(len, Tattach, 0);
	write_fid(fid);
	write_fid(NOFID);
	write_str(sl, s);
	write_str(tl, t);

	return;

usage:
	log_warnx("usage: attach fid uname aname");
}

static void
excmd(const char **argv, int argc)
{
	struct cmd {
		const char	*name;
		void		(*fn)(const char **, int);
	} cmds[] = {
		{"version", excmd_version},
		{"attach", excmd_attach},
	};
	size_t i;

	for (i = 0; i < sizeof(cmds)/sizeof(cmds[0]); ++i) {
		if (!strcmp(cmds[i].name, argv[0])) {
			cmds[i].fn(argv, argc);
			return;
		}
	}

	log_warnx("Unknown command %s", *argv);
}

static const char *
pp_qid_type(uint8_t type)
{
        switch (type) {
	case QTDIR: return "dir";
	case QTAPPEND: return "append-only";
	case QTEXCL: return "exclusive";
	case QTMOUNT: return "mounted-channel";
	case QTAUTH: return "authentication";
	case QTTMP: return "non-backed-up";
	case QTSYMLINK: return "symlink";
	case QTFILE: return "file";
	}

	return "unknown";
}

static void
pp_qid(const uint8_t *d, uint32_t len)
{
	uint64_t	path;
	uint32_t	vers;
	uint8_t		type;

	if (len < 13) {
		printf("invalid");
		return;
	}

	memcpy(&path, d, sizeof(path));
	d += sizeof(path);
	path = le64toh(path);

	memcpy(&vers, d, sizeof(vers));
	d += sizeof(vers);
	path = le64toh(vers);

	type = *d;

	printf("qid{path=%"PRIu64" version=%"PRIu32" type=0x%x\"%s\"",
	    path, vers, type, pp_qid_type(type));
}

static void
pp_msg(uint32_t len, uint8_t type, uint16_t tag, const uint8_t *d)
{
	uint32_t	msize;
	uint16_t	slen;

	printf("len=%"PRIu32" type=%d[%s] tag=0x%x[%d] ", len,
	    type, pp_msg_type(type), tag, tag);

	len -= HEADERSIZE;

	switch (type) {
	case Rversion:
		if (len < 6) {
			printf("invalid: not enough space for msize "
			    "and version provided.");
			break;
		}

		memcpy(&msize, d, sizeof(msize));
		d += sizeof(msize);
		len -= sizeof(msize);
		msize = le32toh(msize);

		memcpy(&slen, d, sizeof(slen));
		d += sizeof(slen);
		len -= sizeof(slen);
		slen = le32toh(slen);

		if (len != slen) {
			printf("invalid: version string length doesn't "
			    "match.  Got %d; want %d", slen, len);
			break;
		}

		printf("msize=%"PRIu32" version[%"PRIu16"]=\"",
		    msize, slen);
		fwrite(d, 1, slen, stdout);
		printf("\"");

		break;

	case Rattach:
		pp_qid(d, len);
		break;

	default:
		printf("unknown command type");
	}

	printf("\n");
}

static void
handle_9p(const uint8_t *data, size_t size)
{
        uint32_t len;
	uint16_t tag;
	uint8_t type;

	assert(size >= HEADERSIZE);

	memcpy(&len, data, sizeof(len));
	data += sizeof(len);

	memcpy(&type, data, sizeof(type));
	data += sizeof(type);

	memcpy(&tag, data, sizeof(tag));
	data += sizeof(tag);

	len = le32toh(len);
	/* type is one byte long, no endianness issues */
	tag = le16toh(tag);

	clr();
	pp_msg(len, type, tag, data);
	prompt();
}

static void
clr(void)
{
	printf("\r");
	fflush(stdout);
}

static void
prompt(void)
{
	printf("%s", PROMPT);
	fflush(stdout);
}

int
main(int argc, char **argv)
{
	int		 ch, sock, handshake;
	struct event	 ev_sigint, ev_sigterm;

	signal(SIGPIPE, SIG_IGN);

	while ((ch = getopt(argc, argv, "C:cH:hK:P:v")) != -1) {
		switch (ch) {
		case 'C':
			crtpath = optarg;
			break;
		case 'c':
			tls = 1;
			break;
		case 'H':
			host = optarg;
			break;
		case 'h':
			usage(0);
			break;
		case 'K':
			keypath = optarg;
			break;
		case 'P':
			port = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			usage(1);
		}
	}

	if (host == NULL)
		host = "localhost";
	if (port == NULL)
		port = "1337";

	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage(1);
	/* if (!tls || (crtpath != NULL || keypath != NULL)) */
		/* usage(1); */
	if (!tls)
                errx(1, "must enable tls (for now)");

	log_init(1, LOG_DAEMON);
	log_setverbose(verbose);
	log_procinit(getprogname());

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

	log_info("connecting to %s:%s...", host, port);

	if ((sock = openconn()) == -1)
		fatalx("can't connect to %s:%s", host, port);

	if (tls_connect_socket(ctx, sock, host) == -1)
		fatalx("tls_connect_socket: %s", tls_error(ctx));

	for (handshake = 0; !handshake;) {
		switch (tls_handshake(ctx)) {
		case -1:
			fatalx("tls_handshake: %s", tls_error(ctx));
		case 0:
			handshake = 1;
			break;
		}
	}

	log_info("connected!");

	mark_nonblock(sock);

	event_init();

	signal_set(&ev_sigint, SIGINT, sig_handler, NULL);
	signal_set(&ev_sigterm, SIGINT, sig_handler, NULL);

	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);

	bev = bufferevent_new(sock, client_read, client_write, client_error,
	    NULL);
	if (bev == NULL)
		fatal("bufferevent_new");

	/* setup tls/io */
	event_set(&bev->ev_read, sock, EV_READ, tls_readcb, bev);
	event_set(&bev->ev_write, sock, EV_WRITE, tls_writecb, bev);

	bufferevent_setwatermark(bev, EV_READ|EV_WRITE,
	    sizeof(struct np_msg_header), 0);
	bufferevent_enable(bev, EV_READ|EV_WRITE);

	mark_nonblock(0);
	inbev = bufferevent_new(0, repl_read, NULL, repl_error, NULL);
	bufferevent_enable(inbev, EV_READ);

	prompt();
	event_dispatch();

	bufferevent_free(bev);
	tls_free(ctx);
	tls_config_free(tlsconf);
	close(sock);

	return 0;
}
