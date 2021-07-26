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
#include <event.h>
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

#define PROMPT "> "

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

static void ATTR_DEAD	 usage(int);

static void		 sig_handler(int, short, void *);

static int		 openconn(void);

static void		 tls_readcb(int, short, void *);
static void		 tls_writecb(int, short, void *);

static void		 client_read(struct bufferevent *, void *);
static void		 client_write(struct bufferevent *, void *);
static void		 client_error(struct bufferevent *, short, void *);

static void		 readcmd(int, short, void *);

static void		 handle_9p(const void *, size_t);
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
		if (EVBUFFER_LENGTH(src) < 4)
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
readcmd(int fd, short event, void *data)
{
	char	*line = NULL;
	size_t	 linesize = 0;
	ssize_t	 linelen;

	if ((linelen = getline(&line, &linesize, stdin)) != -1) {
		line[linelen-1] = '\0';

		clr();
		log_info("TODO: parse `%s'", line);
		prompt();
	}

	free(line);
	if (ferror(stdin))
		fatal("getline");
}

static void
handle_9p(const void *data, size_t len)
{
	struct np_msg_header hdr;

	assert(len >= sizeof(hdr));
	memcpy(&hdr, data, sizeof(hdr));

	hdr.len = le32toh(hdr.len);
	/* type is one byte long, no endianness issues */
	hdr.tag = le16toh(hdr.tag);

	clr();
	log_info("[%d] type=%s len=%"PRIu32, hdr.tag, pp_msg_type(hdr.type),
	    hdr.len);
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
	int			 ch, sock, handshake;
	struct bufferevent	*bev;
	struct event		 inev, ev_sigint, ev_sigterm;

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

	event_set(&inev, 0, EV_READ, readcmd, NULL);
	event_add(&inev, NULL);

	prompt();
	event_dispatch();

	bufferevent_free(bev);
	tls_free(ctx);
	tls_config_free(tlsconf);
	close(sock);

	return 0;
}
