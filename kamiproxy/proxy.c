/*
 * Copyright (c) 2022 Omar Polo <op@omarpolo.com>
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

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <tls.h>
#include <unistd.h>

#include "log.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))

int		 debug;
int		 verbose;
const char	*tohost;
const char	*fromhost;

uint8_t		*cert;
size_t		 certlen;
uint8_t		*key;
size_t		 keylen;

#define MAXSOCK 32
struct event	sockev[MAXSOCK];
int		socks[MAXSOCK];
int		nsock;

char		kamihost[64];
char		kamiport[8];

struct conn {
	struct tls		*ctx;
	struct bufferevent	*server;
	int			 kfd;
	struct bufferevent	*client;
	int			 lfd;
};

#ifndef __OpenBSD__
# define pledge(a, b) (0)
#endif

static const char *
copysec(const char *s, char *d, size_t len)
{
	const char *c;

	if ((c = strchr(s, ':')) == NULL)
		return NULL;
	if ((size_t)(c-s) >= len-1)
		return NULL;
	memset(d, 0, len);
	memcpy(d, s, c - s);
	return c;
}

static void
parse_tohost(void)
{
	const char *c;

	if ((c = strchr(tohost, ':')) == NULL) {
		strlcpy(kamihost, tohost, sizeof(kamihost));
		strlcpy(kamiport, "1337", sizeof(kamiport));
		return;
	}

	if ((c = copysec(tohost, kamihost, sizeof(kamihost))) == NULL)
		fatalx("hostname too long: %s", tohost);

	strlcpy(kamiport, c+1, sizeof(kamiport));
}

static void
tls_readcb(int fd, short event, void *d)
{
	struct bufferevent	*bufev = d;
	struct conn		*conn = bufev->cbarg;
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

	switch (ret = tls_read(conn->ctx, buf, howmuch)) {
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
	if (bufev->wm_read.high != 0 && len > bufev->wm_read.high) {
		/*
		 * here we could implement some read pressure
		 * mechanism.
		 */
	}

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
	struct conn		*conn = bufev->cbarg;
	ssize_t			 ret;
	size_t			 len;
	short			 what = EVBUFFER_WRITE;

	if (event == EV_TIMEOUT) {
		what |= EVBUFFER_TIMEOUT;
		goto err;
	}

	if (EVBUFFER_LENGTH(bufev->output) != 0) {
		ret = tls_write(conn->ctx,
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
		len = ret;
		evbuffer_drain(bufev->output, len);
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
setup(void)
{
	struct addrinfo	 hints, *res, *res0;
	int		 v, r, saved_errno;
	char		 host[64];
	const char	*c, *h, *port, *cause;

	if ((c = strchr(fromhost, ':')) == NULL) {
		h = NULL;
		port = fromhost;
	} else {
		if ((c = copysec(fromhost, host, sizeof(host))) == NULL)
			fatalx("hostname too long: %s", fromhost);
		h = host;
		port = c+1;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	r = getaddrinfo(h, port, &hints, &res0);
	if (r != 0)
		fatalx("getaddrinfo(%s): %s", fromhost,
		    gai_strerror(r));

	for (res = res0; res && nsock < MAXSOCK; res = res->ai_next) {
		socks[nsock] = socket(res->ai_family, res->ai_socktype,
		    res->ai_protocol);
		if (socks[nsock] == -1) {
			cause = "socket";
			continue;
		}

		if (bind(socks[nsock], res->ai_addr, res->ai_addrlen) == -1) {
			cause = "bind";
			saved_errno = errno;
			close(socks[nsock]);
			errno = saved_errno;
			continue;
		}

		v = 1;
		if (setsockopt(socks[nsock], SOL_SOCKET, SO_REUSEADDR, &v,
		    sizeof(v)) == -1)
			err(1, "setsockopt(SO_REUSEADDR)");

		v = 1;
		if (setsockopt(socks[nsock], SOL_SOCKET, SO_REUSEPORT, &v,
		    sizeof(v)) == -1)
			err(1, "setsockopt(SO_REUSEPORT)");

		listen(socks[nsock], 5);
		nsock++;
	}

	if (nsock == 0)
		fatal("%s", cause);

	freeaddrinfo(res0);
}

static int
servconnect(void)
{
	struct addrinfo	 hints, *res, *res0;
	int		 r, saved_errno, sock;
	const char	*cause;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	r = getaddrinfo(kamihost, kamiport, &hints, &res0);
	if (r != 0) {
		log_warnx("getaddrinfo(%s, %s): %s", kamihost, kamiport,
		    gai_strerror(r));
		return -1;
	}

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

		/* found one */
		break;
	}

	if (sock == -1)
		log_warn("%s", cause);

	freeaddrinfo(res0);
	return sock;
}

static void
copy_to_server(struct bufferevent *bev, void *d)
{
	struct conn *c = d;

	bufferevent_write_buffer(c->server, EVBUFFER_INPUT(bev));
}

static void
copy_to_client(struct bufferevent *bev, void *d)
{
	struct conn *c = d;

	bufferevent_write_buffer(c->client, EVBUFFER_INPUT(bev));
}

static void
nopcb(struct bufferevent *bev, void *d)
{
	return;
}

static void
errcb(struct bufferevent *bev, short ev, void *d)
{
	struct conn *c = d;

	log_debug("closing connection (event=%x / side=%s)", ev,
	    bev == c->server ? "server" : "client");

	bufferevent_free(c->server);
	bufferevent_free(c->client);

	tls_close(c->ctx);
	tls_free(c->ctx);

	close(c->lfd);
	close(c->kfd);

	free(c);
}

static void
doaccept(int fd, short ev, void *data)
{
	struct tls_config	*conf;
	struct conn		*c;
	int			 r;

	if ((c = calloc(1, sizeof(*c))) == NULL)
		fatal("calloc");

	if ((c->lfd = accept(fd, NULL, 0)) == -1) {
		log_warn("accept");
		free(c);
		return;
	}

	if ((c->kfd = servconnect()) == -1) {
		close(c->lfd);
		free(c);
		return;
	}

	if ((c->ctx = tls_client()) == NULL)
		fatal("tls_client");

	if ((conf = tls_config_new()) == NULL)
		fatal("tls_config_new");

	if (tls_config_set_cert_mem(conf, cert, certlen) == -1 ||
	    tls_config_set_key_mem(conf, key, keylen) == -1)
		fatalx("tls_config_set_{cert,key}: %s", tls_config_error(conf));
	tls_config_insecure_noverifycert(conf);

	if (tls_configure(c->ctx, conf) == -1)
		fatalx("tls_configure");

	tls_config_free(conf);

	if (tls_connect_socket(c->ctx, c->kfd, kamihost) == -1)
		fatal("tls_connect_socket");

again:	switch (r = tls_handshake(c->ctx)) {
	case -1:
		log_warnx("tls_handshake: %s", tls_error(c->ctx));
		tls_close(c->ctx);
		tls_free(c->ctx);
		close(c->lfd);
		close(c->kfd);
		free(c);
		return;
	case TLS_WANT_POLLIN:
	case TLS_WANT_POLLOUT:
		goto again;
	}

	c->server = bufferevent_new(c->kfd, copy_to_client, nopcb, errcb, c);
	if (c->server == NULL)
		fatal("bufferevent_new");

	event_set(&c->server->ev_read, c->kfd, EV_READ, tls_readcb,
	    c->server);
	event_set(&c->server->ev_write, c->kfd, EV_WRITE, tls_writecb,
	    c->server);

#if HAVE_EVENT2
	evbuffer_unfreeze(c->server->input, 0);
	evbuffer_unfreeze(c->server->output, 1);
#endif

	c->client = bufferevent_new(c->lfd, copy_to_server, nopcb, errcb, c);
	if (c->client == NULL)
		fatal("bufferevent_new");

	bufferevent_enable(c->server, EV_READ|EV_WRITE);
	bufferevent_enable(c->client, EV_READ|EV_WRITE);
}

__dead static void
usage(void)
{
	fprintf(stderr,
	    "usage: %s [-dv] -c host[:port] -l [host:]port -C cert [-K key]\n",
	    getprogname());
	exit(1);
}

int
main(int argc, char **argv)
{
	int		 ch, i;
	const char	*certf = NULL, *keyf = NULL;

	log_init(1, LOG_DAEMON);
	log_setverbose(1);

	while ((ch = getopt(argc, argv, "C:c:dK:l:v")) != -1) {
		switch (ch) {
		case 'C':
			certf = optarg;
			break;
		case 'c':
			tohost = optarg;
			break;
		case 'd':
			debug = 1;
			break;
		case 'K':
			keyf = optarg;
			break;
		case 'l':
			fromhost = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage();
	if (certf == NULL || tohost == NULL || fromhost == NULL)
		usage();
	if (keyf == NULL)
		keyf = certf;

	parse_tohost();

	if ((cert = tls_load_file(certf, &certlen, NULL)) == NULL)
		fatal("can't load %s", certf);
	if ((key = tls_load_file(keyf, &keylen, NULL)) == NULL)
		fatal("can't load %s", keyf);

	log_init(debug, LOG_DAEMON);
	log_setverbose(verbose);

	if (!debug)
		daemon(1, 0);

	signal(SIGPIPE, SIG_IGN);

	event_init();

	setup();
	for (i = 0; i < nsock; ++i) {
		event_set(&sockev[i], socks[i], EV_READ|EV_PERSIST,
		    doaccept, NULL);
		event_add(&sockev[i], NULL);
	}

	if (pledge("stdio dns inet", NULL) == -1)
		err(1, "pledge");

	log_info("starting");
	event_dispatch();

	return 0;
}
