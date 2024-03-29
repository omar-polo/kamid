/*
 * Copyright (c) 2021, 2022 Omar Polo <op@omarpolo.com>
 * Copyright (c) 2018 Florian Obser <florian@openbsd.org>
 * Copyright (c) 2004, 2005 Claudio Jeker <claudio@openbsd.org>
 * Copyright (c) 2004 Esben Norby <norby@openbsd.org>
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
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

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <errno.h>
#include <grp.h>
#include <inttypes.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "control.h"
#include "kami.h"
#include "kamid.h"
#include "listener.h"
#include "log.h"
#include "sandbox.h"
#include "utils.h"

#define IMSG_MAXSIZE (MAX_IMSGSIZE - IMSG_HEADER_SIZE)

static struct kd_conf	*listener_conf;
static struct imsgev	*iev_main;

static void	listener_sig_handler(int, short, void *);
__dead void	listener_shutdown(void);

SPLAY_HEAD(clients_tree_id, client) clients;

struct client {
	uint32_t		 id;
	uint32_t		 lid;
	uint32_t		 lflags;
	uint32_t		 msize;
	uint32_t		 left;
	int			 fd;
	struct tls		*ctx;
	struct event		 event;
	struct imsgev		 iev;
	struct bufferevent	*bev;
	SPLAY_ENTRY(client)	 sp_entry;
};

static void	listener_imsg_event_add(struct imsgev *, void *);
static void	listener_dispatch_client(int, short, void *);
static int	listener_imsg_compose_client(struct client *, int,
    uint32_t, const void *, uint16_t);

static void	apply_config(struct kd_conf *);
static void	handle_accept(int, short, void *);

static void	handle_handshake(int, short, void *);
static void	client_read(struct bufferevent *, void *);
static void	client_write(struct bufferevent *, void *);
static void	client_error(struct bufferevent *, short, void *);
static void	client_tls_readcb(int, short, void *);
static void	client_tls_writecb(int, short, void *);
static void	close_conn(struct client *);
static void	handle_close(int, short, void *);

static inline int
clients_tree_cmp(struct client *a, struct client *b)
{
	if (a->id == b->id)
		return 0;
	else if (a->id < b->id)
		return -1;
	else
		return +1;
}

SPLAY_PROTOTYPE(clients_tree_id, client, sp_entry, clients_tree_cmp);
SPLAY_GENERATE(clients_tree_id, client, sp_entry, clients_tree_cmp);

static void
listener_sig_handler(int sig, short event, void *d)
{
	/*
	 * Normal signal handler rules don't apply because libevent
	 * decouples for us.
	 */

	switch (sig) {
	case SIGINT:
	case SIGTERM:
		listener_shutdown();
	default:
		fatalx("unexpected signal %d", sig);
	}
}

void
listener(int debug, int verbose)
{
	struct event		 ev_sigint, ev_sigterm;
	struct passwd		*pw;

	/* listener_conf = config_new_empty(); */

	log_init(debug, LOG_DAEMON);
	log_setverbose(verbose);

	if ((pw = getpwnam(KD_USER)) == NULL)
		fatal("getpwnam");

	if (chroot(pw->pw_dir) == -1)
		fatal("chroot");
	if (chdir("/") == -1)
		fatal("chdir(\"/\")");

	setproctitle("listener");
	log_procinit("listener");

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("can't drop privileges");

	event_init();

	/* Setup signal handlers(s). */
	signal_set(&ev_sigint, SIGINT, listener_sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, listener_sig_handler, NULL);

	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	/* Setup pipe and event handler to the main process. */
	if ((iev_main = malloc(sizeof(*iev_main))) == NULL)
		fatal(NULL);

	imsg_init(&iev_main->ibuf, 3);
	iev_main->handler = listener_dispatch_main;

	/* Setup event handlers. */
	iev_main->events = EV_READ;
	event_set(&iev_main->ev, iev_main->ibuf.fd, iev_main->events,
	    iev_main->handler, iev_main);
	event_add(&iev_main->ev, NULL);

	sandbox_listener();
	event_dispatch();
	listener_shutdown();
}

__dead void
listener_shutdown(void)
{
	msgbuf_clear(&iev_main->ibuf.w);
	close(iev_main->ibuf.fd);

	clear_config(listener_conf);

	free(iev_main);

	log_info("listener exiting");
	exit(0);
}

static void
listener_receive_config(struct imsg *imsg, struct kd_conf **nconf,
    struct kd_pki_conf **pki)
{
	struct kd_listen_conf *listen;
	char *t;

	switch (imsg->hdr.type) {
	case IMSG_RECONF_CONF:
		if (*nconf != NULL)
			fatalx("%s: IMSG_RECONF_CONF already in "
			    "progress", __func__);

		if (IMSG_DATA_SIZE(*imsg) != sizeof(struct kd_conf))
			fatalx("%s: IMSG_RECONF_CONF wrong length: %lu",
			    __func__, IMSG_DATA_SIZE(*imsg));
		if ((*nconf = malloc(sizeof(**nconf))) == NULL)
			fatal(NULL);
		memcpy(*nconf, imsg->data, sizeof(**nconf));
		STAILQ_INIT(&(*nconf)->pki_head);
		STAILQ_INIT(&(*nconf)->table_head);
		STAILQ_INIT(&(*nconf)->listen_head);
		break;
	case IMSG_RECONF_PKI:
		if (*nconf == NULL)
			fatalx("%s: IMSG_RECONF_PKI without "
			    "IMSG_RECONF_CONF", __func__);
		*pki = xcalloc(1, sizeof(**pki));
		t = imsg->data;
		t[IMSG_DATA_SIZE(*imsg)-1] = '\0';
		strlcpy((*pki)->name, t, sizeof((*pki)->name));
		break;
	case IMSG_RECONF_PKI_CERT:
		if (*pki == NULL)
			fatalx("%s: IMSG_RECONF_PKI_CERT without "
			    "IMSG_RECONF_PKI", __func__);
		(*pki)->certlen = IMSG_DATA_SIZE(*imsg);
		(*pki)->cert = xmemdup(imsg->data, (*pki)->certlen);
		break;
	case IMSG_RECONF_PKI_KEY:
		if (*pki == NULL)
			fatalx("%s: IMSG_RECONF_PKI_KEY without "
			    "IMSG_RECONF_PKI", __func__);
		(*pki)->keylen = IMSG_DATA_SIZE(*imsg);
		(*pki)->key = xmemdup(imsg->data, (*pki)->keylen);
		STAILQ_INSERT_HEAD(&(*nconf)->pki_head, *pki, entry);
		pki = NULL;
		break;
	case IMSG_RECONF_LISTEN:
		if (*nconf == NULL)
			fatalx("%s: IMSG_RECONF_LISTEN without "
			    "IMSG_RECONF_CONF", __func__);
		if (IMSG_DATA_SIZE(*imsg) != sizeof(*listen))
			fatalx("%s: IMSG_RECONF_LISTEN wrong length: %lu",
			    __func__, IMSG_DATA_SIZE(*imsg));
		listen = xcalloc(1, sizeof(*listen));
		memcpy(listen, imsg->data, sizeof(*listen));
		memset(&listen->entry, 0, sizeof(listen->entry));
		if ((listen->fd = imsg->fd) == -1)
			fatalx("%s: IMSG_RECONF_LISTEN no fd",
			    __func__);
		listen->auth_table = NULL;
		memset(&listen->ev, 0, sizeof(listen->ev));
		STAILQ_INSERT_HEAD(&(*nconf)->listen_head, listen, entry);
		break;
	case IMSG_RECONF_END:
		if (*nconf == NULL)
			fatalx("%s: IMSG_RECONF_END without "
			    "IMSG_RECONF_CONF", __func__);
		apply_config(*nconf);
		*nconf = NULL;
		break;
	}
}

void
listener_dispatch_main(int fd, short event, void *d)
{
	static struct kd_conf		*nconf;
	static struct kd_pki_conf	*pki;
	struct client			*client, find;
	struct imsg			 imsg;
	struct imsgev			*iev = d;
	struct imsgbuf			*ibuf;
	ssize_t				 n;
	int				 shut = 0;

	ibuf = &iev->ibuf;

	if (event & EV_READ) {
		if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
			fatal("imsg_read error");
		if (n == 0)	/* Connection closed. */
			shut = 1;
	}
	if (event & EV_WRITE) {
		if ((n = msgbuf_write(&ibuf->w)) == -1 && errno != EAGAIN)
			fatal("msgbuf_write");
		if (n == 0)	/* Connection closed. */
			shut = 1;
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("%s: imsg_get error", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case IMSG_CTL_LOG_VERBOSE:
			if (IMSG_DATA_SIZE(imsg) != sizeof(verbose))
				fatalx("wrong size for IMSG_CTL_LOG_VERBOSE");
			memcpy(&verbose, imsg.data, sizeof(verbose));
			log_setverbose(verbose);
			SPLAY_FOREACH(client, clients_tree_id, &clients)
				listener_imsg_compose_client(client,
				    imsg.hdr.type, 0,
				    &verbose, sizeof(verbose));
			break;
		case IMSG_CTL_DEBUG:
			if (SPLAY_EMPTY(&clients))
				listener_imsg_compose_main(IMSG_CTL_DEBUG_END,
				    imsg.hdr.peerid, NULL, 0);
			SPLAY_FOREACH(client, clients_tree_id, &clients)
				listener_imsg_compose_client(client,
				    imsg.hdr.type, imsg.hdr.peerid,
				    imsg.data, IMSG_DATA_SIZE(imsg));
			break;
		case IMSG_RECONF_CONF:
		case IMSG_RECONF_PKI:
		case IMSG_RECONF_PKI_CERT:
		case IMSG_RECONF_PKI_KEY:
		case IMSG_RECONF_LISTEN:
		case IMSG_RECONF_END:
			listener_receive_config(&imsg, &nconf, &pki);
			break;
		case IMSG_AUTH:
			if (IMSG_DATA_SIZE(imsg) != sizeof(struct kd_auth_proc))
				fatalx("mismatching size for IMSG_AUTH");

			find.id = imsg.hdr.peerid;
			client = SPLAY_FIND(clients_tree_id, &clients, &find);
			if (client == NULL) {
				if (imsg.fd != -1)
					close(imsg.fd);
				break;
			}
			if (imsg.fd == -1) {
				log_info("got fd = -1, auth failed?");
				close_conn(client);
				break;
			}
			imsg_init(&client->iev.ibuf, imsg.fd);
			client->iev.events = EV_READ;
			client->iev.handler = listener_dispatch_client;
			event_set(&client->iev.ev, client->iev.ibuf.fd,
			    client->iev.events, client->iev.handler, client);
			listener_imsg_compose_client(client, IMSG_AUTH,
			    client->id, imsg.data, IMSG_DATA_SIZE(imsg));

			client->bev = bufferevent_new(client->fd,
			    client_read, client_write, client_error,
			    client);
			if (client->bev == NULL) {
				log_info("failed to allocate client buffer");
				close_conn(client);
				return;
			}

#if HAVE_EVENT2
			evbuffer_unfreeze(client->bev->input, 0);
			evbuffer_unfreeze(client->bev->output, 1);
#endif

			if (client->lflags & L_TLS) {
				event_set(&client->bev->ev_read, client->fd,
				    EV_READ, client_tls_readcb, client->bev);
				event_set(&client->bev->ev_write, client->fd,
				    EV_WRITE, client_tls_writecb, client->bev);
			}

			/*
			 * Read or write at least a header before
			 * firing the callbacks.  High watermark of 0
			 * to never stop reading/writing; probably to
			 * be revisited.
			 */
			/* bufferevent_setwatermark(client->bev, EV_READ|EV_WRITE, */
			    /* sizeof(struct np_msg_header), 0); */
			bufferevent_enable(client->bev, EV_READ|EV_WRITE);
			break;

		default:
			log_debug("%s: unexpected imsg %d", __func__,
			    imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);
	}

	if (!shut)
		listener_imsg_event_add(iev, d);
	else {
		/* This pipe is dead.  Remove its event handler. */
		event_del(&iev->ev);
		log_warnx("pipe closed, shutting down...");
		event_loopexit(NULL);
	}
}

int
listener_imsg_compose_main(int type, uint32_t peerid, const void *data,
    uint16_t datalen)
{
	return imsg_compose_event(iev_main, type, peerid, 0, -1, data,
	    datalen);
}

static void
listener_imsg_event_add(struct imsgev *iev, void *d)
{
	iev->events = EV_READ;
	if (iev->ibuf.w.queued)
		iev->events |= EV_WRITE;

	event_del(&iev->ev);
	event_set(&iev->ev, iev->ibuf.fd, iev->events, iev->handler, d);
	event_add(&iev->ev, NULL);
}

static void
listener_dispatch_client(int fd, short event, void *d)
{
        struct client	 find, *client = d;
	struct imsg	 imsg;
	struct imsgev	*iev;
	struct imsgbuf	*ibuf;
	ssize_t		 n;
	int		 r, shut = 0;

	iev = &client->iev;
	ibuf = &iev->ibuf;

	if (event & EV_READ) {
		if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
			fatal("imsg_read error");
		if (n == 0)	/* Connection closed */
			shut = 1;
	}

	if (event & EV_WRITE) {
		if ((n = msgbuf_write(&ibuf->w)) == -1 && errno != EAGAIN)
			fatal("msgbuf_write");
		if (n == 0)	/* Connection closed. */
			shut = 1;
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("%s: imsg_get error", __func__);
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case IMSG_CTL_DEBUG_BACK:
		case IMSG_CTL_DEBUG_END:
			listener_imsg_compose_main(imsg.hdr.type,
			    imsg.hdr.peerid, imsg.data, IMSG_DATA_SIZE(imsg));
			break;

		case IMSG_BUF:
			find.id = imsg.hdr.peerid;
			client = SPLAY_FIND(clients_tree_id, &clients, &find);
			if (client == NULL) {
				log_info("got IMSG_BUF but client %d gone",
				    imsg.hdr.peerid);
				break;
			}
			r = bufferevent_write(client->bev, imsg.data,
			    IMSG_DATA_SIZE(imsg));
			if (r == -1) {
				log_warn("%s: bufferevent_write failed",
				    __func__);
				close_conn(client);
				break;
			}
			break;

		case IMSG_MSIZE:
			if (IMSG_DATA_SIZE(imsg) != sizeof(client->msize))
				fatal("IMSG_MSIZE size mismatch: "
				    "got %zu want %zu", IMSG_DATA_SIZE(imsg),
				    sizeof(client->msize));

			memcpy(&client->msize, imsg.data,
			    sizeof(client->msize));

			if (client->msize == 0)
				fatal("IMSG_MSIZE got msize = 0");
			log_debug("set msize to %d", client->msize);
			break;

		case IMSG_CLOSE:
			/*
			 * Both EVBUFFER_READ or EVBUFFER_WRITE should
			 * be fine.
			 */
			client_error(client->bev, EVBUFFER_READ, client);
			break;

		default:
			log_debug("%s: unexpected imsg %d", __func__,
			    imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);
	}

	if (!shut)
		listener_imsg_event_add(iev, d);
	else {
		/* This pipe is dead.  Remove its handler */
		log_debug("client proc vanished");
                close_conn(client);
	}
}

static int
listener_imsg_compose_client(struct client *client, int type,
    uint32_t peerid, const void *data, uint16_t len)
{
	int ret;

	if ((ret = imsg_compose(&client->iev.ibuf, type, peerid, 0, -1,
	    data, len)) != -1)
		listener_imsg_event_add(&client->iev, client);

	return ret;
}

static inline struct kd_pki_conf *
pki_by_name(const char *name)
{
        struct kd_pki_conf *pki;

	STAILQ_FOREACH(pki, &listener_conf->pki_head, entry) {
		if (!strcmp(name, pki->name))
			return pki;
	}

	return NULL;
}

static void
apply_config(struct kd_conf *conf)
{
	struct kd_pki_conf *pki;
	struct kd_listen_conf *listen;
	struct client *c;

	/* drop any pre-auth inflight connections */
	SPLAY_FOREACH(c, clients_tree_id, &clients) {
		/*
		 * c->event is set only during the handshake and the teardown
		 * of the connection; c->bev is set only after auth.  Checking
		 * for both ensures we drop only incoming connection in the
		 * pre-auth state.
		 */
		if (event_pending(&c->event, EV_READ|EV_WRITE, NULL) &&
		    c->bev == NULL) {
			log_warn("closing in-flight connection due to reload");
			close_conn(c);
		}
	}

	/* swap the now config with the current one */
	clear_config(listener_conf);
	listener_conf = conf;

	/* prepare the various tls_config */
	STAILQ_FOREACH(pki, &listener_conf->pki_head, entry) {
		if ((pki->tlsconf = tls_config_new()) == NULL)
			fatal("tls_config_new");
		tls_config_verify_client_optional(pki->tlsconf);
		tls_config_insecure_noverifycert(pki->tlsconf);
		if (tls_config_set_keypair_mem(pki->tlsconf,
		    pki->cert, pki->certlen,
		    pki->key, pki->keylen) == -1)
			fatalx("tls_config_set_keypair_mem: %s",
			    tls_config_error(pki->tlsconf));
	}

	/* prepare and kickoff the listeners */
	STAILQ_FOREACH(listen, &listener_conf->listen_head, entry) {
		if ((listen->ctx = tls_server()) == NULL)
			fatal("tls_server");

		pki = pki_by_name(listen->pki);
		if (tls_configure(listen->ctx, pki->tlsconf) == -1)
			fatalx("tls_configure: %s",
			    tls_config_error(pki->tlsconf));

		event_set(&listen->ev, listen->fd, EV_READ|EV_PERSIST,
		    handle_accept, listen);
		event_add(&listen->ev, NULL);
	}
}

static inline void
yield_r(struct client *c, void (*fn)(int, short, void *))
{
	if (event_pending(&c->event, EV_WRITE|EV_READ, NULL))
		event_del(&c->event);
	event_set(&c->event, c->fd, EV_READ, fn, c);
	event_add(&c->event, NULL);
}

static inline void
yield_w(struct client *c, void (*fn)(int, short, void *))
{
	if (event_pending(&c->event, EV_WRITE|EV_READ, NULL))
		event_del(&c->event);
	event_set(&c->event, c->fd, EV_WRITE, fn, c);
	event_add(&c->event, NULL);
}

static void
handle_accept(int fd, short ev, void *data)
{
	static uint32_t counter;
	struct kd_listen_conf *listen = data;
	struct client *c;
	int s;

	if ((s = accept(fd, NULL, NULL)) == -1) {
		log_warn("accept");
		return;
	}

	c = xcalloc(1, sizeof(*c));
	c->msize = MSIZE9P;
	c->lid = listen->id;
	c->lflags = listen->flags;
	c->iev.ibuf.fd = -1;

	if (tls_accept_socket(listen->ctx, &c->ctx, s) == -1) {
		log_warnx("tls_accept_socket: %s",
		    tls_error(listen->ctx));
		free(c);
		close(s);
		return;
	}

	c->fd = s;
	c->id = counter++;

	SPLAY_INSERT(clients_tree_id, &clients, c);

	/* initialize the event */
	event_set(&c->event, c->fd, EV_READ, NULL, NULL);

	yield_r(c, handle_handshake);
}

static void
handle_handshake(int fd, short ev, void *data)
{
	struct client *c = data;
	struct kd_auth_req auth;
	ssize_t r;
	const char *hash;

	switch (r = tls_handshake(c->ctx)) {
	case TLS_WANT_POLLIN:
		yield_r(c, handle_handshake);
		return;
	case TLS_WANT_POLLOUT:
		yield_w(c, handle_handshake);
		return;
	case -1:
		log_debug("handhsake failed: %s", tls_error(c->ctx));
		close_conn(c);
		return;
	}

	if ((hash = tls_peer_cert_hash(c->ctx)) == NULL) {
		log_warnx("client didn't provide certificate");
		close_conn(c);
		return;
	}

	memset(&auth, 0, sizeof(auth));
	auth.listen_id = c->lid;
	strlcpy(auth.hash, hash, sizeof(auth.hash));
	log_debug("sending hash %s", auth.hash);

	listener_imsg_compose_main(IMSG_AUTH_TLS, c->id,
	    &auth, sizeof(auth));
}

static void
client_read(struct bufferevent *bev, void *d)
{
	struct client	*client = d;
	struct evbuffer	*src = EVBUFFER_INPUT(bev);
	size_t evlen;
	uint32_t len;

	for (;;) {
		evlen = EVBUFFER_LENGTH(src);

		if (client->left != 0) {
			/* wait to fill a whole imsg if possible */
			if (client->left >= IMSG_MAXSIZE &&
			    evlen < IMSG_MAXSIZE)
				return;

			len = MIN(client->left, evlen);
			len = MIN(len, IMSG_MAXSIZE);

			listener_imsg_compose_client(client, IMSG_BUF_CONT,
			    client->id, EVBUFFER_DATA(src), len);
			evbuffer_drain(src, len);
			client->left -= len;
			continue;
		}

		if (evlen < 4)
			return;

		memcpy(&len, EVBUFFER_DATA(src), sizeof(len));
		len = le32toh(len);
		log_debug("expecting a message %"PRIu32" bytes long "
		    "(of wich %zu already read)", len, evlen);

		if (len < HEADERSIZE) {
			log_warnx("invalid message size %d (too low)", len);
			client_error(bev, EVBUFFER_READ, client);
			return;
		}

		if (len > client->msize) {
			log_warnx("incoming message bigger than msize "
			    "(%"PRIu32" vs %"PRIu32")", len, client->msize);
			client_error(bev, EVBUFFER_READ, client);
			return;
		}

		if (len > IMSG_MAXSIZE && evlen >= len) {
			listener_imsg_compose_client(client, IMSG_BUF,
			    client->id, EVBUFFER_DATA(src), IMSG_MAXSIZE);
			evbuffer_drain(src, IMSG_MAXSIZE);
			client->left = len - IMSG_MAXSIZE;
			continue;
		}

		if (len > evlen)
			return;

		listener_imsg_compose_client(client, IMSG_BUF, client->id,
		    EVBUFFER_DATA(src), len);
		evbuffer_drain(src, len);
	}
}

static void
client_write(struct bufferevent *bev, void *d)
{
	/*
	 * here we can do some fancy logic like deciding when to call
	 *
	 *	(*bev->errorcb)(bev, EVBUFFER_WRITE, bev->cbarg)
	 *
	 * to signal the end of the transaction.
	 */

	return;
}

static void
client_error(struct bufferevent *bev, short err, void *d)
{
	struct client	*client = d;
	struct evbuffer	*buf;

        if (err & EVBUFFER_ERROR) {
		if (errno == EFBIG) {
			bufferevent_enable(bev, EV_READ);
			return;
		}
		log_debug("buffer event error");
                close_conn(client);
		return;
	}

	if (err & EVBUFFER_EOF) {
                close_conn(client);
		return;
	}

	if (err & (EVBUFFER_READ|EVBUFFER_WRITE)) {
		bufferevent_disable(bev, EV_READ|EV_WRITE);

		buf = EVBUFFER_OUTPUT(client->bev);
		if (EVBUFFER_LENGTH(buf) != 0) {
			/* finish writing all the data first */
			bufferevent_enable(client->bev, EV_WRITE);
			return;
		}

		close_conn(client);
		return;
	}

	log_warnx("unknown event error, closing client connection");
	close_conn(client);
}

static void
client_tls_readcb(int fd, short event, void *d)
{
	struct bufferevent	*bufev = d;
	struct client		*client = bufev->cbarg;
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

        switch (ret = tls_read(client->ctx, buf, howmuch)) {
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
client_tls_writecb(int fd, short event, void *d)
{
	struct bufferevent	*bufev = d;
	struct client		*client = bufev->cbarg;
	ssize_t			 ret;
	size_t			 len;
	short			 what = EVBUFFER_WRITE;

	if (event == EV_TIMEOUT) {
		what |= EVBUFFER_TIMEOUT;
		goto err;
	}

	if (EVBUFFER_LENGTH(bufev->output) != 0) {
		ret = tls_write(client->ctx,
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
close_conn(struct client *c)
{
	log_debug("closing connection");

	SPLAY_REMOVE(clients_tree_id, &clients, c);

	if (c->iev.ibuf.fd != -1) {
		listener_imsg_compose_client(c, IMSG_CONN_GONE, 0, NULL, 0);
		imsg_flush(&c->iev.ibuf);
		msgbuf_clear(&c->iev.ibuf.w);
		event_del(&c->iev.ev);
		close(c->iev.ibuf.fd);
	}

	handle_close(c->fd, 0, c);
}

static void
handle_close(int fd, short ev, void *d)
{
	struct client *c = d;

	switch (tls_close(c->ctx)) {
	case TLS_WANT_POLLIN:
		yield_r(c, handle_close);
		return;
	case TLS_WANT_POLLOUT:
		yield_w(c, handle_close);
		return;
	}

	event_del(&c->event);
	tls_free(c->ctx);
	close(c->fd);
	free(c);
}
