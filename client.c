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

#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "client.h"
#include "kamid.h"
#include "log.h"
#include "sandbox.h"

static struct imsgev	*iev_listener;

static __dead void	client_shutdown(void);
static void		client_sig_handler(int, short, void *);
static void		client_dispatch_listener(int, short, void *);
static void		client_privdrop(const char *, const char *);

static int		client_imsg_compose_listener(int, uint32_t,
    const void *, uint16_t);

__dead void
client(int debug, int verbose)
{
	struct event	ev_sigint, ev_sigterm;

	log_init(debug, LOG_DAEMON);
	log_setverbose(verbose);

	setproctitle("client");
	log_procinit("client");

	log_debug("warming up");

	event_init();

	/* Setup signal handlers */
	signal_set(&ev_sigint, SIGINT, client_sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, client_sig_handler, NULL);

	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	/* Setup pipe and event handler to the listener process */
	if ((iev_listener = malloc(sizeof(*iev_listener))) == NULL)
		fatal(NULL);

	imsg_init(&iev_listener->ibuf, 3);
	iev_listener->handler = client_dispatch_listener;

	/* Setup event handlers. */
	iev_listener->events = EV_READ;
	event_set(&iev_listener->ev, iev_listener->ibuf.fd,
	    iev_listener->events, iev_listener->handler, iev_listener);
	event_add(&iev_listener->ev, NULL);

	log_debug("before dispatch");
	event_dispatch();
	client_shutdown();
}

static __dead void
client_shutdown(void)
{
	msgbuf_clear(&iev_listener->ibuf.w);
	close(iev_listener->ibuf.fd);

        free(iev_listener);

	log_info("client exiting");
	exit(0);
}

static void
client_sig_handler(int sig, short event, void *d)
{
	/*
	 * Normal signal handler rules don't apply because libevent
	 * decouples for us.
	 */

	switch (sig) {
	case SIGINT:
	case SIGTERM:
		client_shutdown();
	default:
		fatalx("unexpected signal %d", sig);
	}
}

#define AUTH_NONE 0
#define AUTH_USER 1
#define AUTH_DONE 2

static void
client_dispatch_listener(int fd, short event, void *d)
{
	static int		 auth = AUTH_NONE;
	static char		 username[64] = {0};
	static char		 dir[PATH_MAX] = {0};
	struct imsg		 imsg;
	struct imsgev		*iev = d;
	struct imsgbuf		*ibuf;
	ssize_t			 n;
	int			 shut = 0;

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
		if (n == 0)	/* Connection closed */
			shut = 1;
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("%s: imsg_get error", __func__);
		if (n == 0)	/* No more messages. */
			break;

		log_debug("client: got message type %d", imsg.hdr.type);
		switch (imsg.hdr.type) {
		case IMSG_AUTH:
			if (auth)
				fatalx("%s: IMSG_AUTH already done", __func__);
			auth = AUTH_USER;
			((char *)imsg.data)[IMSG_DATA_SIZE(imsg)-1] = '\0';
			strlcpy(username, imsg.data, sizeof(username));
			break;
		case IMSG_AUTH_DIR:
			if (auth != AUTH_USER)
				fatalx("%s: IMSG_AUTH_DIR not after IMSG_AUTH",
				    __func__);
			auth = AUTH_DONE;
			((char *)imsg.data)[IMSG_DATA_SIZE(imsg)-1] = '\0';
			strlcpy(dir, imsg.data, sizeof(dir));
			client_privdrop(username, dir);
			memset(username, 0, sizeof(username));
			memset(dir, 0, sizeof(username));
			break;
		case IMSG_BUF:
			/* echo! */
			client_imsg_compose_listener(IMSG_BUF, imsg.hdr.peerid,
			    imsg.data, IMSG_DATA_SIZE(imsg));
			break;
		case IMSG_CONN_GONE:
			log_debug("closing");
			shut = 1;
			break;
		default:
			log_debug("%s: unexpected imsg %d",
			    __func__, imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);
	}

	if (!shut)
		imsg_event_add(iev);
	else {
		/* This pipe is dead.  Remove its event handler. */
		event_del(&iev->ev);
		log_warnx("pipe closed, shutting down...");
		event_loopexit(NULL);
	}
}

static void
client_privdrop(const char *username, const char *dir)
{
	struct passwd *pw;

	setproctitle("client %s", username);

	if ((pw = getpwnam(username)) == NULL)
		fatalx("getpwnam(%s) failed", username);

	if (chroot(dir) == -1)
		fatal("chroot");
	if (chdir("/") == -1)
		fatal("chdir(\"/\")");

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("can't drop privileges");

	sandbox_client();
	log_debug("client ready");
}

static int
client_imsg_compose_listener(int type, uint32_t peerid,
    const void *data, uint16_t len)
{
	int ret;

	if ((ret = imsg_compose(&iev_listener->ibuf, type, peerid, 0, -1,
	    data, len)) != -1)
		imsg_event_add(iev_listener);

	return ret;
}
