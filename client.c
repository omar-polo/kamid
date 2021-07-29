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

#include <sys/stat.h>

#include <endian.h>
#include <errno.h>
#include <fcntl.h>
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
#include "utils.h"

#if HAVE_ARC4RANDOM
# define RANDID() arc4random()
#else
static uint32_t counter;
# define RANDID() counter++
#endif

STAILQ_HEAD(qidhead, qid) qids;
struct qid {
	/* definition of a qid */
	uint64_t		 path;
	uint32_t		 vers;
	uint8_t			 type;

	int			 fd;

	STAILQ_ENTRY(qid)	 entries;
};

STAILQ_HEAD(fidhead, fid) fids;
struct fid {
	uint32_t		 fid;
	struct qid		*qid;
	STAILQ_ENTRY(fid)	 entries;
};

static struct imsgev	*iev_listener;
static struct evbuffer	*evb;
static uint32_t		 peerid;

static int		 handshaked;
uint32_t		 msize;

static ATTR_DEAD void	client_shutdown(void);
static void		client_sig_handler(int, short, void *);
static void		client_dispatch_listener(int, short, void *);
static void		client_privdrop(const char *, const char *);

static int		client_send_listener(int, const void *, uint16_t);

static struct qid	*new_qid(int);
static struct fid	*new_fid(struct qid *, uint32_t);

static void		parse_message(uint8_t *, size_t, struct np_msg_header *,
			    uint8_t **);

static void		np_header(uint32_t, uint8_t, uint16_t);
static void		np_string(uint16_t, const char *);
static void		np_qid(struct qid *);
static void		do_send(void);

static void		np_version(uint16_t, uint32_t, const char *);
static void		np_attach(uint16_t, struct qid *);
static void		np_error(uint16_t, const char *);
static void		np_errno(uint16_t);

static void		handle_message(struct imsg *, size_t);

ATTR_DEAD void
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

	event_dispatch();
	client_shutdown();
}

static ATTR_DEAD void
client_shutdown(void)
{
	if (evb != NULL)
		evbuffer_free(evb);

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

		switch (imsg.hdr.type) {
		case IMSG_AUTH:
			peerid = imsg.hdr.peerid;
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
			if (!auth)
				fatalx("%s: can't handle messages before"
				    " doing the auth", __func__);
			handle_message(&imsg, IMSG_DATA_SIZE(imsg));
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
	log_debug("client ready; user=%s dir=%s", username, dir);

	if ((evb = evbuffer_new()) == NULL)
		fatal("evbuffer_new");
}

static int
client_send_listener(int type, const void *data, uint16_t len)
{
	int ret;

	if ((ret = imsg_compose(&iev_listener->ibuf, type, peerid, 0, -1,
	    data, len)) != -1)
		imsg_event_add(iev_listener);

	return ret;
}

/* creates a qid given a fd */
static struct qid *
new_qid(int fd)
{
	struct stat	 sb;
	struct qid	*qid;

	if (fstat(fd, &sb) == -1) {
		log_warn("fstat");
		return NULL;
	}

	if ((qid = calloc(1, sizeof(*qid))) == NULL)
		return NULL;

	qid->fd = fd;

	qid->path = RANDID();

	if (S_ISREG(sb.st_mode))
		qid->type = QTFILE;
	else if (S_ISDIR(sb.st_mode))
		qid->type = QTDIR;
	else if (S_ISLNK(sb.st_mode))
		qid->type = QTSYMLINK;

        STAILQ_INSERT_HEAD(&qids, qid, entries);

	return qid;
}

static struct fid *
new_fid(struct qid *qid, uint32_t fid)
{
	struct fid *f;

	if ((f = calloc(1, sizeof(*f))) == NULL)
		return NULL;

	f->qid = qid;
	f->fid = fid;

	STAILQ_INSERT_HEAD(&fids, f, entries);

	return f;
}

static void
parse_message(uint8_t *data, size_t len, struct np_msg_header *hdr,
    uint8_t **cnt)
{
	if (len < 4)
		goto err;

	memcpy(&hdr->len, data, sizeof(hdr->len));
	data += sizeof(hdr->len);

	memcpy(&hdr->type, data, sizeof(hdr->type));
	data += sizeof(hdr->type);

	memcpy(&hdr->tag, data, sizeof(hdr->tag));
	data += sizeof(hdr->tag);

	hdr->len = le32toh(hdr->len);
	/* type is one byte long, no endianness issues */
	hdr->tag = le16toh(hdr->tag);

	if (len != hdr->len)
		goto err;

	if (hdr->type < Tversion ||
	    hdr->type >= Tmax    ||
	    hdr->type == Terror  ||
	    (hdr->type & 0x1) != 0) /* cannot recv a R* */
		goto err;

	hdr->tag = le32toh(hdr->tag);

	*cnt = data;
	return;

err:
	/* TODO: send a proper message to terminate the connection. */
	fatalx("got invalid message");
}

static void
np_header(uint32_t len, uint8_t type, uint16_t tag)
{
	len = htole32(len);
	tag = htole16(tag);

	evbuffer_add(evb, &len, sizeof(len));
	evbuffer_add(evb, &type, sizeof(type));
	evbuffer_add(evb, &tag, sizeof(tag));
}

static void
np_string(uint16_t len, const char *str)
{
	uint16_t l = len;

	len = htole16(len);
	evbuffer_add(evb, &len, sizeof(len));
	evbuffer_add(evb, str, l);
}

static void
np_qid(struct qid *qid)
{
	uint64_t	path;
	uint32_t	vers;

	path = htole64(qid->path);
	vers = htole32(qid->vers);

	evbuffer_add(evb, &path, sizeof(path));
	evbuffer_add(evb, &vers, sizeof(path));
	evbuffer_add(evb, &qid->type, sizeof(qid->type));
}

static void
do_send(void)
{
	size_t len;

	len = EVBUFFER_LENGTH(evb);
	log_debug("sending a packet long %zu bytes", len);
	client_send_listener(IMSG_BUF, EVBUFFER_DATA(evb), len);
	evbuffer_drain(evb, len);
}

static void
np_version(uint16_t tag, uint32_t msize, const char *version)
{
	uint32_t len = HEADERSIZE;
	uint16_t l;

	l = strlen(version);
	len += sizeof(msize) + sizeof(l) + l;

	msize = htole32(msize);

	np_header(len, Rversion, tag);
	evbuffer_add(evb, &msize, sizeof(msize));
	np_string(l, version);
	do_send();
}

static void
np_attach(uint16_t tag, struct qid *qid)
{
	uint32_t len = HEADERSIZE;

	len += 13;
	np_header(len, Rattach, tag);
	np_qid(qid);
	do_send();
}

static void
np_error(uint16_t tag, const char *errstr)
{
	uint32_t len = HEADERSIZE;
	uint16_t l;

	l = strlen(errstr);
	len += sizeof(l) + l;

	np_header(len, Rerror, tag);
	np_string(l, errstr);
	do_send();
}

static void
np_errno(uint16_t tag)
{
	char buf[64];

	strerror_r(errno, buf, sizeof(buf));
	np_error(tag, buf);
}

static void
handle_message(struct imsg *imsg, size_t len)
{
	struct np_msg_header	 hdr;
	struct qid		*qid;
	struct fid		*f;
	int			 fd;
	uint32_t		 fid;
	uint16_t		 slen;
	uint8_t			*data, *dot;
	char			 buf[16];

	parse_message(imsg->data, len, &hdr, &data);
	len -= HEADERSIZE;

	log_debug("got request: len=%d type=%d[%s] tag=%d",
	    hdr.len, hdr.type, pp_msg_type(hdr.type), hdr.tag);

	if (!handshaked && hdr.type != Tversion)
		goto err;

	switch (hdr.type) {
	case Tversion:
		if (handshaked)
			goto err;

		/* msize[4] + version[s] */
		if (len < 6)
			goto err;

		memcpy(&msize, data, sizeof(msize));
		data += sizeof(msize);
		msize = le32toh(msize);

		memcpy(&slen, data, sizeof(slen));
		data += sizeof(slen);
		slen = le16toh(slen);

		if ((dot = memchr(data, '.', slen)) != NULL)
			slen -= dot - data;

		if (slen != strlen(VERSION9P) ||
		    memcmp(data, VERSION9P, slen) != 0 ||
		    msize == 0) {
			slen = MIN(slen, sizeof(buf)-1);
			memcpy(buf, data, slen);
			buf[slen] = '\0';
			log_warnx("unknown 9P version string: [%d]\"%s\", "
			    "want " VERSION9P,
			    slen, buf);
			np_version(hdr.tag, MSIZE9P, "unknown");
			return;
		}

		handshaked = 1;

		msize = MIN(msize, MSIZE9P);
		client_send_listener(IMSG_MSIZE, &msize, sizeof(msize));
		np_version(hdr.tag, msize, VERSION9P);
		break;

	case Tattach:
		/* fid[4] afid[4] uname[s] aname[s] */

		/* for the moment, happily ignore afid */

		if ((fd = open("/", O_DIRECTORY)) == -1) {
			np_errno(hdr.tag);
                        return;
		}

		if ((qid = new_qid(fd)) == NULL) {
                        close(fd);
			np_error(hdr.tag, "no memory");
			return;
		}

		memcpy(&fid, data, sizeof(fid));
		data += sizeof(fid);
		fid = le32toh(fid);

		if ((f = new_fid(qid, fid)) == NULL) {
			close(qid->fd);
			free(qid);
			np_error(hdr.tag, "no memory");
			return;
		}

		np_attach(hdr.tag, qid);

		break;

	default:
		/* for now, log the request and reply with an error. */
		np_error(hdr.tag, "Not supported.");
		break;
	}

	return;

err:
	client_send_listener(IMSG_CLOSE, NULL, 0);
	client_shutdown();
}
