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

#define DEBUG_PACKETS 0

STAILQ_HEAD(qidhead, qid) qids;
struct qid {
	/* definition of a qid */
	uint64_t		 path;
	uint32_t		 vers;
	uint8_t			 type;

	int			 fd;
	int			 refcount;

	char			 fpath[PATH_MAX];
	struct stat		 sb;

	STAILQ_ENTRY(qid)	 entries;
};

STAILQ_HEAD(fidhead, fid) fids;
struct fid {
	uint32_t		 fid;
	int			 iomode;
	struct qid		*qid;
	STAILQ_ENTRY(fid)	 entries;
};

static struct imsgev	*iev_listener;
static struct evbuffer	*evb;
static uint32_t		 peerid;

static int		 handshaked, attached;
uint32_t		 msize;

static ATTR_DEAD void	client_shutdown(void);
static void		client_sig_handler(int, short, void *);
static void		client_dispatch_listener(int, short, void *);
static void		client_privdrop(const char *, const char *);

static int		client_send_listener(int, const void *, uint16_t);

static void		 qid_set_from_sb(struct qid *);
static int		 qid_update_stat(struct qid *);
static struct qid	*qid_from_copy(const struct qid *);
static struct qid	*qid_from_fd(int);
static struct qid	*qid_from_path(const char *);
static struct qid	*qid_incref(struct qid *);
static void		 qid_decref(struct qid *);

static struct fid	*new_fid(struct qid *, uint32_t);
static struct fid	*fid_by_id(uint32_t);
static void		 free_fid(struct fid *);

static void		parse_message(const uint8_t *, size_t,
			    struct np_msg_header *, uint8_t **);

static void		np_write16(uint16_t);
static void		np_header(uint32_t, uint8_t, uint16_t);
static void		np_string(uint16_t, const char *);
static void		np_qid(struct qid *);
static void		do_send(void);

static void		np_version(uint16_t, uint32_t, const char *);
static void		np_attach(uint16_t, struct qid *);
static void		np_clunk(uint16_t);
static void		np_flush(uint16_t);
static void		np_walk(uint16_t, int, struct qid *);
static void		np_error(uint16_t, const char *);
static void		np_errno(uint16_t);

static int	np_read8(const char *, const char *, uint8_t *,
		    const uint8_t **, size_t *);
static int	np_read16(const char *, const char *, uint16_t *,
		    const uint8_t **, size_t *);
static int	np_read32(const char *, const char *, uint32_t *,
		    const uint8_t **, size_t *);

#define READSTRERR	-1
#define READSTRTRUNC	-2
static int	np_readstr(const char *, const char *, char *, size_t,
		    const uint8_t **, size_t *);

#define NPREAD8(f, dst, src, len)  np_read8(__func__, f, dst, src, len)
#define NPREAD16(f, dst, src, len) np_read16(__func__, f, dst, src, len)
#define NPREAD32(f, dst, src, len) np_read32(__func__, f, dst, src, len)

#define NPREADSTR(f, b, bl, src, len) np_readstr(__func__, f, b, bl, src, len)

static void	tversion(struct np_msg_header *, const uint8_t *, size_t);
static void	tattach(struct np_msg_header *, const uint8_t *, size_t);
static void	tclunk(struct np_msg_header *, const uint8_t *, size_t);
static void	tflush(struct np_msg_header *, const uint8_t *, size_t);
static void	twalk(struct np_msg_header *, const uint8_t *, size_t);
static void	handle_message(struct imsg *, size_t);

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

/* set qid fields from the sb field */
static void
qid_set_from_sb(struct qid *qid)
{
	qid->path = qid->sb.st_ino;

	/*
	 * Theoretically (and hopefully!) this should be a 64 bit
	 * number.  Unfortunately, 9P uses 32 bit timestamps.
	 */
	qid->vers = qid->sb.st_mtim.tv_sec;

	if (S_ISREG(qid->sb.st_mode))
		qid->type = QTFILE;
	else if (S_ISDIR(qid->sb.st_mode))
		qid->type = QTDIR;
	else if (S_ISLNK(qid->sb.st_mode))
		qid->type = QTSYMLINK;
}

/* update qid info */
static int
qid_update_stat(struct qid *qid)
{
	if (fstat(qid->fd, &qid->sb) == -1)
		return -1;

	qid_set_from_sb(qid);
	return 0;
}

/* create a new qid by copying info from an existing one */
static struct qid *
qid_from_copy(const struct qid *qid)
{
	struct qid *q;

	if ((q = calloc(1, sizeof(*q))) == NULL)
		return NULL;
	q->fd = -1;

	memcpy(q->fpath, qid->fpath, sizeof(q->fpath));

	memcpy(&q->sb, &qid->sb, sizeof(q->sb));
	memcpy(&q->path, &qid->path, sizeof(q->path));
	memcpy(&q->vers, &qid->vers, sizeof(q->vers));
	memcpy(&q->type, &qid->type, sizeof(q->type));

	return q;
}

/* creates a qid given a fd */
static struct qid *
qid_from_fd(int fd)
{
	struct qid	*qid;

	if ((qid = calloc(1, sizeof(*qid))) == NULL)
		return NULL;

	qid->fd = fd;
	qid_update_stat(qid);

	STAILQ_INSERT_HEAD(&qids, qid, entries);

	return qid;
}

static struct qid *
qid_from_path(const char *path)
{
	struct qid *qid;

	if ((qid = calloc(1, sizeof(*qid))) == NULL)
		return NULL;

	qid->fd = -1;

	if (stat(path, &qid->sb) == -1) {
		free(qid);
		return NULL;
	}

	qid_set_from_sb(qid);

	STAILQ_INSERT_HEAD(&qids, qid, entries);

	return qid;
}

static struct qid *
qid_incref(struct qid *qid)
{
	qid->refcount++;
	return qid;
}

static void
qid_decref(struct qid *qid)
{
	if (--qid->refcount > 0)
		return;

	STAILQ_REMOVE(&qids, qid, qid, entries);

	close(qid->fd);
	free(qid);

	if (STAILQ_EMPTY(&qids))
		attached = 0;
}

static struct fid *
new_fid(struct qid *qid, uint32_t fid)
{
	struct fid *f;

	if ((f = calloc(1, sizeof(*f))) == NULL)
		return NULL;

	f->qid = qid_incref(qid);
	f->fid = fid;

	STAILQ_INSERT_HEAD(&fids, f, entries);

	return f;
}

static struct fid *
fid_by_id(uint32_t fid)
{
	struct fid	*f;

	STAILQ_FOREACH(f, &fids, entries) {
		if (f->fid == fid)
			return f;
	}

	return NULL;
}

static void
free_fid(struct fid *f)
{
	qid_decref(f->qid);

	STAILQ_REMOVE(&fids, f, fid, entries);
	free(f);
}

static void
parse_message(const uint8_t *data, size_t len, struct np_msg_header *hdr,
    uint8_t **cnt)
{
	size_t olen = len;

	if (!NPREAD32("len", &hdr->len, &data, &len) ||
	    !NPREAD8("type", &hdr->type, &data, &len) ||
	    !NPREAD16("tag", &hdr->tag, &data, &len))
		goto err;

	if (olen != hdr->len)
		goto err;

	if (hdr->type < Tversion ||
	    hdr->type >= Tmax    ||
	    hdr->type == Terror  ||
	    (hdr->type & 0x1) != 0) /* cannot recv a R* */
		goto err;

	hdr->tag = le32toh(hdr->tag);

	*cnt = (uint8_t *)data;
	return;

err:
	/* TODO: send a proper message to terminate the connection. */
	fatalx("got invalid message");
}

static void
np_write16(uint16_t x)
{
	x = htole16(x);
	evbuffer_add(evb, &x, sizeof(x));
}

static void
np_header(uint32_t len, uint8_t type, uint16_t tag)
{
	len += HEADERSIZE;

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

	evbuffer_add(evb, &qid->type, sizeof(qid->type));
	evbuffer_add(evb, &vers, sizeof(vers));
	evbuffer_add(evb, &path, sizeof(path));
}

static void
do_send(void)
{
	size_t	 len;
	void	*data;

	len = EVBUFFER_LENGTH(evb);
	data = EVBUFFER_DATA(evb);

#if DEBUG_PACKETS
	hexdump("outgoing packet", data, len);
#endif
	client_send_listener(IMSG_BUF, data, len);
	evbuffer_drain(evb, len);
}

static void
np_version(uint16_t tag, uint32_t msize, const char *version)
{
	uint16_t l;

	l = strlen(version);

	msize = htole32(msize);

	np_header(sizeof(msize) + sizeof(l) + l, Rversion, tag);
	evbuffer_add(evb, &msize, sizeof(msize));
	np_string(l, version);
	do_send();
}

static void
np_attach(uint16_t tag, struct qid *qid)
{
	np_header(QIDSIZE, Rattach, tag);
	np_qid(qid);
	do_send();
}

static void
np_clunk(uint16_t tag)
{
	np_header(0, Rclunk, tag);
	do_send();
}

static void
np_flush(uint16_t tag)
{
	np_header(0, Rflush, tag);
	do_send();
}

static void
np_walk(uint16_t tag, int nwqid, struct qid *wqid)
{
	int i;

	/* two bytes for the counter */
	np_header(2 + QIDSIZE * nwqid, Rwalk, tag);
	np_write16(nwqid);
	for (i = 0; i < nwqid; ++i)
		np_qid(wqid + i);

	do_send();
}

static void
np_error(uint16_t tag, const char *errstr)
{
	uint16_t l;

	l = strlen(errstr);

	np_header(sizeof(l) + l, Rerror, tag);
	np_string(l, errstr);
	do_send();
}

static void
np_errno(uint16_t tag)
{
	int saved_errno;
	char buf[64];

	saved_errno = errno;

	strerror_r(errno, buf, sizeof(buf));
	np_error(tag, buf);

	errno = saved_errno;
}

static int
np_read8(const char *t, const char *f, uint8_t *dst, const uint8_t **src,
    size_t *len)
{
	if (*len < sizeof(*dst)) {
		log_warnx("%s: wanted %zu bytes for the %s field but only "
		    "%zu are available.", t, sizeof(*dst), f, *len);
		return -1;
	}

	memcpy(dst, *src, sizeof(*dst));
	*src += sizeof(*dst);
	*len -= sizeof(*dst);

	return 1;
}

static int
np_read16(const char *t, const char *f, uint16_t *dst, const uint8_t **src,
    size_t *len)
{
	if (*len < sizeof(*dst)) {
		log_warnx("%s: wanted %zu bytes for the %s field but only "
		    "%zu are available.", t, sizeof(*dst), f, *len);
		return -1;
	}

	memcpy(dst, *src, sizeof(*dst));
	*src += sizeof(*dst);
	*len -= sizeof(*dst);
	*dst = le16toh(*dst);

	return 1;
}

static int
np_read32(const char *t, const char *f, uint32_t *dst, const uint8_t **src,
    size_t *len)
{
	if (*len < sizeof(*dst)) {
		log_warnx("%s: wanted %zu bytes for the %s field but only "
		    "%zu are available.", t, sizeof(*dst), f, *len);
		return -1;
	}

	memcpy(dst, *src, sizeof(*dst));
	*src += sizeof(*dst);
	*len -= sizeof(*dst);
	*dst = le32toh(*dst);

	return 1;
}

static int
np_readstr(const char *t, const char *f, char *res, size_t reslen,
    const uint8_t **src, size_t *len)
{
	uint16_t	sl;
	char		buf[32];

	strlcpy(buf, f, sizeof(buf));
	strlcat(buf, "-len", sizeof(buf));

	if (!np_read16(t, buf, &sl, src, len))
		return READSTRERR;

	if (*len < sl) {
		log_warnx("%s: wanted %d bytes for the %s field but only "
		    "%zu are available.", t, sl, f, *len);
		return READSTRERR;
	}

	if (*len > reslen-1)
		return READSTRTRUNC;

	memcpy(res, *src, sl);
	res[sl] = '\0';
	*src += sl;
	*len -= sl;

	return 0;
}

static void
tversion(struct np_msg_header *hdr, const uint8_t *data, size_t len)
{
	char *dot, version[32];

	if (handshaked)
		goto err;

	/* msize[4] version[s] */
	if (!NPREAD32("msize", &msize, &data, &len))
		goto err;

	switch (NPREADSTR("version", version, sizeof(version), &data, &len)) {
	case READSTRERR:
		goto err;
	case READSTRTRUNC:
		log_warnx("9P version string too long, truncated");
		goto mismatch;
	}

	if ((dot = strchr(version, '.')) != NULL)
		*dot = '\0';

	if (strcmp(version, VERSION9P) != 0 ||
	    msize == 0)
		goto mismatch;

	/* version matched */
	handshaked = 1;
	msize = MIN(msize, MSIZE9P);
	client_send_listener(IMSG_MSIZE, &msize, sizeof(msize));
	np_version(hdr->tag, msize, VERSION9P);
	return;

mismatch:
	log_warnx("unknown 9P version string: \"%s\", want "VERSION9P,
	    version);
	np_version(hdr->tag, MSIZE9P, "unknown");
	return;

err:
	client_send_listener(IMSG_CLOSE, NULL, 0);
	client_shutdown();
}

static void
tattach(struct np_msg_header *hdr, const uint8_t *data, size_t len)
{
	struct qid	*qid;
	struct fid	*f;
	uint32_t	 fid, afid;
	char		 aname[PATH_MAX];

	if (attached) {
		np_error(hdr->tag, "already attached");
		return;
	}

	/* fid[4] afid[4] uname[s] aname[s] */

	if (!NPREAD32("fid", &fid, &data, &len) ||
	    !NPREAD32("afid", &afid, &data, &len))
		goto err;

	/* read the uname but don't actually use it */
	switch (NPREADSTR("uname", aname, sizeof(aname), &data, &len)) {
	case READSTRERR:
		goto err;
	case READSTRTRUNC:
		np_error(hdr->tag, "name too long");
		return;
	}

	switch (NPREADSTR("aname", aname, sizeof(aname), &data, &len)) {
	case READSTRERR:
		goto err;
	case READSTRTRUNC:
		np_error(hdr->tag, "name too long");
		return;
	}

	if ((qid = qid_from_path(aname)) == NULL) {
		np_errno(hdr->tag);
		log_debug("failed to attach %s: %s", aname, strerror(errno));
		return;
	}
	log_debug("attached %s", aname);

	if ((f = new_fid(qid, fid)) == NULL) {
		qid_decref(qid);
		np_error(hdr->tag, "no memory");
		return;
	}

	np_attach(hdr->tag, qid);
	attached = 1;
	return;

err:
	client_send_listener(IMSG_CLOSE, NULL, 0);
	client_shutdown();
}

static void
tclunk(struct np_msg_header *hdr, const uint8_t *data, size_t len)
{
	struct fid	*f;
	uint32_t	 fid;

	/* fid[4] */
	if (!NPREAD32("fid", &fid, &data, &len)) {
		client_send_listener(IMSG_CLOSE, NULL, 0);
		client_shutdown();
		return;
	}

	if ((f = fid_by_id(fid)) == NULL) {
		np_error(hdr->tag, "invalid fid");
		return;
	}

	free_fid(f);
	np_clunk(hdr->tag);
}

static void
tflush(struct np_msg_header *hdr, const uint8_t *data, size_t len)
{
	uint16_t	oldtag;

	/*
	 * We're doing only synchronous I/O.  Tflush is implemented
	 * only because it's illegal to reply with a Rerror.
	 */

	/* oldtag[2] */
	if (len != sizeof(oldtag)) {
		log_warnx("Tclunk with the wrong size: got %zu want %zu",
		    len, sizeof(oldtag));
		client_send_listener(IMSG_CLOSE, NULL, 0);
		client_shutdown();
		return;
	}

	np_flush(hdr->tag);
}

static void
twalk(struct np_msg_header *hdr, const uint8_t *data, size_t len)
{
	struct qid	*qid, wqid[MAXWELEM] = {0};
	struct fid	*f, *nf;
	uint32_t	 fid, newfid;
	uint16_t	 nwname;
	int		 nwqid = 0;
	char		 wnam[PATH_MAX+1], path[PATH_MAX+1];

	if (!NPREAD32("fid", &fid, &data, &len)       ||
	    !NPREAD32("newfid", &newfid, &data, &len) ||
	    !NPREAD16("nwname", &nwname, &data, &len))
		goto err;

	if (nwname > MAXWELEM) {
		log_warnx("Twalk: more than %d path elements: %d",
		    MAXWELEM, nwname);
		goto err;
	}

	if ((f = fid_by_id(fid)) == NULL) {
		np_error(hdr->tag, "invalid fid");
		return;
	}

	if (fid == newfid)
		nf = f;
	else if ((nf = fid_by_id(newfid)) != NULL) {
		np_error(hdr->tag, "newfid already in use");
		return;
	} else
		nf = NULL;

	/* special case: fid duplication */
	if (nwname == 0) {
		/*
		 * TODO: should we forbid fids duplication when fid ==
		 * newfid?
		 */

		if (nf == NULL) {
			if ((nf = new_fid(f->qid, newfid)) == NULL)
				fatal("new_fid duplication");
		}

		np_walk(hdr->tag, 1, f->qid);
		return;
	}

	if (f->iomode != 0) {
		np_error(hdr->tag, "fid already opened for I/O");
		return;
	}

	if (f->qid->type != QTDIR) {
		np_error(hdr->tag, "fid doesn't represent a directory");
		return;
	}

	strlcpy(path, f->qid->fpath, sizeof(path));

	for (nwqid = 0; nwqid < nwname; nwqid++) {
		switch (NPREADSTR("wname", wnam, sizeof(wnam), &data, &len)) {
		case READSTRERR:
			goto err;
		case READSTRTRUNC:
			np_error(hdr->tag, "wname too long");
			return;
		}

		strlcat(path, "/", sizeof(path));
		strlcat(path, wnam, sizeof(path));

		if (stat(path, &wqid[nwqid].sb) == -1) {
			if (nwqid == 0)
				np_errno(hdr->tag);
			else
				np_walk(hdr->tag, nwqid, wqid);
			return;
		}

		qid_set_from_sb(&wqid[nwqid]);
	}

        if ((qid = qid_from_path(path)) == NULL)
		fatal("qid_from_fd");

	if (nf == NULL) {
		if ((nf = new_fid(qid, newfid)) == NULL)
			fatal("new_fid");
	} else {
		/* swap qid */
		qid_decref(nf->qid);
		nf->qid = qid_incref(qid);
	}

	np_walk(hdr->tag, nwqid, wqid);

	return;

err:
	client_send_listener(IMSG_CLOSE, NULL, 0);
	client_shutdown();
}

static void
handle_message(struct imsg *imsg, size_t len)
{
	struct msg {
		uint8_t	 type;
		void	(*fn)(struct np_msg_header *, const uint8_t *, size_t);
	} msgs[] = {
		{Tversion,	tversion},
		{Tattach,	tattach},
		{Tclunk,	tclunk},
		{Tflush,	tflush},
		{Twalk,		twalk},
	};
	struct np_msg_header	 hdr;
	size_t			 i;
	uint8_t			*data;

#if DEBUG_PACKETS
	hexdump("incoming packet", imsg->data, len);
#endif

	parse_message(imsg->data, len, &hdr, &data);
	len -= HEADERSIZE;

	log_debug("got request: len=%d type=%d[%s] tag=%d",
	    hdr.len, hdr.type, pp_msg_type(hdr.type), hdr.tag);

	if (!handshaked && hdr.type != Tversion) {
		client_send_listener(IMSG_CLOSE, NULL, 0);
		client_shutdown();
		return;
	}

	for (i = 0; i < sizeof(msgs)/sizeof(msgs[0]); ++i) {
		if (msgs[i].type != hdr.type)
			continue;

		msgs[i].fn(&hdr, data, len);
		return;
	}

	np_error(hdr.tag, "Not supported.");
}
