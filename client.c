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

#include <dirent.h>
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

/*
 * XXX: atm is difficult to accept messages bigger than MAX_IMSGSIZE
 * minus IMSG_HEADER_SIZE, we need something to split messages into
 * chunks and receive them one by the other.
 *
 * CLIENT_MSIZE is thus the maximum message size we can handle now.
 */
#define CLIENT_MSIZE (MAX_IMSGSIZE - IMSG_HEADER_SIZE)

#define DEBUG_PACKETS 0

/* straight outta /src/usr.bin/ssh/scp.c */
#define TYPE_OVERFLOW(type, val) \
	((sizeof(type) == 4 && (val) > INT32_MAX) || \
	 (sizeof(type) == 8 && (val) > INT64_MAX) || \
	 (sizeof(type) != 4 && sizeof(type) != 8))

STAILQ_HEAD(dirhead, dir) dirs;
struct dir {
	int			 refcount;
	int			 fd;
	STAILQ_ENTRY(dir)	 entries;
};

STAILQ_HEAD(fidhead, fid) fids;
struct fid {
	uint32_t		 fid;

	char			 fpath[PATH_MAX];

	/*
	 * the flags passed to open(2).  O_CLOEXEC means ORCLOSE, that
	 * is to unlink the file upon Tclunk.
	 */
	int			 iomode;

	/*
	 * if fd is not -1 this fid was opened, fd represents its
	 * file descriptor and iomode the flags passed to open(2).
	 */
	int			 fd;
	DIR			*d;
	struct evbuffer		*evb;

	/*
	 * expected offset for Tread against a directory.
	 */
	uint64_t		 offset;

	struct qid		 qid;
	struct dir		*dir;
	STAILQ_ENTRY(fid)	 entries;
};

static struct imsgev	*iev_listener;
static struct evbuffer	*evb;
static uint32_t		 peerid;

static int		 handshaked;
uint32_t		 msize;

static __dead void	client_shutdown(void);
static void		client_sig_handler(int, short, void *);
static void		client_dispatch_listener(int, short, void *);
static void		client_privdrop(const char *, const char *);

static int		client_send_listener(int, const void *, uint16_t);

static void		 qid_update_from_sb(struct qid *, struct stat *);

static struct dir	*new_dir(int);
static struct dir	*dir_incref(struct dir *);
static void		 dir_decref(struct dir *);

static struct fid	*new_fid(struct dir *, uint32_t, const char *, struct qid *);
static struct fid	*fid_by_id(uint32_t);
static void		 free_fid(struct fid *);

static void		parse_message(const uint8_t *, size_t,
			    struct np_msg_header *, uint8_t **);

static void		np_write16(struct evbuffer *, uint16_t);
static void		np_write32(struct evbuffer *, uint32_t);
static void		np_write64(struct evbuffer *, uint64_t);
static void		np_header(uint32_t, uint8_t, uint16_t);
static void		np_string(struct evbuffer *, uint16_t, const char *);
static void		np_qid(struct evbuffer *, struct qid *);
static void		do_send(void);

static void		np_version(uint16_t, uint32_t, const char *);
static void		np_attach(uint16_t, struct qid *);
static void		np_clunk(uint16_t);
static void		np_flush(uint16_t);
static void		np_walk(uint16_t, int, struct qid *);
static void		np_open(uint16_t, struct qid *, uint32_t);
static void		np_create(uint16_t, struct qid *, uint32_t);
static void		np_read(uint16_t, uint32_t, void *);
static void		np_write(uint16_t, uint32_t);
static void		np_stat(uint16_t, uint32_t, void *);
static void		np_remove(uint16_t);
static void		np_error(uint16_t, const char *);
static void		np_errno(uint16_t);

static int	np_read8(const char *, const char *, uint8_t *,
		    const uint8_t **, size_t *);
static int	np_read16(const char *, const char *, uint16_t *,
		    const uint8_t **, size_t *);
static int	np_read32(const char *, const char *, uint32_t *,
		    const uint8_t **, size_t *);
static int	np_read64(const char *, const char *, uint64_t *,
		    const uint8_t **, size_t *);

#define READSTRERR	-1
#define READSTRTRUNC	-2
static int	np_readstr(const char *, const char *, char *, size_t,
		    const uint8_t **, size_t *);

#define NPREAD8(f, dst, src, len)  np_read8(__func__, f, dst, src, len)
#define NPREAD16(f, dst, src, len) np_read16(__func__, f, dst, src, len)
#define NPREAD32(f, dst, src, len) np_read32(__func__, f, dst, src, len)
#define NPREAD64(f, dst, src, len) np_read64(__func__, f, dst, src, len)

#define NPREADSTR(f, b, bl, src, len) np_readstr(__func__, f, b, bl, src, len)

static void	tversion(struct np_msg_header *, const uint8_t *, size_t);
static void	tattach(struct np_msg_header *, const uint8_t *, size_t);
static void	tclunk(struct np_msg_header *, const uint8_t *, size_t);
static void	tflush(struct np_msg_header *, const uint8_t *, size_t);
static void	twalk(struct np_msg_header *, const uint8_t *, size_t);
static void	topen(struct np_msg_header *, const uint8_t *, size_t);
static void	tcreate(struct np_msg_header *, const uint8_t *, size_t);
static void	tread(struct np_msg_header *, const uint8_t *, size_t);
static void	twrite(struct np_msg_header *, const uint8_t *, size_t);
static void	tstat(struct np_msg_header *, const uint8_t *, size_t);
static void	tremove(struct np_msg_header *, const uint8_t *, size_t);
static void	handle_message(struct imsg *, size_t);

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

	event_dispatch();
	client_shutdown();
}

static __dead void
client_shutdown(void)
{
	if (evb != NULL)
		evbuffer_free(evb);

	msgbuf_clear(&iev_listener->ibuf.w);
	close(iev_listener->ibuf.fd);

        free(iev_listener);

	log_debug("client exiting");
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
		log_debug("pipe closed, shutting down...");
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

/* set qid fields from sb */
static void
qid_update_from_sb(struct qid *qid, struct stat *sb)
{
	qid->path = sb->st_ino;

	/*
	 * Theoretically (and hopefully!) this should be a 64 bit
	 * number.  Unfortunately, 9P uses 32 bit timestamps.
	 */
	qid->vers = sb->st_mtim.tv_sec;

	if (S_ISREG(sb->st_mode))
		qid->type = QTFILE;
	else if (S_ISDIR(sb->st_mode))
		qid->type = QTDIR;
	else if (S_ISLNK(sb->st_mode))
		qid->type = QTSYMLINK;
}

/* creates a qid given a fd */
static struct dir *
new_dir(int fd)
{
	struct dir	*dir;

	if ((dir = calloc(1, sizeof(*dir))) == NULL)
		return NULL;

	dir->fd = fd;
	STAILQ_INSERT_HEAD(&dirs, dir, entries);
	return dir;
}

static struct dir *
dir_incref(struct dir *dir)
{
	dir->refcount++;
	return dir;
}

static void
dir_decref(struct dir *dir)
{
	if (--dir->refcount > 0)
		return;

	STAILQ_REMOVE(&dirs, dir, dir, entries);

	close(dir->fd);
	free(dir);
}

static struct fid *
new_fid(struct dir *dir, uint32_t fid, const char *path, struct qid *qid)
{
	struct fid	*f;
	struct qid	 q;
	struct stat	sb;

	if (qid == NULL) {
		if (fstatat(dir->fd, path, &sb, 0)) {
			log_warn("fstatat(%s)", path);
			return NULL;
		}
		qid_update_from_sb(&q, &sb);
		qid = &q;
	}

	if ((f = calloc(1, sizeof(*f))) == NULL)
		return NULL;

	f->dir = dir_incref(dir);
	f->fid = fid;
	f->fd = -1;

	strlcpy(f->fpath, path, sizeof(f->fpath));

	memcpy(&f->qid, qid, sizeof(f->qid));

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
	int r;

	if (f->fd != -1) {
		if (f->d != NULL)
			r = closedir(f->d);
		else
			r = close(f->fd);

		if (r == -1)
			fatal("can't close fid %d", f->fid);

		if (f->evb != NULL)
			evbuffer_free(f->evb);

		/* try to honour ORCLOSE if requested */
		if (f->iomode & O_CLOEXEC)
			unlinkat(f->dir->fd, f->fpath, 0);
	}

	dir_decref(f->dir);

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
np_write16(struct evbuffer *e, uint16_t x)
{
	x = htole16(x);
	evbuffer_add(e, &x, sizeof(x));
}

static void
np_write32(struct evbuffer *e, uint32_t x)
{
	x = htole32(x);
	evbuffer_add(e, &x, sizeof(x));
}

static void
np_write64(struct evbuffer *e, uint64_t x)
{
	x = htole64(x);
	evbuffer_add(e, &x, sizeof(x));
}

static void
np_writebuf(struct evbuffer *e, size_t len, void *data)
{
	evbuffer_add(e, data, len);
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
np_string(struct evbuffer *e, uint16_t len, const char *str)
{
	uint16_t l = len;

	len = htole16(len);
	evbuffer_add(e, &len, sizeof(len));
	evbuffer_add(e, str, l);
}

static void
np_qid(struct evbuffer *e, struct qid *qid)
{
	uint64_t	path;
	uint32_t	vers;

	path = htole64(qid->path);
	vers = htole32(qid->vers);

	evbuffer_add(e, &qid->type, sizeof(qid->type));
	evbuffer_add(e, &vers, sizeof(vers));
	evbuffer_add(e, &path, sizeof(path));
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
	np_string(evb, l, version);
	do_send();
}

static void
np_attach(uint16_t tag, struct qid *qid)
{
	np_header(QIDSIZE, Rattach, tag);
	np_qid(evb, qid);
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
	np_write16(evb, nwqid);
	for (i = 0; i < nwqid; ++i)
		np_qid(evb, wqid + i);

	do_send();
}

static void
np_open(uint16_t tag, struct qid *qid, uint32_t iounit)
{
	np_header(QIDSIZE + sizeof(iounit), Ropen, tag);
	np_qid(evb, qid);
	np_write32(evb, iounit);
	do_send();
}

static void
np_create(uint16_t tag, struct qid *qid, uint32_t iounit)
{
	np_header(QIDSIZE + sizeof(iounit), Rcreate, tag);
	np_qid(evb, qid);
	np_write32(evb, iounit);
	do_send();
}

static void
np_read(uint16_t tag, uint32_t count, void *data)
{
	np_header(sizeof(count) + count, Rread, tag);
	np_write32(evb, count);
	np_writebuf(evb, count, data);
	do_send();
}

static void
np_write(uint16_t tag, uint32_t count)
{
	np_header(sizeof(count), Rwrite, tag);
	np_write32(evb, count);
	do_send();
}

static void
np_stat(uint16_t tag, uint32_t count, void *data)
{
	np_header(count, Rstat, tag);
	np_writebuf(evb, count, data);
	do_send();
}

static void
np_remove(uint16_t tag)
{
	np_header(0, Rremove, tag);
	do_send();
}

static void
np_error(uint16_t tag, const char *errstr)
{
	uint16_t l;

	l = strlen(errstr);

	np_header(sizeof(l) + l, Rerror, tag);
	np_string(evb, l, errstr);
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
np_read64(const char *t, const char *f, uint64_t *dst, const uint8_t **src,
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
	*dst = le64toh(*dst);

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
	msize = MIN(msize, CLIENT_MSIZE);
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
	struct dir	*dir;
	struct fid	*f;
	uint32_t	 fid, afid;
	int		 fd;
	char		 aname[PATH_MAX];

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

	if (fid_by_id(fid) != NULL || afid != NOFID) {
		np_error(hdr->tag, "invalid fid or afid");
		return;
	}

	if ((fd = open(aname, O_RDONLY|O_DIRECTORY)) == -1)
		goto fail;

	if ((dir = new_dir(fd)) == NULL)
		goto fail;

	log_debug("attached %s to %d", aname, fid);

	if ((f = new_fid(dir, fid, aname, NULL)) == NULL) {
		dir_decref(dir);
		goto fail;
	}

	np_attach(hdr->tag, &f->qid);
	return;

fail:
	np_errno(hdr->tag);
	log_warn("failed to attach %s", aname);
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
		log_warnx("Tflush with the wrong size: got %zu want %zu",
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
	struct stat	 sb;
	struct dir	*dir;
	struct qid	 wqid[MAXWELEM] = {0};
	struct fid	*f, *nf;
	uint32_t	 fid, newfid;
	uint16_t	 nwname;
	int		 fd, oldfd, no, nwqid = 0;
	char		 wnam[PATH_MAX];

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

	if (f->fd != -1) {
		np_error(hdr->tag, "fid already opened for I/O");
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
		if (nf == NULL && 
		    (nf = new_fid(f->dir, newfid, f->fpath, &f->qid)) == NULL)
			fatal("new_fid duplication");

		np_walk(hdr->tag, 0, NULL);
		return;
	}

	if (!(f->qid.type & QTDIR)) {
		np_error(hdr->tag, "fid doesn't represent a directory");
		return;
	}

	oldfd = f->dir->fd;

	for (nwqid = 0; nwqid < nwname; nwqid++) {
		switch (NPREADSTR("wname", wnam, sizeof(wnam), &data, &len)) {
		case READSTRERR:
			goto err;
		case READSTRTRUNC:
			np_error(hdr->tag, "wname too long");
			return;
		}

		if (*wnam == '\0' ||
		    strchr(wnam, '/') != NULL ||
		    !strcmp(wnam, ".")) {
			errno = EINVAL;
			goto cantopen;
		}

		if ((fd = openat(oldfd, wnam, O_RDONLY|O_DIRECTORY)) == -1 &&
		    errno != ENOTDIR)
			goto cantopen;

		if ((fd == -1 && fstatat(oldfd, wnam, &sb, 0) == -1) ||
		    (fd != -1 && fstat(fd, &sb) == -1))
			goto cantopen;

		qid_update_from_sb(&wqid[nwqid], &sb);

		/* reached a file but we still have other components */
		if (fd == -1 && nwqid+1 < nwname)
			goto cantopen;

		/* reached the end and found a file */
		if (fd == -1 && nwqid+1 == nwname)
			continue;

		if (oldfd != f->dir->fd)
			close(oldfd);
		oldfd = fd;
	}

	/* 
	 * If fd is -1 we've reached a file, otherwise we've just
	 * reached another directory.  We must pay attention to what
	 * file descriptor we use to create the dir, because if we've
	 * reached a file and oldfd is f->dir->fd then we *must* share
	 * the same dir (it was a walk of one path from a directory to a
	 * file, otherwise fun is bound to happen as soon as the client
     	 * closes the fid for the directory but keeps the one for the
	 * file.
	 */
	if (fd == -1 && oldfd == f->dir->fd)
		dir = f->dir;
	else if (fd == -1)
		dir = new_dir(oldfd);
	else
		dir = new_dir(fd);

	if (dir == NULL)
		fatal("new_dir");

	if (nf == NULL) {
		if ((nf = new_fid(dir, newfid, wnam, &wqid[nwqid-1])) == NULL)
			fatal("new fid");
	} else {
		/* update the dir */
		dir_decref(nf->dir);
		nf->dir = dir_incref(dir);
	}

	np_walk(hdr->tag, nwqid, wqid);
	return;

cantopen:
	if (oldfd != f->dir->fd)
		close(oldfd);
	no = errno;
	if (nwqid == 0)
		np_error(hdr->tag, strerror(no));
	else
		np_walk(hdr->tag, nwqid, wqid);
	return;

err:
	client_send_listener(IMSG_CLOSE, NULL, 0);
	client_shutdown();
}

static inline int
npmode_to_unix(uint8_t mode, int *flags)
{
	switch (mode & 0x0F) {
	case KOREAD:
		*flags = O_RDONLY;
		break;
	case KOWRITE:
		*flags = O_WRONLY;
		break;
	case KORDWR:
		*flags = O_RDWR;
		break;
	case KOEXEC:
		log_warnx("tried to open something with KOEXEC");
		/* fallthrough */
	default:
		return -1;
	}

	if (mode & KOTRUNC)
		*flags |= O_TRUNC;
	if (mode & KORCLOSE)
		*flags |= O_CLOEXEC;

	return 0;
}

static void
topen(struct np_msg_header *hdr, const uint8_t *data, size_t len)
{
	struct stat	 sb;
	struct qid	 qid;
	struct fid	*f;
	uint32_t	 fid;
	uint8_t		 mode;
	const char	*path;

	/* fid[4] mode[1] */
	if (!NPREAD32("fid", &fid, &data, &len) ||
	    !NPREAD8("mode", &mode, &data, &len)) {
		client_send_listener(IMSG_CLOSE, NULL, 0);
		client_shutdown();
		return;
	}

	if ((f = fid_by_id(fid)) == NULL || f->fd != -1) {
		np_error(hdr->tag, "invalid fid");
		return;
	}

	if (npmode_to_unix(mode, &f->iomode) == -1) {
		np_error(hdr->tag, "invalid mode");
		return;
	}

	path = f->fpath;
	if (f->qid.type & QTDIR)
		path = ".";

	if ((f->fd = openat(f->dir->fd, path, f->iomode)) == -1) {
		np_error(hdr->tag, strerror(errno));
		return;
	}

	if (fstat(f->fd, &sb) == -1)
		fatal("fstat");

	if (S_ISDIR(sb.st_mode)) {
		if ((f->d = fdopendir(f->fd)) == NULL) {
			np_errno(hdr->tag);
			close(f->fd);
			f->fd = -1;
			return;
		}

		if ((f->evb = evbuffer_new()) == NULL) {
			np_errno(hdr->tag);
			closedir(f->d);
			f->d = NULL;
			f->fd = -1;
		}
	}

	f->offset = 0;

	qid_update_from_sb(&qid, &sb);
	np_open(hdr->tag, &qid, sb.st_blksize);
}

static void
tcreate(struct np_msg_header *hdr, const uint8_t *data, size_t len)
{
	struct stat	 sb;
	struct qid	 qid;
	struct fid	*f;
	uint32_t	 fid, perm;
	uint8_t		 mode;
	char		 name[PATH_MAX];

	/* fid[4] name[s] perm[4] mode[1] */
	if (!NPREAD32("fid", &fid, &data, &len))
		goto err;
	switch (NPREADSTR("name", name, sizeof(name), &data, &len)) {
	case READSTRERR:
		goto err;
	case READSTRTRUNC:
		np_error(hdr->tag, "name too long");
		return;
	}
	if (!NPREAD32("perm", &perm, &data, &len) ||
	    !NPREAD8("mode", &mode, &data, &len))
		goto err;

	if (!strcmp(name, ".") || !strcmp(name, "..") ||
	    strchr(name, '/') != NULL) {
		np_error(hdr->tag, "invalid name");
		return;
	}

	if ((f = fid_by_id(fid)) == NULL || f->fd != -1) {
		np_error(hdr->tag, "invalid fid");
		return;
	}

	if (!(f->qid.type & QTDIR)) {
		np_error(hdr->tag, "fid doesn't identify a directory");
		return;
	}

	if (npmode_to_unix(mode, &f->iomode) == -1) {
		np_error(hdr->tag, "invalid mode");
		return;
	}

	if (f->iomode & O_RDONLY) {
		np_error(hdr->tag, "can't create a read-only file");
		return;
	}

	/* TODO: parse the mode */

	if (perm & 0x80000000) {
		/* create a directory */
		f->fd = mkdirat(f->dir->fd, name, 0755);
	} else {
		/* create a file */
		f->fd = openat(f->dir->fd, name, f->iomode | O_CREAT | O_TRUNC,
		    0644);
	}

	if (f->fd == -1) {
		np_errno(hdr->tag);
		return;
	}

	if (fstat(f->fd, &sb) == -1)
		fatal("fstat");

	if (S_ISDIR(sb.st_mode)) {
		if ((f->d = fdopendir(f->fd)) == NULL) {
			np_errno(hdr->tag);
			close(f->fd);
			f->fd = -1;
			return;
		}

		if ((f->evb = evbuffer_new()) == NULL) {
			np_errno(hdr->tag);
			closedir(f->d);
			f->d = NULL;
			f->fd = -1;
		}
	}

	f->offset = 0;

	qid_update_from_sb(&qid, &sb);
	np_create(hdr->tag, &qid, sb.st_blksize);

	return;

err:
	client_send_listener(IMSG_CLOSE, NULL, 0);
	client_shutdown();
}

static inline void
serialize_stat(const char *fname, struct stat *sb, struct evbuffer *evb)
{
	struct qid	 qid;
	const char	*uid, *gid, *muid;
	size_t		 tot;
	uint16_t	 namlen, uidlen, gidlen, ulen;

	qid_update_from_sb(&qid, sb);

	/* TODO: fill these fields */
	uid = "";
	gid = "";
	muid = "";

	namlen = strlen(fname);
	uidlen = strlen(uid);
	gidlen = strlen(gid);
	ulen = strlen(muid);

	tot = NPSTATSIZ(namlen, uidlen, gidlen, ulen);
	if (tot > UINT32_MAX) {
		log_warnx("stat info for dir entry %s would overflow",
		    fname);
		return;
	}

	np_write16(evb, tot);			/*	size[2]		*/
	np_write16(evb, sb->st_rdev);		/*	type[2]		*/
	np_write32(evb, sb->st_dev);		/*	dev[4]		*/
	np_qid(evb, &qid);			/*	qid[13]		*/

	/* XXX: translate? */
	np_write32(evb, sb->st_mode);		/*	mode[4]		*/

	np_write32(evb, sb->st_atim.tv_sec);	/*	atime[4]	*/
	np_write32(evb, sb->st_mtim.tv_sec);	/*	mtime[4]	*/
	np_write64(evb, sb->st_size);		/*	length[8]	*/
	np_string(evb, namlen, fname);		/*	name[s]		*/
	np_string(evb, uidlen, uid);		/*	uid[s]		*/
	np_string(evb, gidlen, gid);		/*	gid[s]		*/
	np_string(evb, ulen, muid);		/*	muid[s]		*/
}

static void
tread(struct np_msg_header *hdr, const uint8_t *data, size_t len)
{
	struct fid	*f;
	ssize_t		 r;
	uint64_t	 off;
	uint32_t	 fid, count;
	char		 buf[2048];

	/* fid[4] offset[8] count[4] */
	if (!NPREAD32("fid", &fid, &data, &len) ||
	    !NPREAD64("offset", &off, &data, &len) ||
	    !NPREAD32("count", &count, &data, &len)) {
		client_send_listener(IMSG_CLOSE, NULL, 0);
		client_shutdown();
		return;
	}

	if ((f = fid_by_id(fid)) == NULL || f->fd == -1) {
		np_error(hdr->tag, "invalid fid");
		return;
	}

	if (TYPE_OVERFLOW(off_t, off)) {
		log_warnx("unexpected off_t size");
		np_error(hdr->tag, "invalid offset");
		return;
	}

	if (f->d == NULL) {
		/* read a file */
		r = pread(f->fd, buf, sizeof(buf), (off_t)off);
		if (r == -1)
			np_errno(hdr->tag);
		else
			np_read(hdr->tag, r, buf);
	} else {
		if (off == 0 && f->offset != 0) {
			rewinddir(f->d);
			f->offset = 0;
			evbuffer_drain(f->evb, EVBUFFER_LENGTH(f->evb));
		}

		if (off != f->offset) {
			np_error(hdr->tag, "can't seek in directories");
			return;
		}

		while (EVBUFFER_LENGTH(f->evb) < count) {
			struct dirent *d;
			struct stat sb;

			if ((d = readdir(f->d)) == NULL)
				break;
			if (fstatat(f->fd, d->d_name, &sb, 0) == -1) {
				warn("fstatat");
				continue;
			}
			serialize_stat(d->d_name, &sb, f->evb);
		}

		count = MIN(count, EVBUFFER_LENGTH(f->evb));
		np_read(hdr->tag, count, EVBUFFER_DATA(f->evb));
		evbuffer_drain(f->evb, count);

		f->offset += count;
	}
}

static void
twrite(struct np_msg_header *hdr, const uint8_t *data, size_t len)
{
	struct fid	*f;
	ssize_t		 r;
	uint64_t	 off;
	uint32_t	 fid, count;

	/* fid[4] offset[8] count[4] data[count] */
	if (!NPREAD32("fid", &fid, &data, &len) ||
	    !NPREAD64("off", &off, &data, &len) ||
	    !NPREAD32("count", &count, &data, &len) ||
	    len != count) {
		client_send_listener(IMSG_CLOSE, NULL, 0);
		client_shutdown();
		return;
	}

	if ((f = fid_by_id(fid)) == NULL || f->fd == -1) {
		np_error(hdr->tag, "invalid fid");
		return;
	}

	if (!(f->iomode & O_WRONLY) &&
	    !(f->iomode & O_RDWR)) {
		np_error(hdr->tag, "fid not opened for writing");
		return;
	}

	if (TYPE_OVERFLOW(off_t, off)) {
		log_warnx("unexpected off_t size");
		np_error(hdr->tag, "invalid offset");
		return;
	}

	if ((r = pwrite(f->fd, data, len, off)) == -1)
		np_errno(hdr->tag);
	else
		np_write(hdr->tag, r);
}

static void
tstat(struct np_msg_header *hdr, const uint8_t *data, size_t len)
{
	struct evbuffer	*evb;
	struct stat	 sb;
	struct fid	*f;
	int		 r;
	uint32_t	 fid;

	/* fid[4] */
	if (!NPREAD32("fid", &fid, &data, &len)) {
		client_send_listener(IMSG_CLOSE, NULL, 0);
		client_shutdown();
		return;
	}

	/*
	 * plan9' stat(9P) is not clear on whether the stat is allowed
	 * on opened fids or not.
	 */
	if ((f = fid_by_id(fid)) == NULL) {
		np_error(hdr->tag, "invalid fid");
		return;
	}

	if ((evb = evbuffer_new()) == NULL)
		fatal("evbuffer_new");

	if (f->fd != -1)
		r = fstat(f->fd, &sb);
	else
		r = fstatat(f->dir->fd, f->fpath, &sb, 0);

	if (r == -1) {
		np_errno(hdr->tag);
		evbuffer_free(evb);
		return;
	}

	serialize_stat(f->fpath, &sb, evb);
	np_stat(hdr->tag, EVBUFFER_LENGTH(evb), EVBUFFER_DATA(evb));
	evbuffer_free(evb);
}

static void
tremove(struct np_msg_header *hdr, const uint8_t *data, size_t len)
{
	struct fid	*f;
	uint32_t	 fid;
	int		 r;
	char		 dirpath[PATH_MAX + 3];

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

	if (f->qid.type & QTDIR) { /* directory */
		strlcpy(dirpath, "../", sizeof(dirpath));
		strlcat(dirpath, f->fpath, sizeof(dirpath));
		r = unlinkat(f->dir->fd, dirpath, AT_REMOVEDIR);
	} else /* file */
		r = unlinkat(f->dir->fd, f->fpath, 0);

	if (r == -1)
		np_errno(hdr->tag);
	else
		np_remove(hdr->tag);

	free_fid(f);
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
		{Topen,		topen},
		{Tcreate,	tcreate},
		{Tread,		tread},
		{Twrite,	twrite},
		{Tstat,		tstat},
		{Tremove,	tremove},
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
