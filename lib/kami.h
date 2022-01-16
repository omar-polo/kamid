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

#ifndef KAMI_H
#define KAMI_H

/*
 * 9p message header.
 *
 * The message itself is len bytes long (counting the whole header
 * too.)
 */
struct np_msg_header {
	uint32_t	len;
	uint8_t		type;
	uint16_t	tag;
};

struct qid {
	uint64_t		 path;
	uint32_t		 vers;
	uint8_t			 type;
};

struct np_stat {
	uint16_t	 type;
	uint32_t	 dev;
	struct qid	 qid;
	uint32_t	 mode;
	uint32_t	 atime;
	uint32_t	 mtime;
	uint64_t	 length;
	char		*name;
	char		*uid;
	char		*gid;
	char		*muid;
};

/* useful constants */
#define HEADERSIZE	(4 + 1 + 2)
#define	VERSION9P	"9P2000"
#define MSIZE9P		((uint32_t)4*1024*1024)
#define NOTAG		((uint16_t)~0U)
#define NOFID		((uint32_t)~0U)
#define NOUID		(-1)
#define QIDSIZE		13
#define MAXWELEM	16

#define NPSTATSIZ(namlen, uidnam, gidnam, unam) \
	(6 + QIDSIZE + 20 + 2 + namlen + 2 + uidnam + 2 + gidnam + 2 + unam)

/* bits in Qid.type */
#define QTDIR		0x80		/* type bit for directories */
#define QTAPPEND	0x40		/* type bit for append only files */
#define QTEXCL		0x20		/* type bit for exclusive use files */
#define QTMOUNT		0x10		/* type bit for mounted channel */
#define QTAUTH		0x08		/* type bit for authentication file */
#define QTTMP		0x04		/* type bit for non-backed-up file */
#define QTSYMLINK	0x02		/* type bit for symbolic link */
#define QTFILE		0x00		/* type bits for plain file */

/* Topen mode/flags */
#define KOREAD		0x00
#define KOWRITE		0x01
#define KORDWR		0x02
#define KOEXEC		0x03
#define KOTRUNC		0x10
#define KORCLOSE	0x40

/* 9p message types */
enum {
	Treaddir =	40,	/* .L */
	Rreaddir,

	Tversion =	100,
	Rversion,
	Tauth =		102,
	Rauth,
	Tattach =	104,
	Rattach,
	Terror =	106,	/* illegal */
	Rerror,
	Tflush =	108,
	Rflush,
	Twalk =		110,
	Rwalk,
	Topen =		112,
	Ropen,
	Tcreate =	114,
	Rcreate,
	Tread =		116,
	Rread,
	Twrite =	118,
	Rwrite,
	Tclunk =	120,
	Rclunk,
	Tremove =	122,
	Rremove,
	Tstat =		124,
	Rstat,
	Twstat =	126,
	Rwstat,
	Tmax,

	/*
	 * plan9ports' include/fcall.h also has a
	 *
	 *	Topenfd = 98,
	 *	Ropenfd,
	 *
	 * which it's not mentioned in the 9p "rfc" over at
	 * 9p.cat-v.org.  Ignoring that for now.
	 */
};

#endif
