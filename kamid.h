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

#ifndef KAMID_H
#define KAMID_H

#include "compat.h"

#include <limits.h>
#include <stdint.h>
#include <tls.h>

/* TODO: make these customizable */
#define KD_CONF_FILE		"/etc/kamid.conf"
#define KD_USER			"_kamid"
#define KD_SOCKET		"/var/run/kamid.sock"

#define IMSG_DATA_SIZE(imsg)	((imsg).hdr.len - IMSG_HEADER_SIZE)

#define MIN(a, b) ((a) < (b) ? (a) : (b))

struct imsgev {
	struct imsgbuf	 ibuf;
	void		(*handler)(int, short, void *);
	struct event	 ev;
	short		 events;
};

enum imsg_type {
	IMSG_NONE,
	IMSG_CTL_LOG_VERBOSE,
	IMSG_CTL_RELOAD,
	IMSG_CONTROLFD,
	IMSG_STARTUP,
	IMSG_RECONF_CONF,
	IMSG_RECONF_PKI,
	IMSG_RECONF_PKI_CERT,
	IMSG_RECONF_PKI_KEY,
	IMSG_RECONF_LISTEN,
	IMSG_RECONF_END,
	IMSG_AUTH,
	IMSG_AUTH_DIR,
	IMSG_AUTH_TLS,
	IMSG_CONN_GONE,
	IMSG_BUF,
	IMSG_MSIZE,
	IMSG_CLOSE,
};

struct kd_options_conf {
	/* ... */
};

enum table_type {
	T_NONE		= 0,
	T_HASH		= 0x01,
};

struct table {
	char			 t_name[LINE_MAX];
	enum table_type		 t_type;
	char			 t_path[PATH_MAX];
	void			*t_handle;
	struct table_backend	*t_backend;
};

struct table_backend {
	const char	*name;
	int		(*open)(struct table *);
	int		(*add)(struct table *, const char *, const char *);
	int		(*lookup)(struct table *, const char *, char **);
	void		(*close)(struct table *);
};

/* table_static.c */
extern struct table_backend table_static;

#define L_NONE	0x0
#define L_TLS	0x1
struct kd_listen_conf {
	STAILQ_ENTRY(kd_listen_conf)	 entry;
	uint32_t			 id;
	uint32_t			 flags;
	int				 fd;
	char				 iface[LINE_MAX];
	uint16_t			 port;
	struct table			*auth_table;
	char				 pki[LINE_MAX];
	struct event			 ev;
	struct tls			*ctx;
};

struct kd_pki_conf {
	STAILQ_ENTRY(kd_pki_conf)	 entry;
	char				 name[LINE_MAX];
	uint8_t				*cert;
	size_t				 certlen;
	uint8_t				*key;
	size_t				 keylen;
	struct tls_config		*tlsconf;
};

struct kd_tables_conf {
	STAILQ_ENTRY(kd_tables_conf)	 entry;
	struct table			*table;
};

struct kd_conf {
	struct kd_options_conf					 kd_options;
	STAILQ_HEAD(kd_pki_conf_head, kd_pki_conf)		 pki_head;
	STAILQ_HEAD(kd_tables_conf_head, kd_tables_conf)	 table_head;
	STAILQ_HEAD(kd_listen_conf_head, kd_listen_conf)	 listen_head;
};

struct kd_auth_req {
	uint32_t	listen_id;
	char		hash[128+1];
};

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

/* kamid.c */
extern int verbose;
int	main_imsg_compose_listener(int, int, uint32_t, const void *, uint16_t);
void	merge_config(struct kd_conf *, struct kd_conf *);

struct kd_conf	*config_new_empty(void);
void		 config_clear(struct kd_conf *);

/* parse.y */
struct kd_conf	*parse_config(const char *);
int		 cmdline_symset(char *);

#endif
