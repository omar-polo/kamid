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

#include <event.h>
#include <limits.h>
#include <stdint.h>
#include <tls.h>

/* TODO: make these customizable */
#define KD_CONF_FILE		"/etc/kamid.conf"
#define KD_USER			"_kamid"
#define KD_SOCKET		"/var/run/kamid.sock"

#define IMSG_DATA_SIZE(imsg)	((imsg).hdr.len - IMSG_HEADER_SIZE)

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

struct kd_listen_conf {
	SIMPLEQ_ENTRY(kd_listen_conf)	 entry;
	uint32_t			 id;
	int				 fd;
	char				 iface[LINE_MAX];
	uint16_t			 port;
	struct table			*auth_table;
	char				 pki[LINE_MAX];
	struct event			 ev;
	struct tls			*ctx;
};

struct kd_pki_conf {
	SIMPLEQ_ENTRY(kd_pki_conf)	 entry;
	char				 name[LINE_MAX];
	uint8_t				*cert;
	size_t				 certlen;
	uint8_t				*key;
	size_t				 keylen;
	struct tls_config		*tlsconf;
};

struct kd_tables_conf {
	SIMPLEQ_ENTRY(kd_tables_conf)	 entry;
	struct table			*table;
};

struct kd_conf {
	struct kd_options_conf					 kd_options;
	SIMPLEQ_HEAD(kd_pki_conf_head, kd_pki_conf)		 pki_head;
	SIMPLEQ_HEAD(kd_tables_conf_head, kd_tables_conf)	 table_head;
	SIMPLEQ_HEAD(kd_listen_conf_head, kd_listen_conf)	 listen_head;
};

/* kamid.c */
extern int verbose;
int	main_imsg_compose_listener(int, int, uint32_t, const void *, uint16_t);
void	merge_config(struct kd_conf *, struct kd_conf *);
void	imsg_event_add(struct imsgev *);
int	imsg_compose_event(struct imsgev *, uint16_t, uint32_t, pid_t,
	    int, const void *, uint16_t);

struct kd_conf	*config_new_empty(void);
void		 config_clear(struct kd_conf *);

/* parse.y */
struct kd_conf	*parse_config(const char *);
int		 cmdline_symset(char *);

#endif
