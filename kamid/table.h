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

#ifndef TABLE_H
#define TABLE_H

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

int	 table_open(struct kd_conf *, const char *, const char *, const char *);
int	 table_add(struct table *, const char *, const char *);
int	 table_lookup(struct table *, const char *, char **);
void	 table_close(struct table *);

#endif
