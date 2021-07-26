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

#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "table.h"
#include "utils.h"

int
table_open(struct kd_conf *conf, const char *name, const char *type,
    const char *path)
{
	struct table *t;
	struct kd_tables_conf *entry;
	struct table_backend *backends[] = {
		&table_static,
		NULL,
	}, *b;
	size_t i;

	for (i = 0; backends[i] != NULL; ++i) {
		b = backends[i];
		if (!strcmp(type, b->name))
			goto found;
	}
	log_warn("unknown table type %s", type);
	return -1;

found:
	if (b->open == NULL) {
		log_warn("can't open table %s (type %s)",
		    name, b->name);
		return -1;
	}

	t = xcalloc(1, sizeof(*t));
	strlcpy(t->t_name, name, sizeof(t->t_name));
	if (path != NULL)
		strlcpy(t->t_path, path, sizeof(t->t_path));
	t->t_backend = b;

	if (t->t_backend->open(t) == -1)
		fatal("can't open table %s (type %s)",
		    name, path);

	entry = xcalloc(1, sizeof(*entry));
	entry->table = t;
	STAILQ_INSERT_HEAD(&conf->table_head, entry, entry);
	return 0;
}

int
table_add(struct table *t, const char *key, const char *val)
{
	if (t->t_backend->add == NULL) {
		log_warn("can't add to table %s (type %s)",
		    t->t_name, t->t_backend->name);
		return -1;
	}

	return t->t_backend->add(t, key, val);
}

int
table_lookup(struct table *t, const char *key, char **ret_val)
{
	if (t->t_backend->lookup == NULL) {
		log_warn("can't lookup table %s (type %s)",
		    t->t_name, t->t_backend->name);
		return -1;
	}

	return t->t_backend->lookup(t, key, ret_val);
}

void
table_close(struct table *t)
{
	if (t->t_backend->close != NULL)
		t->t_backend->close(t);
}
