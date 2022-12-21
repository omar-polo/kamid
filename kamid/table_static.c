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

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "kamid.h"
#include "table.h"

static void	*hash_alloc(size_t, void *);
static void	*hash_calloc(size_t, size_t, void *);
static void	 hash_free(void *, void *);

static int	 table_static_open(struct table *);
static int	 table_static_add(struct table *, const char *, const char *);
static int	 table_static_lookup(struct table *, const char *, char **);
static void	 table_static_close(struct table *);

struct table_backend table_static = {
	"static",
	table_static_open,
	table_static_add,
	table_static_lookup,
	table_static_close,
};

struct kp {
	char	*val;
	char	 key[];
};

static void *
hash_alloc(size_t len, void *d)
{
	return xmalloc(len);
}

static void *
hash_calloc(size_t nmemb, size_t size, void *d)
{
	return xcalloc(nmemb, size);
}

static void
hash_free(void *ptr, void *d)
{
	free(ptr);
}

static int
table_static_open(struct table *t)
{
	struct ohash_info info = {
		.key_offset = offsetof(struct kp, key),
		.calloc = hash_calloc,
		.free = hash_free,
		.alloc = hash_alloc,
	};

	t->t_handle = xmalloc(sizeof(struct ohash));
	ohash_init(t->t_handle, 5, &info);
	return 0;
}

int
table_static_add(struct table *t, const char *key, const char *val)
{
	struct kp	*kp;
	unsigned int	 slot;
	size_t		 len;

	if (key == NULL)
		return -1;

	len = strlen(key) + 1;
	kp = xcalloc(1, sizeof(*kp) + len);
	memcpy(kp->key, key, len);
	if (val != NULL)
		kp->val = xstrdup(val);

	slot = ohash_qlookup(t->t_handle, kp->key);
	ohash_insert(t->t_handle, slot, kp);

	return 0;
}

int
table_static_lookup(struct table *t, const char *key, char **ret_val)
{
	struct kp	*kp;
	unsigned int	 slot;

	slot = ohash_qlookup(t->t_handle, key);
	if ((kp = ohash_find(t->t_handle, slot)) == NULL)
		return -1;

	*ret_val = xstrdup(kp->val);
	return 0;
}

static void
table_static_close(struct table *t)
{
	struct kp	*kp;
	unsigned int	 i;

	for (kp = ohash_first(t->t_handle, &i);
	     kp != NULL;
	     kp = ohash_next(t->t_handle, &i)) {
		ohash_remove(t->t_handle, i);
		free(kp->val);
		free(kp);
	}

	free(t->t_handle);
}
