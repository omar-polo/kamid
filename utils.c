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

#include "kamid.h"
#include "log.h"
#include "utils.h"

void *
xmalloc(size_t size)
{
	void	*r;

	if ((r = malloc(size)) == NULL)
		fatal("malloc");
	return r;
}

void *
xcalloc(size_t nmemb, size_t size)
{
	void	*r;

	if ((r = calloc(nmemb, size)) == NULL)
		fatal("calloc");
	return r;
}

char *
xstrdup(const char *s)
{
	char	*r;

	if ((r = strdup(s)) == NULL)
		fatal("strdup");
	return r;
}

void *
xmemdup(const void *d, size_t len)
{
	void	*r;

	if ((r = malloc(len)) == NULL)
		fatal("malloc");
	memcpy(r, d, len);
	return r;
}

const char *
pp_msg_type(uint8_t type)
{
	switch (type) {
	case Tversion:	return "Tversion";
	case Rversion:	return "Rversion";
	case Tauth:	return "Tauth";
	case Rauth:	return "Rauth";
	case Tattach:	return "Tattach";
	case Rattach:	return "Rattach";
	case Tflush:	return "Tflush";
	case Rflush:	return "Rflush";
	case Twalk:	return "Twalk";
	case Rwalk:	return "Rwalk";
	case Topen:	return "Topen";
	case Ropen:	return "Ropen";
	case Tcreate:	return "Tcreate";
	case Rcreate:	return "Rcreate";
	case Tread:	return "Tread";
	case Rread:	return "Rread";
	case Twrite:	return "Twrite";
	case Rwrite:	return "Rwrite";
	case Tclunk:	return "Tclunk";
	case Rclunk:	return "Rclunk";
	case Tremove:	return "Tremove";
	case Rremove:	return "Rremove";
	case Tstat:	return "Tstat";
	case Rstat:	return "Rstat";
	case Twstat:	return "Twstat";
	case Rwstat:	return "Rwstat";
	default:	return "unknown";
	}
}
