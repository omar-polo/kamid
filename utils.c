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

#include <ctype.h>
#include <stdio.h>
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
	case Terror:	return "Terror"; /* illegal */
	case Rerror:	return "Rerror";
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

const char *
pp_qid_type(uint8_t type)
{
	switch (type) {
	case QTDIR:     return "dir";
	case QTAPPEND:  return "append-only";
	case QTEXCL:    return "exclusive";
	case QTMOUNT:   return "mounted-channel";
	case QTAUTH:    return "authentication";
	case QTTMP:     return "non-backed-up";
	case QTSYMLINK: return "symlink";
	case QTFILE:    return "file";
	}

	return "unknown";
}

static void
hexdump_ppline(int x, uint8_t *data, size_t len)
{
	for (; x < 50; x++)
		printf(" ");

	printf("|");

	for (x = 0; x < (int)len; ++x) {
		if (isgraph(data[x]))
			printf("%c", data[x]);
		else
			printf(".");
	}

	printf("|\n");
}

void
hexdump(const char *label, uint8_t *data, size_t len)
{
	size_t	i;
	int	x, n;

	/*
	 * Layout:
	 * === first block === == second block ==  |........|\n
	 * first and second block are 8 bytes long (for a total of 48
	 * columns), plus two separator plus two | plus 16 chars, for
	 * a total of 68 characters.
	 */

	printf("\nhexdump \"%s\": (%zu bytes)\n", label, len);
	for (x = 0, n = 0, i = 0; i < len; ++i) {
		if (i != 0 && i % 8 == 0) {
			printf(" ");
			x++;
		}

		if (n == 16) {
			hexdump_ppline(x, &data[i - 16], 16);
			x = 0;
			n = 0;
		}

		printf("%02x ", data[i]);
		x += 3;
		n++;
	}

	if (n != 0)
                hexdump_ppline(x, &data[i - n], n);

	printf("\n");
}

void
imsg_event_add(struct imsgev *iev)
{
	iev->events = EV_READ;
	if (iev->ibuf.w.queued)
		iev->events |= EV_WRITE;

	event_del(&iev->ev);
	event_set(&iev->ev, iev->ibuf.fd, iev->events, iev->handler, iev);
	event_add(&iev->ev, NULL);
}

int
imsg_compose_event(struct imsgev *iev, uint16_t type, uint32_t peerid,
    pid_t pid, int fd, const void *data, uint16_t datalen)
{
	int	ret;

	if ((ret = imsg_compose(&iev->ibuf, type, peerid, pid, fd, data,
	    datalen) != -1))
		imsg_event_add(iev);

	return ret;
}
