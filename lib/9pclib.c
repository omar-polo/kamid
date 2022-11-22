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

#include <inttypes.h>
#include <string.h>

#include "kami.h"
#include "log.h"
#include "utils.h"

#include "9pclib.h"

uint16_t iota_tag;

struct evbuffer *evb;

void
write_hdr(uint32_t len, uint8_t type, uint16_t tag)
{
	len += HEADERSIZE;

	log_debug("enqueuing a packet; len=%"PRIu32" type=%d[%s] tag=%d",
	    len, type, pp_msg_type(type), tag);

	len = htole32(len);
	/* type is one byte, no endiannes issues */
	tag = htole16(tag);

	evbuffer_add(evb, &len, sizeof(len));
	evbuffer_add(evb, &type, sizeof(type));
	evbuffer_add(evb, &tag, sizeof(tag));
}

void
write_hdr_auto(uint32_t len, uint8_t type)
{
	if (++iota_tag == NOTAG)
		++iota_tag;
	write_hdr(len, type, iota_tag);
}

void
write_str(uint16_t len, const char *str)
{
	uint16_t l = len;

	len = htole16(len);
	evbuffer_add(evb, &len, sizeof(len));
	evbuffer_add(evb, str, l);
}

void
write_str_auto(const char *str)
{
	if (str == NULL)
		write_16(0);
	else
		write_str(strlen(str), str);
}

void
write_buf(const void *d, uint32_t len)
{
	write_32(len);
	evbuffer_add(evb, d, len);
}

void
write_64(uint64_t x)
{
	x = htole64(x);
	evbuffer_add(evb, &x, sizeof(x));
}

void
write_32(uint32_t fid)
{
	fid = htole32(fid);
	evbuffer_add(evb, &fid, sizeof(fid));
}

void
write_16(uint16_t tag)
{
	tag = htole16(tag);
	evbuffer_add(evb, &tag, sizeof(tag));
}

void
write_8(uint8_t x)
{
	evbuffer_add(evb, &x, sizeof(x));
}



void
tversion(const char *v, uint32_t msize)
{
	uint32_t	len;
	uint16_t	sl;

	sl = strlen(v);

	/* msize[4] version[s] */
	len = sizeof(msize) + sizeof(sl) + sl;
	write_hdr(len, Tversion, NOTAG);
	write_32(msize);
	write_str(sl, v);
}

void
tattach(uint32_t fid, uint32_t afid, const char *uname, const char *aname)
{
	uint32_t	len;
	uint16_t	ul, al;

	ul = strlen(uname);
	al = strlen(aname);

	/* fid[4] afid[4] uname[s] aname[s] */
	len = sizeof(fid) + sizeof(afid) + sizeof(ul) + ul
	    + sizeof(al) + al;
	write_hdr_auto(len, Tattach);
	write_fid(fid);
	write_fid(afid);
	write_str(ul, uname);
	write_str(al, aname);
}

void
tclunk(uint32_t fid)
{
	uint32_t	len;

	/* fid[4] */
	len = sizeof(fid);
	write_hdr_auto(len, Tclunk);
	write_fid(fid);
}

void
tflush(uint16_t oldtag)
{
	uint32_t	len;

	/* oldtag[2] */
	len = sizeof(oldtag);
	write_hdr_auto(len, Tflush);
	write_tag(oldtag);
}

void
twalk(uint32_t fid, uint32_t newfid, const char **wnames, size_t nwname)
{
	size_t		i;
	uint32_t	len;

	/* fid[4] newfid[4] nwname[2] nwname*(wname[s]) */
	len = sizeof(fid) + sizeof(newfid) + 2;
	for (i = 0; i < nwname; ++i)
		len += 2 + strlen(wnames[i]);

	write_hdr_auto(len, Twalk);
	write_fid(fid);
	write_fid(newfid);
	write_16(nwname);
	for (i = 0; i < nwname; ++i)
		write_str_auto(wnames[i]);
}

void
topen(uint32_t fid, uint8_t mode)
{
	uint32_t	len;

	/* fid[4] mode[1] */
	len = sizeof(fid) + sizeof(mode);
	write_hdr_auto(len, Topen);
	write_fid(fid);
	write_8(mode);
}

void
tcreate(uint32_t fid, const char *name, uint32_t perm, uint8_t mode)
{
	uint32_t	len;
	uint16_t	nl;

	/* fid[4] name[s] perm[4] mode[1] */
	nl = strlen(name);
	len = sizeof(fid) + sizeof(nl) + nl + sizeof(perm) + sizeof(mode);
	write_hdr_auto(len, Tcreate);
	write_fid(fid);
	write_str(nl, name);
	write_32(perm);
	write_8(mode);
}

void
tread(uint32_t fid, uint64_t off, uint32_t count)
{
	uint32_t	len;

	/* fid[4] off[8] count[4] */
	len = sizeof(fid) + sizeof(off) + sizeof(count);
	write_hdr_auto(len, Tread);
	write_fid(fid);
	write_off(off);
	write_32(count);
}

void
twrite(uint32_t fid, uint64_t off, const void *data, uint32_t count)
{
	uint32_t	len;

	/* fid[4] off[8] count[4] data[count] */
	len = sizeof(fid) + sizeof(off) + sizeof(count) + count;
	write_hdr_auto(len, Twrite);
	write_fid(fid);
	write_off(off);
	write_buf(data, count);
}

void
tstat(uint32_t fid)
{
	/* fid[4] */
	write_hdr_auto(sizeof(fid), Tstat);
	write_fid(fid);
}

void
twstat(uint32_t fid, const struct np_stat *st)
{
	uint32_t	len;
	uint16_t	stlen, n;

	/* fid[4] stat[n] */

	stlen = NPSTATSIZ(0, 0, 0, 0);
	if (st->name != NULL)
		stlen += strlen(st->name);
	if (st->uid != NULL)
		stlen += strlen(st->uid);
	if (st->gid != NULL)
		stlen += strlen(st->gid);
	if (st->muid != NULL)
		stlen += strlen(st->muid);

	n = sizeof(stlen) + stlen;
	len = sizeof(fid) + sizeof(n) + n;

	write_hdr_auto(len, Twstat);
	write_fid(fid);
	write_16(n);
	write_16(stlen);
	write_16(st->type);
	write_32(st->dev);

	write_8(st->qid.type);
	write_32(st->qid.vers);
	write_64(st->qid.path);

	write_32(st->mode);
	write_32(st->atime);
	write_32(st->mtime);
	write_64(st->length);

	write_str_auto(st->name);
	write_str_auto(st->uid);
	write_str_auto(st->gid);
	write_str_auto(st->muid);
}

void
tremove(uint32_t fid)
{
	/* fid[4] */
	write_hdr_auto(sizeof(fid), Tremove);
	write_fid(fid);
}
