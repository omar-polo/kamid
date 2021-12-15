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

/* 9p client library */

#ifndef NPCLIB_H
#define NPCLIB_H

#include "compat.h"

#include <stdint.h>

extern uint16_t		 iota_tag;
extern struct evbuffer	*evb;

void		 write_hdr(uint32_t, uint8_t, uint16_t);
void		 write_hdr_auto(uint32_t, uint8_t);
void		 write_str(uint16_t, const char *);
void		 write_str_auto(const char *);
void		 write_64(uint64_t);
void		 write_32(uint32_t);
void		 write_16(uint16_t);
void		 write_8(uint8_t);

#define write_off write_64
#define write_fid write_32
#define write_tag write_16

void		 tversion(const char *, uint32_t);
void		 tattach(uint32_t, uint32_t, const char *, const char *);
void		 tclunk(uint32_t);
void		 tflush(uint16_t);
void		 twalk(uint32_t, uint32_t, const char **, size_t);
void		 topen(uint32_t, uint8_t);
void		 tread(uint32_t, uint64_t, uint32_t);

#endif
