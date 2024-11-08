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

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compat.h"

static void vwarn(const char*, va_list);
static void vwarnx(const char*, va_list);

static void
vwarn(const char *fmt, va_list ap)
{
	fprintf(stderr, "%s: ", getprogname());
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, ": %s\n", strerror(errno));
}

static void
vwarnx(const char *fmt, va_list ap)
{
	fprintf(stderr, "%s: ", getprogname());
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
}

void
err(int ret, const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vwarn(fmt, ap);
	va_end(ap);
	exit(ret);
}

void
errc(int ret, int code, const char *fmt, ...)
{
	va_list	ap;

	errno = code;

	va_start(ap, fmt);
	vwarn(fmt, ap);
	va_end(ap);
	exit(ret);
}

void
errx(int ret, const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vwarnx(fmt, ap);
	va_end(ap);
	exit(ret);
}

void
warn(const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vwarn(fmt, ap);
	va_end(ap);
}

void
warnc(int code, const char *fmt, ...)
{
	va_list	ap;

	errno = code;

	va_start(ap, fmt);
	vwarn(fmt, ap);
	va_end(ap);
}

void
warnx(const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vwarnx(fmt, ap);
	va_end(ap);
}
