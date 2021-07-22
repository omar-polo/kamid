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

#ifndef COMPAT_H
#define COMPAT_H

#include "config.h"

#include <sys/types.h>
#include <sys/uio.h>

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#define ATTR_DEAD __attribute__((noreturn))

#ifdef HAVE_QUEUE_H
# include <sys/queue.h>
#else
# include "compat/queue.h"
#endif

#ifdef HAVE_LIBUTIL
# include <imsg.h>
#else
# include "compat/imsg.h"
#endif

#ifndef HAVE_ASPRINTF
int		 asprintf(char **, const char *, ...);
int		 vasprintf(char **, const char *, ...);
#endif

#ifndef HAVE_ERR
void		 err(int, const char *, ...);
void		 errx(int, const char *, ...);
void		 warn(int, const char *, ...);
void		 warnx(int, const char *, ...);
#endif

#ifndef HAVE_GETDTABLECOUNT
int		 getdtablecount(void);
#endif

#ifndef HAVE_GETDTABLESIZE
int		 getdtablesize(void);
#endif

#ifndef HAVE_GETPROGNAME
const char	*getprogname(void);
#endif

#ifndef HAVE_RECALLOCARRAY
void		*recallocarray(void *, size_t, size_t, size_t);
#endif

#ifndef HAVE_SETPROCTITLE
void		 setproctitle(const char *, ...);
#endif

#ifndef HAVE_SETPROGNAME
void		 setproctitle(const char *, ...);
#endif

#ifndef HAVE_STRLCAT
size_t		 strlcat(char *, const char *, size_t);
#endif

#ifndef HAVE_STRLCPY
size_t		 strlcpy(char *, const char *, size_t);
#endif

#ifndef HAVE_STRTONUM
long long	 strtonum(const char *, long long, long long, const char **);
#endif

#endif	/* COMPAT_H */
