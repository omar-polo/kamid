bin_PROGRAMS =	kamiftp

kamiftp_SOURCES=ftp.c				\
		rl.c				\
		$(top_srcdir)/lib/9pclib.c	\
		$(top_srcdir)/lib/9pclib.h	\
		$(top_srcdir)/lib/kami.h	\
		$(top_srcdir)/lib/log.c		\
		$(top_srcdir)/lib/log.h		\
		$(top_srcdir)/lib/utils.c	\
		$(top_srcdir)/lib/utils.h

dist_man1_MANS = kamiftp.1

kamiftp_CFLAGS=	@READLINE_CFLAGS@ $(AM_CFLAGS)
kamiftp_LDADD=	@READLINE_LIBS@ $(top_builddir)/compat/libopenbsd-compat.a
kamiftp_DEPENDENCIES = $(top_builddir)/compat/libopenbsd-compat.a

AM_CPPFLAGS =	-DKAMID_VERSION='"@VERSION@"'	\
		-I$(top_srcdir)/		\
		-I$(top_srcdir)/compat		\
		-I$(top_srcdir)/lib
