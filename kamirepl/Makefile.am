bin_PROGRAMS =	kamirepl

kamirepl_SOURCES=kamirepl.c			\
		$(top_srcdir)/lib/9pclib.c	\
		$(top_srcdir)/lib/9pclib.h	\
		$(top_srcdir)/lib/kami.h	\
		$(top_srcdir)/lib/log.c		\
		$(top_srcdir)/lib/log.h		\
		$(top_srcdir)/lib/utils.c	\
		$(top_srcdir)/lib/utils.h

dist_man1_MANS = kamirepl.1

LDADD =		$(LIBOBJS)

AM_CPPFLAGS +=	-DKAMID_VERSION='"@VERSION@"'	\
		-I$(top_srcdir)/		\
		-I$(top_srcdir)/compat		\
		-I$(top_srcdir)/lib
