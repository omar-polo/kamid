noinst_PROGRAMS =	ninepscript

ninepscript_SOURCES=parse.y			\
		script.c			\
		script.h			\
		$(top_srcdir)/kamid/client.c	\
		$(top_srcdir)/kamid/client.h	\
		$(top_srcdir)/kamid/kamid.h	\
		$(top_srcdir)/lib/kami.h	\
		$(top_srcdir)/lib/log.c		\
		$(top_srcdir)/lib/log.h		\
		$(top_srcdir)/lib/sandbox.c	\
		$(top_srcdir)/lib/sandbox.h	\
		$(top_srcdir)/lib/utils.c	\
		$(top_srcdir)/lib/utils.h

man5_MANS =	ninepscript.5
man8_MANS =	ninepscript.8

LDADD =		$(LIBOBJS)

AM_CPPFLAGS +=	-DKAMID_VERSION='"@VERSION@"'	\
		-I$(top_srcdir)/		\
		-I$(top_srcdir)/compat		\
		-I$(top_srcdir)/lib		\
		-I$(top_srcdir)/kamid
