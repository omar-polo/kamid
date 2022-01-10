bin_PROGRAMS = kamid

kamid_SOURCES =	client.c			\
		client.h			\
		control.c			\
		control.h			\
		kami.h				\
		kamid.c				\
		kamid.h				\
		listener.c			\
		listener.h			\
		parse.y				\
		table.c				\
		table.h				\
		table_static.c			\
		$(top_srcdir)/lib/log.c		\
		$(top_srcdir)/lib/log.h		\
		$(top_srcdir)/lib/sandbox.c	\
		$(top_srcdir)/lib/sandbox.h	\
		$(top_srcdir)/lib/utils.c	\
		$(top_srcdir)/lib/utils.h

man5_MANS =	kamid.conf.5
man7_MANS =	9p.7
man8_MANS =	kamid.8

LDADD =		$(LIBOBJS)

AM_CPPFLAGS +=	-DKAMID_VERSION='"@VERSION@"'	\
		-I$(top_srcdir)/		\
		-I$(top_srcdir)/compat		\
		-I$(top_srcdir)/lib		\
		-I$(top_srcdir)/kamid
