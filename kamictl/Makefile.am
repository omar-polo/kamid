bin_PROGRAMS = kamictl

kamictl_SOURCES=ctl_parser.c			\
		ctl_parser.h			\
		kamictl.c			\
		$(top_srcdir)/compat.h		\
		$(top_srcdir)/lib/log.c		\
		$(top_srcdir)/lib/log.h		\
		$(top_srcdir)/lib/sandbox.c	\
		$(top_srcdir)/lib/sandbox.h

dist_man8_MANS = kamictl.8

kamictl_LDADD =	$(top_builddir)/compat/libopenbsd-compat.a
kamictl_DEPENDENCIES = $(top_builddir)/compat/libopenbsd-compat.a

AM_CPPFLAGS +=	-DKAMID_VERSION='"@VERSION@"'	\
		-I$(top_srcdir)/		\
		-I$(top_srcdir)/compat		\
		-I$(top_srcdir)/lib		\
		-I$(top_srcdir)/kamictl		\
		-I$(top_srcdir)/kamid
