bin_PROGRAMS =		kamiproxy

kamiproxy_SOURCES =	proxy.c			\
			$(top_srcdir)/lib/log.c	\
			$(top_srcdir)/lib/log.h

dist_man1_MANS =	kamiproxy.1

kamiproxy_LDADD =	$(top_builddir)/compat/libopenbsd-compat.a
kamiproxy_DEPENDENCIES = $(top_builddir)/compat/libopenbsd-compat.a

AM_CPPFLAGS +=		-DKAMID_VERSION='"@VERSION@"'	\
			-I$(top_srcdir)/		\
			-I$(top_srcdir)/compat		\
			-I$(top_srcdir)/lib
