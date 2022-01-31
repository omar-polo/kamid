noinst_LIBRARIES = libopenbsd-compat.a

AM_CPPFLAGS +=	-DKAMID_VERSION='"@VERSION@"' \
		-I$(top_srcdir)/compat \
		-I$(top_srcdir)

# LIBOBJS could be empty (especially if we're compiling on OpenBSD), so
# add a dummy file just so we don't end up with an empty archive, if
# that's even a thing.
libopenbsd_compat_a_SOURCES = dummy.c
libopenbsd_compat_a_LIBADD = $(LIBOBJS)

EXTRA_DIST =	imsg.h	\
		ohash.h	\
		queue.h	\
		tree.h	\
		vis.h
