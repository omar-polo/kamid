SUBDIRS = kamictl kamid kamiftp kamirepl ninepscript

AM_CPPFLAGS += -DKAMID_VERSION='"@VERSION"' \
	-I$(top_srcdir)/lib \
	-I$(top_srcdir)/compat

LDADD = $(LIBOBJS)

AM_CFLAGS += -Wall
AM_CFLAGS += -Wextra
AM_CFLAGS += -Wmissing-prototypes
AM_CFLAGS += -Wstrict-prototypes
AM_CFLAGS += -Wwrite-strings
AM_CFLAGS += -Wno-unused-parameter

test:
	@echo XXX: figure it out something
	@false
#$(MAKE) -C regress 
