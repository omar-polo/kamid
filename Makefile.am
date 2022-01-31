SUBDIRS = compat contrib kamictl kamid kamiftp kamirepl ninepscript regress

AM_CPPFLAGS += -DKAMID_VERSION='"@VERSION"' \
	-I$(top_srcdir)/lib \
	-I$(top_srcdir)/compat

LDADD = $(LIBOBJS)

SUDO ?= sudo
HAVE_LISP ?= no

$(top_builddir)/ninepscript/ninepscript:
	${MAKE} -C $(top_builddir)/ninepscript

test: $(top_builddir)/ninepscript/ninepscript
	"${SUDO}" "$(top_builddir)"/ninepscript/ninepscript \
		-r $(top_srcdir)/regress/root \
		$(top_srcdir)/regress/ninepscript/*-suite.9ps
	@if [ "${HAVE_LISP}" = yes ]; then \
		export PATH="$$(cd $(top_builddir)/kamid/; pwd):$$PATH"; \
		cd "$(top_srcdir)"/regress/lisp && \
			SUDO="${SUDO}" ./run.sh; \
	else \
		echo "skipping lisp suite (HAVE_LISP=yes to run it)."; \
	fi
