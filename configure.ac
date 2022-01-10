AC_INIT([kamid-portable], [0.1], [kamid@omarpolo.com], [],
	[https://kamid.omarpolo.com])
AC_CONFIG_AUX_DIR(etc)
AC_CONFIG_LIBOBJ_DIR(compat)
AM_INIT_AUTOMAKE([foreign subdir-objects])

KAMID_RELEASE=No

AC_DEFINE_UNQUOTED(VERSION, "$VERSION")
AC_SUBST(VERSION)
AC_SUBST(KAMID_RELEASE)

AC_CANONICAL_HOST

# When CFLAGS isn't set at this stage and gcc is detected by the macro below,
# autoconf will automatically use CFLAGS="-O2 -g". Prevent that by using an
# empty default.
: ${CFLAGS=""}

# Save user CPPFLAGS, CFLAGS and LDFLAGS. We need to change them because
# AC_CHECK_HEADER doesn't give us any other way to update the include
# paths. But for Makefile.am we want to use AM_CPPFLAGS and friends.
SAVED_CFLAGS="$CFLAGS"
SAVED_CPPFLAGS="$CPPFLAGS"
SAVED_LDFLAGS="$LDFLAGS"

# Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_YACC
PKG_PROG_PKG_CONFIG
AC_USE_SYSTEM_EXTENSIONS

# Some functions can be in libbsd.  Thanks to lldpb for the inspiration :)
AC_ARG_WITH([libbsd],
  AS_HELP_STRING([--with-libbsd], [Use libbsd @<:@default=auto@:>@]),
  [],
  [with_libbsd=auto])
if test x"$with_libbsd" != x"no"; then
  PKG_CHECK_MODULES([libbsd], [libbsd-overlay libbsd-ctor], [
    _save_AM_CFLAGS="$AM_CFLAGS"
    _save_LIBS="$LIBS"
    AM_CFLAGS="$AM_CFLAGS $libbsd_CFLAGS"
    LIBS="$LIBS $libbsd_LIBS"
  ], [
    if test x"$with_libbsd" = x"yes"; then
       AC_MSG_FAILURE([*** no libbsd support found])
    fi
    with_libbsd=no
  ])
fi

# Checks for library functions.
AC_SEARCH_LIBS([arc4random], [],
	[AC_DEFINE([HAVE_ARC4RANDOM], 1, [arc4random])],
	[AC_DEFINE([HAVE_ARC4RANDOM], 0, [arc4random])])

AC_REPLACE_FUNCS([
	asprintf	\
	err		\
	freezero	\
	getdtablecount	\
	getdtablesize	\
	getprogname	\
	memmem		\
	recallocarray	\
	setproctitle	\
	setprogname	\
	strlcat		\
	strlcpy		\
	strsep		\
	strtonum	\
	vis		\
])

AC_MSG_CHECKING([for sys/queue.h with TAILQ_FOREACH_SAFE and STAILQ_ENTRY])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
#include <sys/queue.h>
#include <stddef.h>
], [
	TAILQ_HEAD(tailhead, entry) head;
	struct entry {
		TAILQ_ENTRY(entry) entries;
	} *np, *nt;
	TAILQ_INIT(&head);
	TAILQ_FOREACH_SAFE(np, &head, entries, nt) {
		/* nop */ ;
	}

	STAILQ_HEAD(listhead, qentry) qhead = STAILQ_HEAD_INITIALIZER(qhead);
	struct qentry {
		STAILQ_ENTRY(qentry) entries;
	} foo;

	return 0;
])], [
	AC_MSG_RESULT(yes)
	AC_DEFINE([HAVE_QUEUE_H], 1, [QUEUE_H])
], AC_MSG_RESULT(no))

AC_CHECK_HEADERS([sys/tree.h])

AC_CHECK_DECL(PR_SET_NAME, AC_DEFINE([HAVE_PR_SET_NAME], 1, [pr_set_name]), [],
	[[#include <sys/prctl.h>]])

AC_CHECK_LIB([crypto], [RAND_add], [], [
	AC_MSG_ERROR([requires openssl])
])

AC_CHECK_LIB(tls, tls_init, [], [
	AC_MSG_ERROR([requires libtls])
])

AS_CASE([$host_os],
	[*openbsd*], [AC_CHECK_LIB([event], [event_init], [],
			[AC_MSG_ERROR([requires libevent])])],
	[PKG_CHECK_MODULES([libevent2], [libevent_core >= 2],
		[
			AC_DEFINE([HAVE_EVENT2], 1, [1 if using event2])
			AM_CFLAGS="$libevent2_CFLAGS $AM_CFLAGS"
			LIBS="$libevent2_LIBS $LIBS"
		], [AC_MSG_ERROR([requires libevent])])])

AC_CHECK_LIB(util, imsg_init, [], [
	AC_LIBOBJ(fmt_scaled)
	AC_LIBOBJ(imsg)
	AC_LIBOBJ(imsg-buffer)
	AC_LIBOBJ(ohash)
])

# Check for readline
AS_CASE([$host_os],
	[*openbsd*], [
		AC_DEFINE([HAVE_READLINE], 1, [1 if readline found])
		READLINE_CFLAGS=''
		READLINE_LIBS='-lreadline'
	], [
		PKG_CHECK_MODULES([READLINE], [readline], [
			AC_DEFINE([HAVE_READLINE], 0, [])
		], [
			AC_DEFINE([HAVE_READLINE], 0, [])
		])
	]
)
AC_SUBST(READLINE_CFLAGS)
AC_SUBST(READLINE_LIBS)

# Save our CFLAGS/CPPFLAGS/LDFLAGS for the Makefile and restore the old user
# variables.
AC_SUBST(AM_CPPFLAGS)
CPPFLAGS="$SAVED_CPPFLAGS"
AC_SUBST(AM_CFLAGS)
CFLAGS="$SAVED_CFLAGS"
AC_SUBST(AM_LDFLAGS)
LDFLAGS="$SAVED_LDFLAGS"

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
	Makefile
	kamictl/Makefile
	kamid/Makefile
	kamiftp/Makefile
	kamirepl/Makefile
	ninepscript/Makefile
])

AC_OUTPUT
