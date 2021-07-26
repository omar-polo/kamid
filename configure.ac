AC_INIT([kamid], [0.1], [kamid@omarpolo.com], [kamid], [gemini://kamid.omarpolo.com])
AC_CONFIG_LIBOBJ_DIR(compat)
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])
AC_PROG_CC
AC_USE_SYSTEM_EXTENSIONS
AC_PROG_YACC

# Some functions can be in libbsd.  Thanks to lldpb for the inspiration :)
AC_ARG_WITH([libbsd],
  AS_HELP_STRING([--with-libbsd], [Use libbsd @<:@default=auto@:>@]),
  [],
  [with_libbsd=auto])
if test x"$with_libbsd" != x"no"; then
  PKG_CHECK_MODULES([libbsd], [libbsd-overlay libbsd-ctor], [
    _save_CFLAGS="$CFLAGS"
    _save_LIBS="$LIBS"
    CFLAGS="$CFLAGS $libbsd_CFLAGS"
    LIBS="$LIBS $libbsd_LIBS"
    AC_MSG_CHECKING([if libbsd can be linked correctly])
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[
  @%:@include <sys/time.h>
  @%:@include <sys/types.h>
  ]], [[]])],[
        AC_MSG_RESULT(yes)
        LLDP_CFLAGS="$LLDP_CFLAGS $libbsd_CFLAGS"
        LLDP_LDFLAGS="$LLDP_LDFLAGS $libbsd_LIBS"
        with_libbsd=yes
      ],[
        AC_MSG_RESULT(no)
        CFLAGS="$_save_CFLAGS"
        LIBS="$_save_LIBS"
        if test x"$with_libbsd" = x"yes"; then
           AC_MSG_FAILURE([*** no libbsd support found])
        fi
        with_libbsd=no
      ])
  ], [
    if test x"$with_libbsd" = x"yes"; then
       AC_MSG_FAILURE([*** no libbsd support found])
    fi
    with_libbsd=no
  ])
fi

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
	recallocarray	\
	setproctitle	\
	setprogname	\
	strlcat		\
	strlcpy		\
	strtonum	\
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

AC_CHECK_LIB(event, event_init, [], [
	AC_MSG_ERROR([requires libevent])
])

AC_CHECK_LIB(util, imsg_init, [], [
	AC_LIBOBJ(imsg)
	AC_LIBOBJ(imsg-buffer)
	AC_LIBOBJ(ohash)
])

# check compiler flags
AC_DEFUN([CC_ADD_CHECK_FLAGS], [
	AC_MSG_CHECKING([if $CC supports $1 flag])
	old_CFLAGS="$CFLAGS"
	CFLAGS="$CFLAGS $1"
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],
		AC_MSG_RESULT(yes),
		AC_MSG_RESULT(no)
		CFLAGS="$old_CFLAGS")
])
CC_ADD_CHECK_FLAGS([-Wall])
CC_ADD_CHECK_FLAGS([-Wextra])
CC_ADD_CHECK_FLAGS([-Wmissing-prototypes])
CC_ADD_CHECK_FLAGS([-Wstrict-prototypes])
CC_ADD_CHECK_FLAGS([-Wwrite-strings])
CC_ADD_CHECK_FLAGS([-Wno-unused-parameter])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
	Makefile
])

AC_OUTPUT
