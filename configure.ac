AC_INIT([kamid], [0.2], [kamid@omarpolo.com], [],
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
AC_PROG_RANLIB
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
    AM_CFLAGS="$AM_CFLAGS $libbsd_CFLAGS"
    LIBS="$LIBS $libbsd_LIBS"
  ], [
    if test x"$with_libbsd" = x"yes"; then
       AC_MSG_FAILURE([*** no libbsd support found])
    fi
    with_libbsd=no
  ])
fi

AC_REPLACE_FUNCS([
	asprintf	\
	errc		\
	freezero	\
	getdtablecount	\
	getdtablesize	\
	getprogname	\
	memmem		\
	reallocarray	\
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

AC_MSG_CHECKING([for usable sys/tree.h])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
#include <sys/tree.h>
#include <stdio.h>

struct client {
	int			id;
	SPLAY_ENTRY(client)	sp_entry;
};
SPLAY_HEAD(clients_tree_id, client) clients;

static inline int
clients_tree_cmp(struct client *a, struct client *b)
{
	if (a->id == b->id)
		return 0;
	else if (a->id < b->id)
		return -1;
	else
		return +1;
}

SPLAY_PROTOTYPE(clients_tree_id, client, sp_entry, clients_tree_cmp);
SPLAY_GENERATE(clients_tree_id, client, sp_entry, clients_tree_cmp);
], [
	return 0;
])], [
	AC_MSG_RESULT(yes)
	AC_DEFINE([HAVE_SYS_TREE_H], 1, [TREE_H])
], AC_MSG_RESULT(no))

AC_CHECK_HEADER([endian.h], [AC_DEFINE(HAVE_ENDIAN_H, 1, [have endian.h])], [
	AC_CHECK_HEADER([sys/endian.h],
		[AC_DEFINE(HAVE_SYS_ENDIAN_H, 1, [have sys/endian.h])], [
		AC_CHECK_HEADERS([libkern/OSByteOrder.h],
			[AC_DEFINE(HAVE_LIBKERN_OSBYTEORDER_H, 1, [have OSByteOrder.h])],
			[AC_MSG_ERROR([can't find compatible endian.h header])],
			[#include <machine/endian.h>])
	])
])

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
			AC_DEFINE([HAVE_READLINE], 1, [])
		], [
			AC_DEFINE([HAVE_READLINE], 0, [])
		])
	]
)
AC_SUBST(READLINE_CFLAGS)
AC_SUBST(READLINE_LIBS)

# check compiler flags
AC_DEFUN([CC_ADD_CHECK_FLAGS], [
	AC_MSG_CHECKING([if $CC supports $1 flag])
	old_AM_CFLAGS="$AM_CFLAGS"
	AM_CFLAGS="$AM_CFLAGS $1"
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([], [])],
		AC_MSG_RESULT(yes), [
			AC_MSG_RESULT(no)
			AM_CFLAGS="$old_AM_CFLAGS"
		])
])
CC_ADD_CHECK_FLAGS([-Wall])
CC_ADD_CHECK_FLAGS([-Wextra])
CC_ADD_CHECK_FLAGS([-Wmissing-declarations])
CC_ADD_CHECK_FLAGS([-Wmissing-prototypes])
CC_ADD_CHECK_FLAGS([-Wstrict-prototypes])
CC_ADD_CHECK_FLAGS([-Wwrite-strings])
CC_ADD_CHECK_FLAGS([-Wno-unused-parameter])
CC_ADD_CHECK_FLAGS([-Wpointer-arith])
CC_ADD_CHECK_FLAGS([-Wsign-compare])
CC_ADD_CHECK_FLAGS([-Wcast-align])
CC_ADD_CHECK_FLAGS([-Wno-pointer-sign])

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
	compat/Makefile
	contrib/Makefile
	kamictl/Makefile
	kamid/Makefile
	kamiftp/Makefile
	kamiproxy/Makefile
	kamirepl/Makefile
	ninepscript/Makefile
	regress/Makefile
	regress/lisp/Makefile
	regress/ninepscript/Makefile
])

AC_OUTPUT
