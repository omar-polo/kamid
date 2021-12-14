bin_PROGRAMS =		kamictl kamid kamiftp
check_PROGRAMS =	ninepscript
noinst_PROGRAMS =	kamirepl

EXTRA_kamid_SOURCES =	compat/ohash.h compat/imsg.h compat/queue.h compat/tree.h

kamictl_SOURCES =	compat.h	\
			ctl_parser.c	\
			ctl_parser.h	\
			kamictl.c	\
			kamid.h		\
			log.c		\
			log.h		\
			sandbox.c	\
			sandbox.h

kamid_SOURCES =		client.c	\
			client.h	\
			control.c	\
			control.h	\
			compat.h	\
			kamid.c		\
			kamid.h		\
			listener.c	\
			listener.h	\
			log.c		\
			log.h		\
			parse.y		\
			sandbox.c	\
			sandbox.h	\
			table.c		\
			table.h		\
			table_static.c	\
			utils.c		\
			utils.h

kamiftp_SOURCES =	9pclib.c	\
			9pclib.h	\
			ftp.c		\
			kamid.h		\
			log.c		\
			log.h		\
			utils.c		\
			utils.h

kamirepl_SOURCES =	9pclib.c	\
			9pclib.h	\
			kamid.h		\
			kamirepl.c	\
			log.c		\
			log.h		\
			utils.c		\
			utils.h

ninepscript_SOURCES =	client.c	\
			client.h	\
			compat.h	\
			log.c		\
			log.h		\
			np.y		\
			sandbox.c	\
			script.c	\
			script.h	\
			utils.c		\
			utils.h

AM_CFLAGS =		@AM_CFLAGS@
LDADD =			$(LIBOBJS)

kamiftp_LDFLAGS =	@KAMIFTP_LIBS@

BUILT_SOURCES =		compile_flags.txt
CLEANFILES =		compile_flags.txt

dist_doc_DATA =		README.md LICENSE
dist_man1_MANS =	kamiftp.1
dist_man5_MANS =	kamid.conf.5
dist_man7_MANS =	9p.7
dist_man8_MANS =	kamictl.8 kamid.8

EXTRA_DIST =		regress ninepscript.5 ninepscript.8
TESTS =			run-tests.sh
run-tests.sh:		ninepscript

compile_flags.txt:
	printf "%s\n" ${CFLAGS} > compile_flags.txt
