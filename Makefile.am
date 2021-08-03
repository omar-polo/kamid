# TODO: 9ps should be only built for tests
bin_PROGRAMS =		kamictl kamid kamirepl ninepscript

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

kamirepl_SOURCES =	kamid.h		\
			kamirepl.c	\
			log.c		\
			log.h		\
			utils.c		\
			utils.h

ninepscript_SOURCES =	log.c		\
			log.h		\
			np.y		\
			script.c	\
			script.h	\
			utils.c		\
			utils.h

LDADD =			$(LIBOBJS)

BUILT_SOURCES =		compile_flags.txt
CLEANFILES =		compile_flags.txt

dist_doc_DATA =		README.md LICENSE
dist_man5_MANS =	kamid.conf.5
dist_man7_MANS =	9p.7
dist_man8_MANS =	kamictl.8 kamid.8

compile_flags.txt:
	printf "%s\n" ${CFLAGS} > compile_flags.txt
