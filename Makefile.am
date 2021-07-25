bin_PROGRAMS =		kamictl kamid kamirelp

kamictl_SOURCES =	compat.h	\
			compat/*.[ch]	\
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
			compat/*.[ch]	\
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

LDADD =			$(LIBOBJS)

BUILT_SOURCES =		compile_flags.txt
CLEANFILES =		compile_flags.txt

dist_doc_DATA =		README.md LICENSE
dist_man5_MANS =	kamid.conf.5
dist_man8_MANS =	kamictl.8 kamid.8

compile_flags.txt:
	printf "%s\n" ${CFLAGS} > compile_flags.txt
