.PATH:${.CURDIR}/../lib
.PATH:${.CURDIR}/../kamid

.include "../kamid-version.mk"

PROG=		ninepscript
SRCS=		client.c log.c parse.y sandbox.c script.c utils.c
MAN=		ninepscript.5 ninepscript.8

CPPFLAGS=	-I${.CURDIR}/../kamid/ \
		-I${.CURDIR}/../lib -I${.CURDIR}

LDADD+= -levent -lutil -ltls
DPADD+= ${LIBEVENT} ${LIBUTIL} ${LIBTLS}

NOMAN = Yes

.include <bsd.prog.mk>
