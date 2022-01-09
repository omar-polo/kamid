.PATH:${.CURDIR}/../lib

.include "../kamid-version.mk"

PROG=		kamiftp
SRCS=		9pclib.c ftp.c log.c utils.c
MAN=		kamiftp.1

CPPFLAGS=	-I${.CURDIR}/../lib -I${.CURDIR}

LDADD+= -levent -lutil -ltls
DPADD+= ${LIBEVENT} ${LIBUTIL} ${LIBTLS}

.if ${KAMID_RELEASE} != Yes
NOMAN= Yes
.endif

.include <bsd.prog.mk>
