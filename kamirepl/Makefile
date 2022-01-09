.PATH:${.CURDIR}/../lib

.include "../kamid-version.mk"

PROG=		kamirepl
SRCS=		9pclib.c kamirepl.c log.c utils.c

CPPFLAGS=	-I${.CURDIR}/../lib -I${.CURDIR}

LDADD+= -levent -lutil -ltls
DPADD+= ${LIBEVENT} ${LIBUTIL} ${LIBTLS}

.if ${KAMID_RELEASE} != Yes
NOMAN= Yes
.endif

.include <bsd.prog.mk>
