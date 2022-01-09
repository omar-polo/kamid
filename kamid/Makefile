.PATH:${.CURDIR}/../lib

.include "../kamid-version.mk"

PROG=		kamid
SRCS=		client.c control.c kamid.c listener.c log.c parse.y sandbox.c \
		table.c table_static.c utils.c
MAN=		kamid.conf.5 9p.7 kamid.8

CPPFLAGS=	-I${.CURDIR}/../lib -I${.CURDIR}

LDADD+= -levent -lutil -ltls
DPADD+= ${LIBEVENT} ${LIBUTIL} ${LIBTLS}

.if ${KAMID_RELEASE} != Yes
NOMAN= Yes
.endif

.include <bsd.prog.mk>
