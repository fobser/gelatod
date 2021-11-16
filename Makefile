#	$OpenBSD$

BINDIR?=	/usr/local/sbin
MANDIR?=	/usr/local/man/man
PROG=		gelatod
SRCS=		frontend.c log.c gelatod.c

MAN=		gelatod.8

#DEBUG=		-g -DDEBUG=3 -O0

CFLAGS+=	-Wall -I${.CURDIR}
CFLAGS+=	-Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=	-Wsign-compare
LDADD+=		-levent -lutil
DPADD+=		${LIBEVENT} ${LIBUTIL}

.include <bsd.prog.mk>
