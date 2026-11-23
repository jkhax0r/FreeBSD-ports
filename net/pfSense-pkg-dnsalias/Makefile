PORTNAME=	pfSense-pkg-dnsalias
PORTVERSION=	0.2.57
CATEGORIES=	net
MASTER_SITES=
DISTFILES=

# Local review branch pending a public maintainer address and license.
MAINTAINER=	local@localhost
COMMENT=	Populate pfSense firewall aliases from observed Unbound replies

ONLY_FOR_ARCHS=	amd64
USES=		python:3.11
NO_MTREE=	yes
NO_WRKSUBDIR=	yes

SRC=		${FILESDIR}/src
MODULES=	replywire replyextract confirmation generation confirmationkey

.include <bsd.port.pre.mk>

.if ${PREFIX} != /usr/local
IGNORE=		requires the pfSense package prefix /usr/local
.endif
.if ${OSVERSION} < 1600000 || ${OSVERSION} >= 1700000
IGNORE=		requires the qualified FreeBSD 16 ABI
.endif

do-extract:
	${MKDIR} ${WRKDIR}

do-build:
.for module in ${MODULES}
	${CC} ${CPPFLAGS} ${CFLAGS} -std=gnu11 -fPIC -shared \
		-I${PYTHON_INCLUDEDIR} ${LDFLAGS} -o ${WRKDIR}/${module}.so \
		${SRC}/native/${module}.c
	${STRIP_CMD} ${WRKDIR}/${module}.so
.endfor
	${PYTHON_CMD} -B ${SRC}/tools/build.py ${WRKDIR}/payload.zip \
		--native-codec ${WRKDIR}/replywire.so \
		--native-extractor ${WRKDIR}/replyextract.so \
		--native-confirmation ${WRKDIR}/confirmation.so \
		--native-generation ${WRKDIR}/generation.so \
		--native-key ${WRKDIR}/confirmationkey.so

do-install:
	${PYTHON_CMD} -B ${FILESDIR}/stage_port.py ${WRKDIR}/payload.zip \
		${STAGEDIR}${PREFIX} ${PORTVERSION}

do-test:
	cd ${SRC} && ${PYTHON_CMD} -B -m unittest discover -s tests

.include <bsd.port.post.mk>
