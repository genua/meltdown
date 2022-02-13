PROG=		meltdown
MAN=		meltdown.8

# Meltdown is much more reliable to reproduce with static linking
LDFLAGS=	-nopie -static

CFLAGS+=	-W
CFLAGS+=	-Wall
CFLAGS+=	-Werror
CFLAGS+=	-Wno-unused-parameter
CFLAGS+=	-Wno-missing-field-initializers
CFLAGS+=	-Wno-unused-but-set-variable

.include <bsd.prog.mk>
