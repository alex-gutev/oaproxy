bin_PROGRAMS = oaproxy

oaproxy_LDADD = $(GOA_LIBS) $(OPENSSL_LIBS)
oaproxy_CFLAGS = $(GOA_CFLAGS) $(OPENSSL_CFLAGS)

oaproxy_SOURCES = src/main.c \
	src/xmalloc.c \
	src/b64.c \
	src/xoauth2.c \
	src/ssl.c \
	src/gaccounts.c \
	src/smtp.c \
	src/smtp_reply.c \
	src/smtp_cmd.c
