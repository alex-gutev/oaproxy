AM_DISTCHECK_CONFIGURE_FLAGS = \
  --with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

## Executable

bin_PROGRAMS = oaproxy

oaproxy_LDADD = $(PTHREAD_LIBS) $(GOA_LIBS) $(OPENSSL_LIBS)
oaproxy_CFLAGS = $(PTHREAD_CFLAGS) $(GOA_CFLAGS) $(OPENSSL_CFLAGS) -DSYSCONFDIR='"${sysconfdir}"'

oaproxy_SOURCES = src/main.c \
	src/xmalloc.c \
	src/xmalloc.h \
	src/b64.c \
	src/b64.h \
	src/xoauth2.c \
	src/xoauth2.h \
	src/ssl.c \
	src/ssl.h \
	src/gaccounts.c \
	src/gaccounts.h \
	src/smtp.c \
	src/smtp.h \
	src/smtp_reply.c \
	src/smtp_reply.h \
	src/smtp_cmd.c \
	src/smtp_cmd.h \
	src/imap.c \
	src/imap.h \
	src/imap_cmd.c \
	src/imap_cmd.h \
	src/imap_reply.c \
	src/imap_reply.h \
	src/server.c \
	src/server.h


## Configuration file

dist_sysconf_DATA = oaproxy.conf

## Service File

SERVICE_SUBS = s,[@]bindir[@],$(bindir),g

oaproxy.service: oaproxy.service.in
	$(SED) -e '$(SERVICE_SUBS)' < $< > $@

if HAVE_SYSTEMD
systemduserunit_DATA = oaproxy.service
endif

CLEANFILES = oaproxy.service
EXTRA_DIST = README.md oaproxy.service.in

## Testing

check_PROGRAMS = test-b64 test-xoauth2 test-smtp_cmd test-smtp_reply test-smtp test-imap-cmd test-imap-reply test-imap test-server

TESTS = test-b64 test-xoauth2 test-smtp_cmd test-smtp_reply test-smtp test-imap-cmd test-imap-reply test-imap test-server

# Base64 Encoding/Decoding Tests

test_b64_SOURCES = test/b64.c
test_b64_CFLAGS = -I$(top_srcdir)/src $(CMOCKA_CFLAGS)
test_b64_LDADD = $(CMOCKA_LIBS) \
	src/oaproxy-xmalloc.$(OBJEXT) \
	src/oaproxy-b64.$(OBJEXT)

# XOAUTH2 Token Generation Tests

test_xoauth2_SOURCES = test/xoauth2.c
test_xoauth2_CFLAGS = -I$(top_srcdir)/src $(CMOCKA_FLAGS)
test_xoauth2_LDADD = $(CMOCKA_LIBS) \
	src/oaproxy-xmalloc.$(OBJEXT) \
	src/oaproxy-b64.$(OBJEXT) \
	src/oaproxy-xoauth2.$(OBJEXT)

# SMTP Command Parser

test_smtp_cmd_SOURCES = test/smtp_cmd.c
test_smtp_cmd_CFLAGS = -I$(top_srcdir)/src $(CMOCKA_FLAGS) $(OPENSSL_CFLAGS)
test_smtp_cmd_LDADD = $(CMOCKA_LIBS) \
	src/oaproxy-xmalloc.$(OBJEXT) \
	src/oaproxy-smtp_cmd.$(OBJEXT) \
	 $(OPENSSL_LIBS)

# SMTP Server Reply Parser

test_smtp_reply_SOURCES = test/smtp_reply.c
test_smtp_reply_CFLAGS = -I$(top_srcdir)/src $(CMOCKA_FLAGS) $(OPENSSL_CFLAGS)
test_smtp_reply_LDADD = $(CMOCKA_LIBS) \
	src/oaproxy-xmalloc.$(OBJEXT) \
	src/oaproxy-ssl.$(OBJEXT) \
	src/oaproxy-smtp_reply.$(OBJEXT) \
	 $(OPENSSL_LIBS)

# SMTP Proxy Server

test_smtp_SOURCES = test/smtp.c
test_smtp_CFLAGS = -I$(top_srcdir)/src $(CMOCKA_FLAGS) $(OPENSSL_CFLAGS) $(GOA_CFLAGS)
test_smtp_LDADD = $(CMOCKA_LIBS) \
	src/oaproxy-xmalloc.$(OBJEXT) \
	src/oaproxy-ssl.$(OBJEXT) \
	src/oaproxy-b64.$(OBJEXT) \
	src/oaproxy-gaccounts.$(OBJEXT) \
	src/oaproxy-xoauth2.$(OBJEXT) \
	src/oaproxy-smtp_cmd.$(OBJEXT) \
	src/oaproxy-smtp_reply.$(OBJEXT) \
	src/oaproxy-smtp.$(OBJEXT) \
	 $(OPENSSL_LIBS) $(GOA_LIBS)

test_smtp_LDFLAGS = -Wl,--wrap=server_connect \
	-Wl,--wrap=find_goaccount \
	-Wl,--wrap=get_access_token

# IMAP Command Parser

test_imap_cmd_SOURCES = test/imap_cmd.c
test_imap_cmd_CFLAGS = -I$(top_srcdir)/src $(CMOCKA_FLAGS) $(OPENSSL_CFLAGS)
test_imap_cmd_LDADD = $(CMOCKA_LIBS) \
	src/oaproxy-xmalloc.$(OBJEXT) \
	src/oaproxy-imap_cmd.$(OBJEXT) \
	 $(OPENSSL_LIBS)

# IMAP Reply Parser

test_imap_reply_SOURCES = test/imap_reply.c
test_imap_reply_CFLAGS = -I$(top_srcdir)/src $(CMOCKA_FLAGS) $(OPENSSL_CFLAGS)
test_imap_reply_LDADD = $(CMOCKA_LIBS) \
	src/oaproxy-xmalloc.$(OBJEXT) \
	src/oaproxy-imap_reply.$(OBJEXT) \
	 $(OPENSSL_LIBS)

# IMAP Proxy Server

test_imap_SOURCES = test/imap.c
test_imap_CFLAGS = -I$(top_srcdir)/src $(CMOCKA_FLAGS) $(OPENSSL_CFLAGS) $(GOA_CFLAGS)
test_imap_LDADD = $(CMOCKA_LIBS) \
	src/oaproxy-xmalloc.$(OBJEXT) \
	src/oaproxy-ssl.$(OBJEXT) \
	src/oaproxy-b64.$(OBJEXT) \
	src/oaproxy-gaccounts.$(OBJEXT) \
	src/oaproxy-xoauth2.$(OBJEXT) \
	src/oaproxy-imap_cmd.$(OBJEXT) \
	src/oaproxy-imap_reply.$(OBJEXT) \
	src/oaproxy-imap.$(OBJEXT) \
	 $(OPENSSL_LIBS) $(GOA_LIBS)

test_imap_LDFLAGS = -Wl,--wrap=server_connect \
	-Wl,--wrap=find_goaccount \
	-Wl,--wrap=get_access_token


# Server Config Parser

test_server_SOURCES = test/server.c
test_server_CFLAGS = -I$(top_srcdir)/src $(CMOCKA_FLAGS) $(PTHREAD_CFLAGS) \
	-DCONF_TEST_DIR='"${top_srcdir}/test/conf/"'

test_server_LDADD = $(CMOCKA_LIBS) \
	src/oaproxy-xmalloc.$(OBJEXT) \
	src/oaproxy-ssl.$(OBJEXT) \
	src/oaproxy-b64.$(OBJEXT) \
	src/oaproxy-gaccounts.$(OBJEXT) \
	src/oaproxy-xoauth2.$(OBJEXT) \
	src/oaproxy-smtp_cmd.$(OBJEXT) \
	src/oaproxy-smtp_reply.$(OBJEXT) \
	src/oaproxy-smtp.$(OBJEXT) \
	src/oaproxy-imap_cmd.$(OBJEXT) \
	src/oaproxy-imap_reply.$(OBJEXT) \
	src/oaproxy-imap.$(OBJEXT) \
	src/oaproxy-server.$(OBJEXT) \
	$(OPENSSL_LIBS) $(GOA_LIBS) $(PTHREAD_LIBS)

test_server_LDFLAGS = -Wl,--wrap=socket \
	-Wl,--wrap=bind \
	-Wl,--wrap=listen

EXTRA_DIST += test/conf/test1.conf \
	test/conf/test2.conf \
	test/conf/test3.conf \
	test/conf/test4.conf
