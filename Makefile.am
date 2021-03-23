AM_DISTCHECK_CONFIGURE_FLAGS = \
  --with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

## Executable

bin_PROGRAMS = oaproxy

oaproxy_LDADD = $(PTHREAD_LIBS) $(GOA_LIBS) $(OPENSSL_LIBS)
oaproxy_CFLAGS = $(PTHREAD_CFLAGS) $(GOA_CFLAGS) $(OPENSSL_CFLAGS) -DSYSCONFDIR='"${sysconfdir}"'

oaproxy_SOURCES = src/main.c \
	src/xmalloc.c \
	src/b64.c \
	src/xoauth2.c \
	src/ssl.c \
	src/gaccounts.c \
	src/smtp.c \
	src/smtp_reply.c \
	src/smtp_cmd.c \
	src/imap.c \
	src/imap_cmd.c \
	src/imap_reply.c \
	src/server.c


## Configuration file

dist_sysconf_DATA = oaproxy.conf

## Service File

SERVICE_SUBS = s,[@]bindir[@],$(bindir),g

oaproxy.service: oaproxy.service.in
	$(SED) -e '$(SERVICE_SUBS)' < $< > $@

if HAVE_SYSTEMD
systemduserunit_DATA = oaproxy.service
endif


## Testing

check_PROGRAMS = test-b64 test-xoauth2 test-smtp_cmd test-smtp_reply test-smtp

TESTS = test-b64 test-xoauth2 test-smtp_cmd test-smtp_reply test-smtp

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
