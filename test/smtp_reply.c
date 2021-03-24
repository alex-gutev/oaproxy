#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <string.h>
#include <stdlib.h>

#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <openssl/bio.h>
#include <cmocka.h>

#include "xmalloc.h"
#include "smtp_reply.h"

#define smtp_reply_unit_test(f) cmocka_unit_test_setup_teardown(f, smtp_test_setup, smtp_test_teardown)

struct test_state {
    // Server side socket
    int s_fd;

    // SMTP Command Stream
    struct smtp_reply_stream *stream;
};

static int smtp_test_setup(void ** state) {
    int sv[2];

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
        return 1;
    }

    struct test_state *tstate = xmalloc(sizeof(struct test_state));

    tstate->s_fd = sv[0];

    // Create client side BIO

    BIO *c_bio = BIO_new_socket(sv[1], true);

    if (!c_bio) {
        close(sv[1]);
        goto close_s_fd;
    }

    tstate->stream = smtp_reply_stream_create(c_bio);
    if (!tstate->stream) {
        goto close_bio;
    }

    *state = tstate;
    return 0;

close_bio:
    BIO_free_all(c_bio);

close_s_fd:
    close(tstate->s_fd);

    return 1;
}

static int smtp_test_teardown(void ** state) {
    struct test_state *tstate = *state;

    smtp_reply_stream_free(tstate->stream);

    if (tstate->s_fd >= 0) close(tstate->s_fd);

    free(tstate);
    *state = NULL;

    return 0;
}

/* Test Functions */

/* Simple Replies */

static void test_reply_server_id(void ** state) {
    struct test_state *tstate = *state;

    // Write server identification reply
    char str_reply[] = "220 smtp.example.com ESMTP\r\n";
    size_t reply_len = strlen(str_reply);

    if (write(tstate->s_fd, str_reply, reply_len) < reply_len) {
        fail_msg("Error writing reply to socket");
    }

    // Read reply
    struct smtp_reply reply;
    ssize_t n = smtp_reply_next(tstate->stream, &reply);

    assert_int_equal(n, reply_len);

    // Check Lengths
    assert_string_equal(reply.data, str_reply);
    assert_int_equal(reply.total_len, reply_len);
    assert_int_equal(reply.data_len, reply_len - 2);

    // Parse
    assert_true(smtp_reply_parse(&reply));

    // Check code
    assert_int_equal(reply.code, 220);

    // Check type
    assert_int_equal(reply.type, SMTP_REPLY);

    // Check message
    assert_string_equal(reply.msg, "smtp.example.com ESMTP\r\n");

    // Check last flag
    assert_true(reply.last);
}

/* Multi-line replies */

static void test_reply_multi1(void ** state) {
    struct test_state *tstate = *state;

    // Write server identification reply
    char str_reply[] = "250-smtp.example.com at your service.\r\n"
        "250 SIZE 35882577\r\n";
    size_t reply_len = strlen(str_reply);

    char exp_reply[] = "250-smtp.example.com at your service.\r\n";
    size_t exp_len = strlen(exp_reply);

    if (write(tstate->s_fd, str_reply, reply_len) < reply_len) {
        fail_msg("Error writing reply to socket");
    }

    // Read reply
    struct smtp_reply reply;
    ssize_t n = smtp_reply_next(tstate->stream, &reply);

    assert_int_equal(n, exp_len);

    // Check Lengths
    assert_string_equal(reply.data, exp_reply);
    assert_int_equal(reply.total_len, exp_len);
    assert_int_equal(reply.data_len, exp_len - 2);

    // Parse
    assert_true(smtp_reply_parse(&reply));

    // Check code
    assert_int_equal(reply.code, 250);

    // Check type
    assert_int_equal(reply.type, SMTP_REPLY);

    // Check message
    assert_string_equal(reply.msg, "smtp.example.com at your service.\r\n");

    // Check last flag
    assert_false(reply.last);
}
static void test_reply_multi2(void ** state) {
    struct test_state *tstate = *state;

    // Write server identification reply
    char str_reply[] = "250-smtp.example.com at your service.\r\n"
        "250 SIZE 35882577\r\n";
    size_t reply_len = strlen(str_reply);

    char exp_reply[] = "250 SIZE 35882577\r\n";
    size_t exp_len = strlen(exp_reply);

    if (write(tstate->s_fd, str_reply, reply_len) < reply_len) {
        fail_msg("Error writing reply to socket");
    }

    // Read reply
    struct smtp_reply reply;
    ssize_t n = smtp_reply_next(tstate->stream, &reply);
    n = smtp_reply_next(tstate->stream, &reply);

    assert_int_equal(n, exp_len);

    // Check Lengths
    assert_string_equal(reply.data, exp_reply);
    assert_int_equal(reply.total_len, exp_len);
    assert_int_equal(reply.data_len, exp_len - 2);

    // Parse
    assert_true(smtp_reply_parse(&reply));

    // Check code
    assert_int_equal(reply.code, 250);

    // Check type
    assert_int_equal(reply.type, SMTP_REPLY);

    // Check message
    assert_string_equal(reply.msg, "SIZE 35882577\r\n");

    // Check last flag
    assert_true(reply.last);
}

/* AUTH Replies */

static void test_reply_auth1(void ** state) {
    struct test_state *tstate = *state;

    // Write server identification reply
    char str_reply[] = "250-AUTH PLAIN\r\n";
    size_t reply_len = strlen(str_reply);

    if (write(tstate->s_fd, str_reply, reply_len) < reply_len) {
        fail_msg("Error writing reply to socket");
    }

    // Read reply
    struct smtp_reply reply;
    ssize_t n = smtp_reply_next(tstate->stream, &reply);

    assert_int_equal(n, reply_len);

    // Check Lengths
    assert_string_equal(reply.data, str_reply);
    assert_int_equal(reply.total_len, reply_len);
    assert_int_equal(reply.data_len, reply_len - 2);

    // Parse
    assert_true(smtp_reply_parse(&reply));

    // Check code
    assert_int_equal(reply.code, 250);

    // Check type
    assert_int_equal(reply.type, SMTP_REPLY_AUTH);

    // Check message
    assert_string_equal(reply.msg, "AUTH PLAIN\r\n");

    // Check last flag
    assert_false(reply.last);
}
static void test_reply_auth2(void ** state) {
    struct test_state *tstate = *state;

    // Write server identification reply
    char str_reply[] = "250 AUTH LOGIN PLAIN\r\n";
    size_t reply_len = strlen(str_reply);

    if (write(tstate->s_fd, str_reply, reply_len) < reply_len) {
        fail_msg("Error writing reply to socket");
    }

    // Read reply
    struct smtp_reply reply;
    ssize_t n = smtp_reply_next(tstate->stream, &reply);

    assert_int_equal(n, reply_len);

    // Check Lengths
    assert_string_equal(reply.data, str_reply);
    assert_int_equal(reply.total_len, reply_len);
    assert_int_equal(reply.data_len, reply_len - 2);

    // Parse
    assert_true(smtp_reply_parse(&reply));

    // Check code
    assert_int_equal(reply.code, 250);

    // Check type
    assert_int_equal(reply.type, SMTP_REPLY_AUTH);

    // Check message
    assert_string_equal(reply.msg, "AUTH LOGIN PLAIN\r\n");

    // Check last flag
    assert_true(reply.last);
}
static void test_reply_auth3(void ** state) {
    struct test_state *tstate = *state;

    // Write server identification reply
    char str_reply[] = "250-auth plain\r\n";
    size_t reply_len = strlen(str_reply);

    if (write(tstate->s_fd, str_reply, reply_len) < reply_len) {
        fail_msg("Error writing reply to socket");
    }

    // Read reply
    struct smtp_reply reply;
    ssize_t n = smtp_reply_next(tstate->stream, &reply);

    assert_int_equal(n, reply_len);

    // Check Lengths
    assert_string_equal(reply.data, str_reply);
    assert_int_equal(reply.total_len, reply_len);
    assert_int_equal(reply.data_len, reply_len - 2);

    // Parse
    assert_true(smtp_reply_parse(&reply));

    // Check code
    assert_int_equal(reply.code, 250);

    // Check type
    assert_int_equal(reply.type, SMTP_REPLY_AUTH);

    // Check message
    assert_string_equal(reply.msg, "auth plain\r\n");

    // Check last flag
    assert_false(reply.last);
}

/* DATA Reply */

static void test_reply_data(void ** state) {
    struct test_state *tstate = *state;

    // Write server identification reply
    char str_reply[] = "354\r\n";
    size_t reply_len = strlen(str_reply);

    if (write(tstate->s_fd, str_reply, reply_len) < reply_len) {
        fail_msg("Error writing reply to socket");
    }

    // Read reply
    struct smtp_reply reply;
    ssize_t n = smtp_reply_next(tstate->stream, &reply);

    assert_int_equal(n, reply_len);

    // Check Lengths
    assert_string_equal(reply.data, str_reply);
    assert_int_equal(reply.total_len, reply_len);
    assert_int_equal(reply.data_len, reply_len - 2);

    // Parse
    assert_true(smtp_reply_parse(&reply));

    // Check code
    assert_int_equal(reply.code, 354);

    // Check type
    assert_int_equal(reply.type, SMTP_REPLY);

    // Check message
    assert_string_equal(reply.msg, "\r\n");

    // Check last flag
    assert_true(reply.last);
}

/* Malformed Replies */

static void test_reply_malformed1(void ** state) {
    struct test_state *tstate = *state;

    // Write server identification reply
    char str_reply[] = "220 smtp.example.com ESMTP\n";
    size_t reply_len = strlen(str_reply);

    if (write(tstate->s_fd, str_reply, reply_len) < reply_len) {
        fail_msg("Error writing reply to socket");
    }

    // Read reply
    struct smtp_reply reply;
    ssize_t n = smtp_reply_next(tstate->stream, &reply);

    assert_int_equal(n, reply_len);

    // Check Lengths
    assert_string_equal(reply.data, str_reply);
    assert_int_equal(reply.total_len, reply_len);
    assert_int_equal(reply.data_len, reply_len - 1);

    // Parse
    assert_true(smtp_reply_parse(&reply));

    // Check code
    assert_int_equal(reply.code, 220);

    // Check type
    assert_int_equal(reply.type, SMTP_REPLY);

    // Check message
    assert_string_equal(reply.msg, "smtp.example.com ESMTP\n");

    // Check last flag
    assert_true(reply.last);
}
static void test_reply_malformed2(void ** state) {
    struct test_state *tstate = *state;

    // Write server identification reply
    char str_reply[] = "220 smtp.example.com ESMTP";
    size_t reply_len = strlen(str_reply);

    if (write(tstate->s_fd, str_reply, reply_len) < reply_len) {
        fail_msg("Error writing reply to socket");
    }

    // Close to prevent read from blocking
    close(tstate->s_fd);
    tstate->s_fd = -1;

    // Read reply
    struct smtp_reply reply;
    ssize_t n = smtp_reply_next(tstate->stream, &reply);

    assert_int_equal(n, reply_len);

    // Check Lengths
    assert_string_equal(reply.data, str_reply);
    assert_int_equal(reply.total_len, reply_len);
    assert_int_equal(reply.data_len, reply_len);

    // Parse
    assert_true(smtp_reply_parse(&reply));

    // Check code
    assert_int_equal(reply.code, 220);

    // Check type
    assert_int_equal(reply.type, SMTP_REPLY);

    // Check message
    assert_string_equal(reply.msg, "smtp.example.com ESMTP");

    // Check last flag
    assert_true(reply.last);
}

static void test_reply_malformed3(void ** state) {
    struct test_state *tstate = *state;

    // Write server identification reply
    char str_reply[] = "12345 A malformed reply\r\n";
    size_t reply_len = strlen(str_reply);

    if (write(tstate->s_fd, str_reply, reply_len) < reply_len) {
        fail_msg("Error writing reply to socket");
    }

    // Read reply
    struct smtp_reply reply;
    ssize_t n = smtp_reply_next(tstate->stream, &reply);

    assert_int_equal(n, reply_len);

    // Check Lengths
    assert_string_equal(reply.data, str_reply);
    assert_int_equal(reply.total_len, reply_len);
    assert_int_equal(reply.data_len, reply_len - 2);

    // Parse
    assert_false(smtp_reply_parse(&reply));
}
static void test_reply_malformed4(void ** state) {
    struct test_state *tstate = *state;

    // Write server identification reply
    char str_reply[] = "12345A malformed reply\r\n";
    size_t reply_len = strlen(str_reply);

    if (write(tstate->s_fd, str_reply, reply_len) < reply_len) {
        fail_msg("Error writing reply to socket");
    }

    // Read reply
    struct smtp_reply reply;
    ssize_t n = smtp_reply_next(tstate->stream, &reply);

    assert_int_equal(n, reply_len);

    // Check Lengths
    assert_string_equal(reply.data, str_reply);
    assert_int_equal(reply.total_len, reply_len);
    assert_int_equal(reply.data_len, reply_len - 2);

    // Parse
    assert_false(smtp_reply_parse(&reply));
}


/* Main Function */

int main(void) {
    const struct CMUnitTest tests[] = {
        smtp_reply_unit_test(test_reply_server_id),
        smtp_reply_unit_test(test_reply_multi1),
        smtp_reply_unit_test(test_reply_multi2),
        smtp_reply_unit_test(test_reply_auth1),
        smtp_reply_unit_test(test_reply_auth2),
        smtp_reply_unit_test(test_reply_auth3),
        smtp_reply_unit_test(test_reply_data),
        smtp_reply_unit_test(test_reply_malformed1),
        smtp_reply_unit_test(test_reply_malformed2),
        smtp_reply_unit_test(test_reply_malformed3),
        smtp_reply_unit_test(test_reply_malformed4)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
