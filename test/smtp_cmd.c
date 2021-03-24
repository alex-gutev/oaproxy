#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <string.h>
#include <stdlib.h>

#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <cmocka.h>

#include "xmalloc.h"
#include "smtp_cmd.h"

#define smtp_cmd_unit_test(f) cmocka_unit_test_setup_teardown(f, smtp_test_setup, smtp_test_teardown)

struct test_state {
    // Client side socket
    int c_fd;

    // SMTP Command Stream
    struct smtp_cmd_stream *stream;
};

static int smtp_test_setup(void ** state) {
    int sv[2];

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
        return 1;
    }

    struct test_state *tstate = xmalloc(sizeof(struct test_state));

    tstate->c_fd = sv[0];

    tstate->stream = smtp_cmd_stream_create(sv[1]);
    if (!tstate->stream) {
        close(sv[0]);
        close(sv[1]);
        return 1;
    }

    *state = tstate;

    return 0;
}

static int smtp_test_teardown(void ** state) {
    struct test_state *tstate = *state;

    if (tstate->stream) smtp_cmd_stream_free(tstate->stream);
    if (tstate->c_fd >= 0) close(tstate->c_fd);

    free(tstate);
    *state = NULL;

    return 0;
}

/* Test Functions */

/* Simple Commands */

static void test_cmd_hello(void ** state) {
    struct test_state *tstate = *state;

    // Write EHLO command from client
    char str_cmd[] = "EHLO localhost\r\n";
    size_t cmd_len = strlen(str_cmd);

    if (write(tstate->c_fd, str_cmd, cmd_len) < cmd_len) {
        fail_msg("Error writing command to socket");
    }

    // Read command
    struct smtp_cmd cmd;
    ssize_t n = smtp_cmd_next(tstate->stream, &cmd);

    assert_int_equal(n, cmd_len);
    assert_int_equal(cmd.command, SMTP_CMD);

    assert_string_equal(cmd.line, str_cmd);
    assert_int_equal(cmd.total_len, cmd_len);
}

/* Multiple Commands */

static void test_multi_cmd1(void ** state) {
    struct test_state *tstate = *state;

    // Write EHLO command from client
    char str_cmd[] = "EHLO localhost\r\nAUTH PLAIN\r\n";
    size_t cmd_len = strlen(str_cmd);

    char exp_cmd[] = "EHLO localhost\r\n";
    size_t exp_len = strlen(exp_cmd);

    if (write(tstate->c_fd, str_cmd, cmd_len) < cmd_len) {
        fail_msg("Error writing command to socket");
    }

    // Read command
    struct smtp_cmd cmd;
    ssize_t n = smtp_cmd_next(tstate->stream, &cmd);

    // Check Command Type
    assert_int_equal(n, exp_len);
    assert_int_equal(cmd.command, SMTP_CMD);

    // Check Command Line
    assert_string_equal(cmd.line, exp_cmd);
    assert_int_equal(cmd.total_len, exp_len);
}
static void test_multi_cmd2(void ** state) {
    struct test_state *tstate = *state;

    // Write EHLO command from client
    char str_cmd[] = "EHLO localhost\r\nMAIL FROM <user@example.com>\r\n";
    size_t cmd_len = strlen(str_cmd);

    char exp_cmd[] = "MAIL FROM <user@example.com>\r\n";
    size_t exp_len = strlen(exp_cmd);

    if (write(tstate->c_fd, str_cmd, cmd_len) < cmd_len) {
        fail_msg("Error writing command to socket");
    }

    // Read command
    struct smtp_cmd cmd;
    ssize_t n = smtp_cmd_next(tstate->stream, &cmd);
    n = smtp_cmd_next(tstate->stream, &cmd);

    // Check Command Type
    assert_int_equal(n, exp_len);
    assert_int_equal(cmd.command, SMTP_CMD);

    // Check Command Line
    assert_string_equal(cmd.line, exp_cmd);
    assert_int_equal(cmd.total_len, exp_len);
}

/* AUTH PLAIN Command */

static void test_cmd_auth_plain(void ** state) {
    struct test_state *tstate = *state;

    // Write EHLO command from client
    char str_cmd[] = "AUTH PLAIN\r\n";
    size_t cmd_len = strlen(str_cmd);

    if (write(tstate->c_fd, str_cmd, cmd_len) < cmd_len) {
        fail_msg("Error writing command to socket");
    }

    // Read command
    struct smtp_cmd cmd;
    ssize_t n = smtp_cmd_next(tstate->stream, &cmd);

    assert_int_equal(n, cmd_len);
    assert_int_equal(cmd.command, SMTP_CMD_AUTH);

    assert_string_equal(cmd.line, str_cmd);
    assert_int_equal(cmd.total_len, cmd_len);

    assert_string_equal(cmd.data, "\r\n");
    assert_int_equal(cmd.data_len, 0);
}
static void test_cmd_auth_plain_data(void ** state) {
    struct test_state *tstate = *state;

    // Write EHLO command from client
    char str_cmd[] = "AUTH PLAIN abcdefghi\r\n";
    size_t cmd_len = strlen(str_cmd);

    if (write(tstate->c_fd, str_cmd, cmd_len) < cmd_len) {
        fail_msg("Error writing command to socket");
    }

    // Read command
    struct smtp_cmd cmd;
    ssize_t n = smtp_cmd_next(tstate->stream, &cmd);

    assert_int_equal(n, cmd_len);
    assert_int_equal(cmd.command, SMTP_CMD_AUTH);

    assert_string_equal(cmd.line, str_cmd);
    assert_int_equal(cmd.total_len, cmd_len);

    assert_string_equal(cmd.data, "abcdefghi\r\n");
    assert_int_equal(cmd.data_len, strlen("abcdefghi"));
}

/* Malformed Commands */

static void test_cmd_malformed1(void ** state) {
    struct test_state *tstate = *state;

    // Write EHLO command from client
    char str_cmd[] = "EHLO localhost\n";
    size_t cmd_len = strlen(str_cmd);

    if (write(tstate->c_fd, str_cmd, cmd_len) < cmd_len) {
        fail_msg("Error writing command to socket");
    }

    // Read command
    struct smtp_cmd cmd;
    ssize_t n = smtp_cmd_next(tstate->stream, &cmd);

    assert_int_equal(n, cmd_len);
    assert_int_equal(cmd.command, SMTP_CMD);

    assert_string_equal(cmd.line, str_cmd);
    assert_int_equal(cmd.total_len, cmd_len);
}
static void test_cmd_malformed2(void ** state) {
    struct test_state *tstate = *state;

    // Write EHLO command from client
    char str_cmd[] = "QUIT";
    size_t cmd_len = strlen(str_cmd);

    if (write(tstate->c_fd, str_cmd, cmd_len) < cmd_len) {
        fail_msg("Error writing command to socket");
    }

    // Close to prevent read from blocking
    close(tstate->c_fd);
    tstate->c_fd = -1;

    // Read command
    struct smtp_cmd cmd;
    ssize_t n = smtp_cmd_next(tstate->stream, &cmd);

    assert_int_equal(n, cmd_len);
    assert_int_equal(cmd.command, SMTP_CMD);

    assert_string_equal(cmd.line, str_cmd);
    assert_int_equal(cmd.total_len, cmd_len);
}

/* In Data State */

static void test_data_state(void ** state) {
    struct test_state *tstate = *state;

    // Write EHLO command from client
    char data[] = "Hello World.\nthis is message data";
    size_t data_len = strlen(data);

    const char *exp1 = "Hello World.\n";
    size_t exp1_len = strlen(exp1);

    const char *exp2 = "this is message data";
    size_t exp2_len = strlen(exp2);

    if (write(tstate->c_fd, data, data_len) < data_len) {
        fail_msg("Error writing command to socket");
    }

    // Close to prevent blocking
    close(tstate->c_fd);
    tstate->c_fd = -1;

    // Switch to data state
    smtp_cmd_stream_data_mode(tstate->stream, true);

    // Read first line
    struct smtp_cmd cmd;
    ssize_t n = smtp_cmd_next(tstate->stream, &cmd);

    assert_int_equal(n, exp1_len);
    assert_int_equal(cmd.command, SMTP_CMD);

    assert_string_equal(cmd.line, exp1);
    assert_int_equal(cmd.total_len, exp1_len);

    // Read second line
    n = smtp_cmd_next(tstate->stream, &cmd);

    assert_int_equal(n, exp2_len);
    assert_int_equal(cmd.command, SMTP_CMD);

    assert_string_equal(cmd.line, exp2);
    assert_int_equal(cmd.total_len, exp2_len);
}
static void test_data_state2(void ** state) {
    struct test_state *tstate = *state;

    // Write EHLO command from client
    char str_cmd[] = "EHLO localhost\r\nAUTH PLAIN\r\n";
    size_t cmd_len = strlen(str_cmd);

    char exp_cmd[] = "EHLO localhost\r\n";
    size_t exp_len = strlen(exp_cmd);

    if (write(tstate->c_fd, str_cmd, cmd_len) < cmd_len) {
        fail_msg("Error writing command to socket");
    }

    // Enter and exit data state
    smtp_cmd_stream_data_mode(tstate->stream, true);
    smtp_cmd_stream_data_mode(tstate->stream, false);

    // Read command
    struct smtp_cmd cmd;
    ssize_t n = smtp_cmd_next(tstate->stream, &cmd);

    // Check Command Type
    assert_int_equal(n, exp_len);
    assert_int_equal(cmd.command, SMTP_CMD);

    // Check Command Line
    assert_string_equal(cmd.line, exp_cmd);
    assert_int_equal(cmd.total_len, exp_len);
}

/* Main Function */

int main(void) {
    const struct CMUnitTest tests[] = {
        smtp_cmd_unit_test(test_cmd_hello),
        smtp_cmd_unit_test(test_multi_cmd1),
        smtp_cmd_unit_test(test_multi_cmd2),
        smtp_cmd_unit_test(test_cmd_auth_plain),
        smtp_cmd_unit_test(test_cmd_auth_plain_data),
        smtp_cmd_unit_test(test_cmd_malformed1),
        smtp_cmd_unit_test(test_cmd_malformed2),
        smtp_cmd_unit_test(test_data_state),
        smtp_cmd_unit_test(test_data_state2)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
