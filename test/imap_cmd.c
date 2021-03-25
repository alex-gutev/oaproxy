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
#include "imap_cmd.h"

/* Test Macros */

#define assert_write(fd, str) {                             \
        if (!write_data(fd, str, strlen(str))) {            \
            fail_msg("Error writing command to socket");    \
        }                                                   \
    }

/**
 * Write an entire block of data.
 *
 * @param fd Socket file descriptor.
 * @param buf Buffer to write.
 * @param n Number of bytes in buffer to write.
 *
 * @return True if the entire buffer was written to the socket
 *   successfully, false if there was an error.
 */
static bool write_data(int fd, const char *buf, size_t n) {
    while (n) {
        ssize_t bytes = write(fd, buf, n);

        if (bytes < 0) {
            return false;
        }

        n -= bytes;
        buf += bytes;
    }

    return true;
}


/* Test Fixture */

#define imap_cmd_unit_test(f) cmocka_unit_test_setup_teardown(f, imap_test_setup, imap_test_teardown)

struct test_state {
    // Client side socket
    int c_fd;

    // IMAP Command Stream
    struct imap_cmd_stream *stream;
};

static int imap_test_setup(void ** state) {
    int sv[2];

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
        return 1;
    }

    struct test_state *tstate = xmalloc(sizeof(struct test_state));

    tstate->c_fd = sv[0];

    tstate->stream = imap_cmd_stream_create(sv[1]);
    if (!tstate->stream) {
        close(sv[0]);
        close(sv[1]);
        return 1;
    }

    *state = tstate;

    return 0;
}

static int imap_test_teardown(void ** state) {
    struct test_state *tstate = *state;

    if (tstate->stream) imap_cmd_stream_free(tstate->stream);
    if (tstate->c_fd >= 0) close(tstate->c_fd);

    free(tstate);
    *state = NULL;

    return 0;
}


/* Tests */

static void test_imap_cap(void ** state) {
    struct test_state *tstate = *state;

    const char *str_cmd = "a001 CAPABILITY\r\n";
    size_t cmd_len = strlen(str_cmd);

    const char *tag = "a001";
    size_t tag_len = strlen(tag);

    // Write CAPABILITY command from client
    assert_write(tstate->c_fd, str_cmd);

    // Read command
    struct imap_cmd cmd;
    ssize_t n = imap_cmd_next(tstate->stream, &cmd, true);

    // Check return value and command type
    assert_int_equal(n, cmd_len);
    assert_int_equal(cmd.command, IMAP_CMD);

    // Check command line and length
    assert_string_equal(cmd.line, str_cmd);
    assert_int_equal(cmd.total_len, cmd_len);

    // Check command tag
    assert_int_equal(cmd.tag_len, tag_len);
    assert_memory_equal(cmd.tag, tag, tag_len);
}

static void test_imap_login1(void ** state) {
    struct test_state *tstate = *state;

    const char *str_cmd = "1 LOGIN user2@mail.com password\r\n";
    size_t cmd_len = strlen(str_cmd);

    const char *tag = "1";
    size_t tag_len = strlen(tag);

    const char *param = "user2@mail.com password\r\n";
    size_t param_len = strlen(param) - 2;

    // Write LOGIN command from client
    assert_write(tstate->c_fd, str_cmd);

    // Read command
    struct imap_cmd cmd;
    ssize_t n = imap_cmd_next(tstate->stream, &cmd, true);

    // Check return value and command type
    assert_int_equal(n, cmd_len);
    assert_int_equal(cmd.command, IMAP_CMD_LOGIN);

    // Check command line and length
    assert_int_equal(cmd.total_len, cmd_len);
    assert_string_equal(cmd.line, str_cmd);

    // Check command tag
    assert_int_equal(cmd.tag_len, tag_len);
    assert_memory_equal(cmd.tag, tag, tag_len);

    // Check command parameters
    assert_int_equal(cmd.param_len, param_len);
    assert_string_equal(cmd.param, param);
}

static void test_imap_login2(void ** state) {
    struct test_state *tstate = *state;

    const char *str_cmd = "tag2 login user@example.com pass123\r\n";
    size_t cmd_len = strlen(str_cmd);

    const char *tag = "tag2";
    size_t tag_len = strlen(tag);

    const char *param = "user@example.com pass123\r\n";
    size_t param_len = strlen(param) - 2;

    // Write LOGIN command from client
    assert_write(tstate->c_fd, str_cmd);

    // Read command
    struct imap_cmd cmd;
    ssize_t n = imap_cmd_next(tstate->stream, &cmd, true);

    // Check return value and command type
    assert_int_equal(n, cmd_len);
    assert_int_equal(cmd.command, IMAP_CMD_LOGIN);

    // Check command line and length
    assert_int_equal(cmd.total_len, cmd_len);
    assert_string_equal(cmd.line, str_cmd);

    // Check command tag
    assert_int_equal(cmd.tag_len, tag_len);
    assert_memory_equal(cmd.tag, tag, tag_len);

    // Check command parameters
    assert_int_equal(cmd.param_len, param_len);
    assert_string_equal(cmd.param, param);
}


/* Parsing Functions */

static void test_parse_string1(void ** state) {
    const char *str = "user@example.com";

    assert_string_equal(imap_parse_string(str, strlen(str)), str);
}

static void test_parse_string2(void ** state) {
    const char *str = "user@example.com password";
    const char *exp = "user@example.com";

    assert_string_equal(imap_parse_string(str, strlen(str)), exp);
}

static void test_parse_string3(void ** state) {
    const char *str = "\"a \\\"quoted\\\" string\"";
    const char *exp = "a \"quoted\" string";

    assert_string_equal(imap_parse_string(str, strlen(str)), exp);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        imap_cmd_unit_test(test_imap_cap),
        imap_cmd_unit_test(test_imap_login1),
        imap_cmd_unit_test(test_imap_login2),

        cmocka_unit_test(test_parse_string1),
        cmocka_unit_test(test_parse_string2),
        cmocka_unit_test(test_parse_string3)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
