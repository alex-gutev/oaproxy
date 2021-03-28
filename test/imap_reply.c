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

#include <cmocka.h>

#include "xmalloc.h"
#include "imap_reply.h"

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

#define imap_reply_unit_test(f) cmocka_unit_test_setup_teardown(f, imap_test_setup, imap_test_teardown)

struct test_state {
    // Server side socket
    int s_fd;

    // Server BIO stream
    BIO *s_bio;

    // IMAP Command Stream
    struct imap_reply_stream *stream;
};

static int imap_test_setup(void ** state) {
    int sv[2];

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) {
        return 1;
    }

    struct test_state *tstate = xmalloc(sizeof(struct test_state));

    tstate->s_fd = sv[0];

    // Create client side BIO
    tstate->s_bio = BIO_new_socket(sv[1], true);

    if (!tstate->s_bio) {
        close(sv[1]);
        goto close_s_fd;
    }

    tstate->stream = imap_reply_stream_create(tstate->s_bio);;
    if (!tstate->stream) {
        goto close_bio;
    }

    *state = tstate;
    return 0;

close_bio:
    BIO_free_all(tstate->s_bio);

close_s_fd:
    close(tstate->s_fd);

    return 1;
}

static int imap_test_teardown(void ** state) {
    struct test_state *tstate = *state;

    if (tstate->stream) imap_reply_stream_free(tstate->stream);
    if (tstate->s_fd >= 0) close(tstate->s_fd);
    if (tstate->s_bio) BIO_free_all(tstate->s_bio);

    free(tstate);
    *state = NULL;

    return 0;
}


/* Tests */

/* Simple Replies */

static void test_reply_untagged(void ** state) {
    struct test_state *tstate = *state;

    const char *str_reply = "* OK imap ready for requests from localhost\r\n";
    size_t reply_len = strlen(str_reply);

    // Write reply
    assert_write(tstate->s_fd, str_reply);

    // Read reply
    struct imap_reply reply;
    ssize_t n = imap_reply_next(tstate->stream, &reply, true);

    // Check length
    assert_int_equal(n, reply_len);

    // Check reply code
    assert_int_equal(reply.code, IMAP_REPLY);

    // Check reply type
    assert_int_equal(reply.type, IMAP_REPLY_UNTAGGED);

    // Check reply
    assert_int_equal(reply.total_len, n);
    assert_string_equal(reply.line, str_reply);

    // Check tag length
    assert_int_equal(reply.tag_len, 1);
}

static void test_reply_tagged(void ** state) {
    struct test_state *tstate = *state;

    const char *str_reply = "a123 OK Thats all she wrote!\r\n";
    size_t reply_len = strlen(str_reply);

    const char *tag = "a123";
    size_t tag_len = strlen(tag);

    // Write reply
    assert_write(tstate->s_fd, str_reply);

    // Read reply
    struct imap_reply reply;
    ssize_t n = imap_reply_next(tstate->stream, &reply, true);

    // Check length
    assert_int_equal(n, reply_len);

    // Check reply code
    assert_int_equal(reply.code, IMAP_REPLY);

    // Check reply type
    assert_int_equal(reply.type, IMAP_REPLY_TAGGED);

    // Check reply
    assert_int_equal(reply.total_len, n);
    assert_string_equal(reply.line, str_reply);

    // Check tag length
    assert_int_equal(reply.tag_len, tag_len);
}

static void test_reply_cont(void ** state) {
    struct test_state *tstate = *state;

    const char *str_reply = "+ Ready for additional command text\r\n";
    size_t reply_len = strlen(str_reply);

    // Write reply
    assert_write(tstate->s_fd, str_reply);

    // Read reply
    struct imap_reply reply;
    ssize_t n = imap_reply_next(tstate->stream, &reply, true);

    // Check length
    assert_int_equal(n, reply_len);

    // Check reply code
    assert_int_equal(reply.code, IMAP_REPLY);

    // Check reply type
    assert_int_equal(reply.type, IMAP_REPLY_CONT);

    // Check reply
    assert_int_equal(reply.total_len, n);
    assert_string_equal(reply.line, str_reply);

    // Check tag length
    assert_int_equal(reply.tag_len, 1);
}

/* Main Function */

int main(void) {
    const struct CMUnitTest tests[] = {
        imap_reply_unit_test(test_reply_untagged),
        imap_reply_unit_test(test_reply_tagged),
        imap_reply_unit_test(test_reply_cont)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
