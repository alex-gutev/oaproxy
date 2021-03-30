#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>

#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <cmocka.h>

#include "xmalloc.h"
#include "ssl.h"
#include "imap.h"

#include "gaccounts.h"

#define LOCAL_SERVER "localhost:123"

#define USER1_ID "user1@example.com"
#define USER1_TOK "tokuser1abc"

/* Mocked Functions */

/**
 * Wrapped server_connect function.
 *
 * If the host is equal to LOCAL_SERVER the mock return value is
 * returned.
 */
BIO *__real_server_connect(const char *host);
BIO *__wrap_server_connect(const char *host) {
    if (!strcmp(host, LOCAL_SERVER)) {
        return mock_ptr_type(BIO*);
    }

    return __real_server_connect(host);
}

GList *__wrap_find_goaccount(GList *accounts, const char *user) {
    if (!strcmp(user, USER1_ID)) {
        return g_list_prepend(NULL, USER1_TOK);
    }

    return NULL;
}

gchar *__wrap_get_access_token(GList *account, goa_error *gerr) {
    assert(account);
    return strdup(account->data);
}

/* Server Process Routine */

/**
 * Run the IMAP proxy server.
 *
 * Intended to be run from a forked process.
 *
 * @param c_fd Client socket file descriptor
 * @param s_bio Server BIO stream
 */
void run_server(int c_fd, BIO *s_bio) {
    will_return(__wrap_server_connect, s_bio);
    imap_handle_client(c_fd, LOCAL_SERVER);

    exit(EXIT_SUCCESS);
}


/* Test Fixtures */

/**
 * Unit test with the imap_test_setup and imap_test_teardown setup and
 * teardown functions.
 */
#define imap_unit_test(f) cmocka_unit_test_setup_teardown(f, imap_test_setup, imap_test_teardown)

struct test_state {
    /* Client socket file descriptor */
    int c_fd_in;
    /* Server socket file descriptor */
    int s_fd_in;

    /* Background process ID */
    pid_t proc;
};

static int imap_test_setup(void ** state) {
    // Create client sockets

    struct test_state *tstate = xmalloc(sizeof(struct test_state));
    int c_sv[2];
    int s_sv[2];

    // Create client socket pair

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, c_sv)) {
        goto free_state;
    }

    tstate->c_fd_in = c_sv[0];

    // Create server socket pair

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, s_sv))
        goto close_c_socks;

    tstate->s_fd_in = s_sv[0];

    // Create server BIO stream

    BIO *s_bio = BIO_new_socket(s_sv[1], true);

    if (!s_bio)
        goto close_s_socks;


    // Create proxy server process

    tstate->proc = fork();

    if (tstate->proc == -1) { // fork failed
        goto close_s_socks;
    }
    else if (!tstate->proc) { // proxy server process
        close(tstate->s_fd_in);
        close(tstate->c_fd_in);

        run_server(c_sv[1], s_bio);
    }

    // Test process

    close(c_sv[1]);
    close(s_sv[1]);

    BIO_free_all(s_bio);

    *state = tstate;

    return 0;

close_s_socks:
    close(s_sv[0]);
    close(s_sv[1]);

close_c_socks:
    close(c_sv[0]);
    close(c_sv[1]);

free_state:
    free(tstate);
    return 1;
}

static int imap_test_teardown(void ** state) {
    struct test_state *tstate = *state;

    // Close sockets if open
    if (tstate->c_fd_in >= 0) close(tstate->c_fd_in);
    if (tstate->s_fd_in >= 0) close(tstate->s_fd_in);

    // Kill proxy server process if still running
    if (tstate->proc)
        kill(tstate->proc, SIGKILL);

    free(tstate);
    *state = NULL;

    return 0;
}

/**
 * Wait for the proxy server to finish and return status code.
 *
 * @param state Test state.
 *
 * @return Server status code.
 */
static int imap_exit_status(struct test_state *state) {
    if (state->c_fd_in) {
        shutdown(state->c_fd_in, SHUT_RDWR);
        close(state->c_fd_in);
    }

    if (state->s_fd_in) {
        shutdown(state->s_fd_in, SHUT_RDWR);
        close(state->s_fd_in);
    }

    state->c_fd_in = state->s_fd_in = -1;

    int status;
    assert_int_not_equal(waitpid(state->proc, &status, 0), -1);

    state->proc = 0;

    return status;
}



/* IO Functions */

/**
 * Read a block of data of at least a given size.
 *
 * @param fd Socket file descriptor.
 * @param buf Buffer in which to read data.
 * @param size Size of buffer (maximum amount of data to read).
 * @param min Minimum number of bytes to read.
 *
 * @param Total number of bytes read, -1 if there was an error.
 */
static ssize_t read_data(int fd, char *buf, size_t size, size_t min) {
    size_t total = 0;
    while (total < min) {
        fd_set rfds;

        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);

        struct timeval tv;
        tv.tv_sec = 10;
        tv.tv_usec = 0;

        // Wait for data to be arrive with a timeout.
        if (select(fd + 1, &rfds, NULL, NULL, &tv) < 0)
            return -1;

        if (!FD_ISSET(fd, &rfds)) {
            break;
        }

        ssize_t n = read(fd, buf, size);

        if (n < 0) return n;
        if (n == 0) {
            break;
        }

        total += n;
        size -= n;
        buf += n;
    }

    return total;
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


/* Test Macros */

/**
 * Write a block of data to the socket, using write_data(), and assert
 * that the data was written.
 *
 * @param fd Socket file descriptor
 * @param data Buffer to write
 * @param len Number of bytes in buffer to write
 */
#define assert_write(fd, data, len) assert_true(write_data((fd), (data), (len)))

/**
 * Assert that a given string is read from a socket.
 *
 * @param fd Socket file descriptor
 *
 * @param buf Buffer into which to read data from socket
 *
 * @param str Expected string. The data read from the buffer is
 *   compared to this string.
 */
#define assert_read(fd, buf, str) {                                     \
        ssize_t n = read_data((fd), (buf), sizeof(buf)-1, strlen(str)); \
        printf("read: %s\n", buf); \
        assert_int_equal(n, strlen(str));                               \
        (buf)[n] = 0;                                                   \
        assert_string_equal((buf), (str));                              \
    }

/**
 * Test that a given string written to an input socket is read from
 * the output socket.
 *
 * @param ifd Input socket to write string to.
 * @param ofd Output socket to read string from.
 * @param istr Input string to write.
 * @param ostr Expected output string.
 */
#define test_proxy2(ifd, ofd, istr, ostr) {         \
        char out[500];                              \
        assert_write(ifd, (istr), strlen(istr));    \
        assert_read(ofd, out, (ostr));              \
    }

/**
 * Test that a given string written to an input socket is read from
 * the output socket.
 *
 * @param ifd Input socket to write string to.
 * @param ofd Output socket to read string from.
 * @param data String to write.
 */
#define test_proxy(ifd, ofd, data) test_proxy2(ifd, ofd, data, data)


/* Test simple forwarding */

static void test_simple_proxy(void ** state) {
    struct test_state *tstate = *state;

    // Write initial server reply

    test_proxy(tstate->s_fd_in, tstate->c_fd_in, "* OK imap ready for requests from localhost\r\n");

    // Write first client command

    test_proxy(tstate->c_fd_in, tstate->s_fd_in, "tag1 CAPABILITY\r\n");

    // Write next server replies

    test_proxy(tstate->s_fd_in, tstate->c_fd_in,
               "* CAPABILITY IMAP4 UNSELECT IDLE\r\n"
               "tag1 OK Thats all she wrote!\r\n");

    // Write logout command

    test_proxy(tstate->c_fd_in, tstate->s_fd_in, "tag2 LOGOUT\r\n");

    // Write logout response

    test_proxy(tstate->s_fd_in, tstate->c_fd_in,
               "* BYE server terminating connection\r\n"
               "tag2 OK LOGOUT completed\r\n");

    // Check exit status
    assert_int_equal(imap_exit_status(tstate), 0);
}


/* Capability Replies */

static void test_capability_reply1(void ** state) {
    struct test_state *tstate = * state;

    // Write initial server reply

    test_proxy(tstate->s_fd_in, tstate->c_fd_in, "* OK imap ready for requests from localhost\r\n");

    // Write capability command

    test_proxy(tstate->c_fd_in, tstate->s_fd_in, "t0001 capability\r\n");

    // Write capability response

    test_proxy2(tstate->s_fd_in, tstate->c_fd_in,
                "* CAPABILITY IMAP4rev1 UNSELECT IDLE NAMESPACE AUTH=PLAIN AUTH=XOAUTH2 LOGINDISABLED\r\n"
               "t0001 OK Thats all she wrote!\r\n",
                "* CAPABILITY IMAP4rev1 UNSELECT IDLE NAMESPACE\r\n"
               "t0001 OK Thats all she wrote!\r\n");

    // Write logout command

    test_proxy(tstate->c_fd_in, tstate->s_fd_in, "t0002 logout\r\n");

    // Write logout response

    test_proxy(tstate->s_fd_in, tstate->c_fd_in,
               "* BYE server terminating connection\r\n"
               "t0002 OK LOGOUT completed\r\n");

    // Check exit status
    assert_int_equal(imap_exit_status(tstate), 0);
}

static void test_capability_reply2(void ** state) {
    struct test_state *tstate = * state;

    // Write initial server reply

    test_proxy(tstate->s_fd_in, tstate->c_fd_in, "* OK imap ready for requests from localhost\r\n");

    // Write capability command

    test_proxy(tstate->c_fd_in, tstate->s_fd_in, "t0001 capability\r\n");

    // Write capability response

    test_proxy2(tstate->s_fd_in, tstate->c_fd_in,
                "* CAPABILITY IMAP4rev1 auth=plain UNSELECT AUTH=XOAUTH2 IDLE logindisabled NAMESPACE\r\n"
               "t0001 OK Thats all she wrote!\r\n",
                "* CAPABILITY IMAP4rev1 UNSELECT IDLE NAMESPACE\r\n"
               "t0001 OK Thats all she wrote!\r\n");

    // Write logout command

    test_proxy(tstate->c_fd_in, tstate->s_fd_in, "t0002 logout\r\n");

    // Write logout response

    test_proxy(tstate->s_fd_in, tstate->c_fd_in,
               "* BYE server terminating connection\r\n"
               "t0002 OK LOGOUT completed\r\n");

    // Check exit status
    assert_int_equal(imap_exit_status(tstate), 0);
}


/* LOGIN Commands */

static void test_login_cmd1(void ** state) {
    struct test_state *tstate = * state;

    // Write initial server reply

    test_proxy(tstate->s_fd_in, tstate->c_fd_in, "* OK imap ready for requests from localhost\r\n");

    // Write LOGIN command

    test_proxy2(tstate->c_fd_in, tstate->s_fd_in,
                "a001 LOGIN user1@example.com\r\n",
                "a001 AUTHENTICATE XOAUTH2 dXNlcj11c2VyMUBleGFtcGxlLmNvbQFhdXRoPUJlYXJlciB0b2t1c2VyMWFiYwEB\r\n");

    // Write authenticate response

    test_proxy(tstate->c_fd_in, tstate->s_fd_in,
               "* CAPABILITY IMAP4 IDLE NAMESPACE\r\n"
               "a001 OK user1@example.com authenticated (Success)\r\n");

    // Write logout command

    test_proxy(tstate->c_fd_in, tstate->s_fd_in, "a002 logout\r\n");

    // Write logout response

    test_proxy(tstate->s_fd_in, tstate->c_fd_in,
               "* BYE server terminating connection\r\n"
               "a002 OK LOGOUT completed\r\n");

    // Check exit status
    assert_int_equal(imap_exit_status(tstate), 0);
}

static void test_login_cmd2(void ** state) {
    struct test_state *tstate = * state;

    // Write initial server reply

    test_proxy(tstate->s_fd_in, tstate->c_fd_in, "* OK imap ready for requests from localhost\r\n");

    // Write LOGIN command

    test_proxy2(tstate->c_fd_in, tstate->s_fd_in,
                "tg1 LOGIN \"user1@example.com\" dummypass\r\n"
                "tg2 SELECT \"INBOX\"\r\n",
                "tg1 AUTHENTICATE XOAUTH2 dXNlcj11c2VyMUBleGFtcGxlLmNvbQFhdXRoPUJlYXJlciB0b2t1c2VyMWFiYwEB\r\n"
                "tg2 SELECT \"INBOX\"\r\n");

    // Write authenticate response

    test_proxy(tstate->c_fd_in, tstate->s_fd_in,
               "* CAPABILITY IMAP4 IDLE NAMESPACE\r\n"
               "tg1 OK user1@example.com authenticated (Success)\r\n");

    // Write SELECT response

    test_proxy(tstate->s_fd_in, tstate->c_fd_in,
               "* 5000 EXISTS\r\n"
               "* 1 RECENT\r\n"
               "tg2 OK [READ-WRITE] INBOX selected. (Success)\r\n");

    // Write logout command

    test_proxy(tstate->c_fd_in, tstate->s_fd_in, "tg3 logout\r\n");

    // Write logout response

    test_proxy(tstate->s_fd_in, tstate->c_fd_in,
               "* BYE server terminating connection\r\n"
               "tg3 OK LOGOUT completed\r\n");

    // Check exit status
    assert_int_equal(imap_exit_status(tstate), 0);
}

static void test_login_cmd3(void ** state) {
    struct test_state *tstate = * state;

    // Write initial server reply

    test_proxy(tstate->s_fd_in, tstate->c_fd_in, "* OK imap ready for requests from localhost\r\n");

    // Write LOGIN command

    test_proxy2(tstate->c_fd_in, tstate->s_fd_in,
                "t001 login user1@example.com dummypass2\r\n",
                "t001 AUTHENTICATE XOAUTH2 dXNlcj11c2VyMUBleGFtcGxlLmNvbQFhdXRoPUJlYXJlciB0b2t1c2VyMWFiYwEB\r\n");

    // Write authenticate response

    test_proxy(tstate->c_fd_in, tstate->s_fd_in,
               "* CAPABILITY IMAP4 IDLE NAMESPACE\r\n"
               "t001 OK user1@example.com authenticated (Success)\r\n");

    // Write logout command

    test_proxy(tstate->c_fd_in, tstate->s_fd_in, "a002 logout\r\n");

    // Write logout response

    test_proxy(tstate->s_fd_in, tstate->c_fd_in,
               "* BYE server terminating connection\r\n"
               "a002 OK LOGOUT completed\r\n");

    // Check exit status
    assert_int_equal(imap_exit_status(tstate), 0);
}

/* Invalid Credentials */

static void test_login_cmd4(void ** state) {
    struct test_state *tstate = * state;

    // Write initial server reply

    test_proxy(tstate->s_fd_in, tstate->c_fd_in, "* OK imap ready for requests from localhost\r\n");

    // Write LOGIN command

    test_proxy2(tstate->c_fd_in, tstate->c_fd_in,
                "a1 LOGIN user2@example.com\r\n",
                "a1 NO Invalid username\r\n");

    // Write unilateral response

    test_proxy2(tstate->s_fd_in, tstate->c_fd_in,
                "* CAPABILITY IMAP4 LOGINDISABLED IDLE NAMESPACE\r\n",
                "* CAPABILITY IMAP4 IDLE NAMESPACE\r\n");

    // Write logout command

    test_proxy(tstate->c_fd_in, tstate->s_fd_in, "a2 logout\r\n");

    // Write logout response

    test_proxy(tstate->s_fd_in, tstate->c_fd_in,
               "* BYE server terminating connection\r\n"
               "a2 OK LOGOUT completed\r\n");

    // Check exit status
    assert_int_equal(imap_exit_status(tstate), 0);
}

static void test_login_cmd5(void ** state) {
    struct test_state *tstate = * state;

    // Write initial server reply

    test_proxy(tstate->s_fd_in, tstate->c_fd_in, "* OK imap ready for requests from localhost\r\n");

    // Write LOGIN command

    test_proxy2(tstate->c_fd_in, tstate->c_fd_in,
                "a1 LOGIN\r\n",
                "a1 BAD Syntax error in username\r\n");

    // Write unilateral response

    test_proxy2(tstate->s_fd_in, tstate->c_fd_in,
                "* CAPABILITY IMAP4 LOGINDISABLED IDLE NAMESPACE\r\n",
                "* CAPABILITY IMAP4 IDLE NAMESPACE\r\n");

    // Write logout command

    test_proxy(tstate->c_fd_in, tstate->s_fd_in, "a2 logout\r\n");

    // Write logout response

    test_proxy(tstate->s_fd_in, tstate->c_fd_in,
               "* BYE server terminating connection\r\n"
               "a2 OK LOGOUT completed\r\n");

    // Check exit status
    assert_int_equal(imap_exit_status(tstate), 0);
}

static void test_login_cmd6(void ** state) {
    struct test_state *tstate = * state;

    // Write initial server reply

    test_proxy(tstate->s_fd_in, tstate->c_fd_in, "* OK imap ready for requests from localhost\r\n");

    // Write LOGIN command

    test_proxy2(tstate->c_fd_in, tstate->c_fd_in,
                "a1 LOGIN \"someuser\r\n",
                "a1 BAD Syntax error in username\r\n");

    // Write unilateral response

    test_proxy2(tstate->s_fd_in, tstate->c_fd_in,
                "* CAPABILITY IMAP4 LOGINDISABLED IDLE NAMESPACE\r\n",
                "* CAPABILITY IMAP4 IDLE NAMESPACE\r\n");

    // Write logout command

    test_proxy(tstate->c_fd_in, tstate->s_fd_in, "a2 logout\r\n");

    // Write logout response

    test_proxy(tstate->s_fd_in, tstate->c_fd_in,
               "* BYE server terminating connection\r\n"
               "a2 OK LOGOUT completed\r\n");

    // Check exit status
    assert_int_equal(imap_exit_status(tstate), 0);
}


/* Closing Socket */

static void test_client_close1(void ** state) {
    struct test_state *tstate = *state;

    // Write initial server reply

    test_proxy(tstate->s_fd_in, tstate->c_fd_in, "* OK imap ready for requests from localhost\r\n");

    // Write first client command

    test_proxy(tstate->c_fd_in, tstate->s_fd_in, "c1 LOGOUT\r\n");

    // Close client socket
    shutdown(tstate->c_fd_in, SHUT_RDWR);
    close(tstate->c_fd_in);
    tstate->c_fd_in = -1;

    // Read from server socket
    char buf[500];
    assert_int_equal(read_data(tstate->s_fd_in, buf, sizeof(buf), sizeof(buf)), 0);

    // Check exit status
    assert_int_equal(imap_exit_status(tstate), 0);
}

static void test_client_close2(void ** state) {
    struct test_state *tstate = *state;

    // Write initial server reply

    test_proxy(tstate->s_fd_in, tstate->c_fd_in, "* OK imap ready for requests from localhost\r\n");

    // Write first client command

    const char *cmd = "c1 LOGOUT";
    assert_write(tstate->c_fd_in, cmd, strlen(cmd));

    // Close client socket
    shutdown(tstate->c_fd_in, SHUT_RDWR);
    close(tstate->c_fd_in);
    tstate->c_fd_in = -1;

    // Read from server socket
    char buf[500];
    assert_read(tstate->s_fd_in, buf, cmd);

    // Check exit status
    assert_int_equal(imap_exit_status(tstate), 0);
}

static void test_server_close1(void ** state) {
    struct test_state *tstate = *state;

    // Write initial server reply

    test_proxy(tstate->s_fd_in, tstate->c_fd_in, "* OK imap ready for requests from localhost\r\n");

    // Write first client command

    test_proxy(tstate->c_fd_in, tstate->s_fd_in, "c1 LOGOUT\r\n");

    // Write logout response

    test_proxy(tstate->s_fd_in, tstate->c_fd_in,
               "* BYE server terminating connection\r\n"
               "c1 OK LOGOUT completed\r\n");

    // Close server socket
    shutdown(tstate->s_fd_in, SHUT_RDWR);
    close(tstate->s_fd_in);
    tstate->s_fd_in = -1;

    // Read from client socket
    char buf[500];
    assert_int_equal(read_data(tstate->c_fd_in, buf, sizeof(buf), sizeof(buf)), 0);

    // Check exit status
    assert_int_equal(imap_exit_status(tstate), 0);
}

static void test_server_close2(void ** state) {
    struct test_state *tstate = *state;

    // Write initial server reply

    test_proxy(tstate->s_fd_in, tstate->c_fd_in, "* OK imap ready for requests from localhost\r\n");

    // Write first client command

    test_proxy(tstate->c_fd_in, tstate->s_fd_in, "c1 LOGOUT\r\n");

    // Write logout response

    const char *resp = "* BYE server terminating connection\r\n"
        "c1 OK LOGOUT completed";

    assert_write(tstate->s_fd_in, resp, strlen(resp));

    // Close server socket
    shutdown(tstate->s_fd_in, SHUT_RDWR);
    close(tstate->s_fd_in);
    tstate->s_fd_in = -1;

    // Read from client socket
    char buf[500];
    assert_read(tstate->c_fd_in, buf, resp);

    // Check exit status
    assert_int_equal(imap_exit_status(tstate), 0);
}


/* Main Function */

int main(void) {
    const struct CMUnitTest tests[] = {
        imap_unit_test(test_simple_proxy),
        imap_unit_test(test_capability_reply1),
        imap_unit_test(test_capability_reply2),
        imap_unit_test(test_login_cmd1),
        imap_unit_test(test_login_cmd2),
        imap_unit_test(test_login_cmd3),
        imap_unit_test(test_login_cmd4),
        imap_unit_test(test_login_cmd5),
        imap_unit_test(test_login_cmd6),
        imap_unit_test(test_client_close1),
        imap_unit_test(test_client_close2),
        imap_unit_test(test_server_close1),
        imap_unit_test(test_server_close2)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
