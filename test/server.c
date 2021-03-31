#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <cmocka.h>

#include "server.h"

#ifndef CONF_TEST_DIR
#define CONF_TEST_DIR
#endif

#define TEST_SOCK_FD 54321

/* Mocked Functions */

int __wrap_socket(int domain, int type, int protocol) {
    return mock_type(int);
}

int __wrap_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    return 0;
}

int __wrap_listen(int sockfd, int backlog) {
    return 0;
}


/* Test Functions */

void test_simple_conf(void ** state) {
    // Return valid FD for all servers
    for (int i = 0; i < 4; ++i) {
        will_return(__wrap_socket, TEST_SOCK_FD);
    }

    // Parse config file test1.conf
    size_t n = 0;
    struct proxy_server *servers = parse_servers(CONF_TEST_DIR "test1.conf", &n);

    assert_non_null(servers);
    assert_int_equal(n, 4);

    // First server

    assert_int_equal(servers[0].type, TYPE_SMTP); // Server type
    assert_int_equal(servers[0].port, 5000); // Port
    assert_string_equal(servers[0].host, "smtp.example.com:465");

    // Second server

    assert_int_equal(servers[1].type, TYPE_IMAP); // Server type
    assert_int_equal(servers[1].port, 5001); // Port
    assert_string_equal(servers[1].host, "imap.example.com:993");

    // Third server

    assert_int_equal(servers[2].type, TYPE_IMAP); // Server type
    assert_int_equal(servers[2].port, 600); // Port
    assert_string_equal(servers[2].host, "imap.mail.com:444");

    // Third server

    assert_int_equal(servers[3].type, TYPE_SMTP); // Server type
    assert_int_equal(servers[3].port, 700); // Port
    assert_string_equal(servers[3].host, "smtp.mail.com:100");
}

void test_malformed_conf1(void ** state) {
    // Return valid FD for all servers
    will_return(__wrap_socket, TEST_SOCK_FD);

    // Parse config file test2.conf
    size_t n = 0;
    struct proxy_server *servers = parse_servers(CONF_TEST_DIR "test2.conf", &n);

    assert_non_null(servers);
    assert_int_equal(n, 1);

    // First server

    assert_int_equal(servers[0].type, TYPE_SMTP); // Server type
    assert_int_equal(servers[0].port, 3000); // Port
    assert_string_equal(servers[0].host, "smtp.example.com:465");
}

void test_malformed_conf2(void ** state) {
    // Parse config file test3.conf
    size_t n = 0;
    struct proxy_server *servers = parse_servers(CONF_TEST_DIR "test3.conf", &n);

    assert_null(servers);
    assert_int_equal(n, 0);
}

void test_empty_conf(void ** state) {
    // Parse config file test4.conf
    size_t n = 0;
    struct proxy_server *servers = parse_servers(CONF_TEST_DIR "test4.conf", &n);

    assert_null(servers);
    assert_int_equal(n, 0);
}

void test_socket_fail(void ** state) {
    // Return valid FD for all servers except second
    will_return(__wrap_socket, TEST_SOCK_FD);
    will_return(__wrap_socket, -1);
    will_return(__wrap_socket, TEST_SOCK_FD);
    will_return(__wrap_socket, TEST_SOCK_FD);

    // Parse config file test1.conf
    size_t n = 0;
    struct proxy_server *servers = parse_servers(CONF_TEST_DIR "test1.conf", &n);

    assert_non_null(servers);
    assert_int_equal(n, 3);

    // First server

    assert_int_equal(servers[0].type, TYPE_SMTP); // Server type
    assert_int_equal(servers[0].port, 5000); // Port
    assert_string_equal(servers[0].host, "smtp.example.com:465");

    // Third server

    assert_int_equal(servers[1].type, TYPE_IMAP); // Server type
    assert_int_equal(servers[1].port, 600); // Port
    assert_string_equal(servers[1].host, "imap.mail.com:444");

    // Third server

    assert_int_equal(servers[2].type, TYPE_SMTP); // Server type
    assert_int_equal(servers[2].port, 700); // Port
    assert_string_equal(servers[2].host, "smtp.mail.com:100");
}

/* Main Function */

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_simple_conf),
        cmocka_unit_test(test_malformed_conf1),
        cmocka_unit_test(test_malformed_conf2),
        cmocka_unit_test(test_empty_conf),
        cmocka_unit_test(test_socket_fail)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
