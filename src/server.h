#ifndef OAPROXY_SERVER_H
#define OAPROXY_SERVER_H

#include <stddef.h>

#include <stdbool.h>

/**
 * Type of proxy server IMAP or SMTP.
 */
typedef enum server_type {
    TYPE_IMAP = 0,
    TYPE_SMTP
} server_type;

/**
 * Proxy server state
 */
struct proxy_server {
    /** Server type */
    server_type type;

    /** Server port */
    unsigned long port;

    /** Server socket file descriptor */
    int sock_fd;

    /** Remote server host */
    char *host;
};

/**
 * Parse the server configurations from a text file.
 *
 * @param path Path to text file
 *
 * @param n Pointer to variable which is set to the number of servers
 *   parsed from the text file.
 *
 * @return Pointer to array of proxy server configurations, or NULL if
 *   no servers were parsed.
 */
struct proxy_server *parse_servers(const char *path, size_t *n);

/**
 * Create a socket for a given proxy server.
 *
 * @param server Proxy server state.
 * @param port   Local proxy port.
 *
 * @return True if the socket was created and bound to the port
 *   successfully.
 */
bool open_server_sock(struct proxy_server *server, int port);

/**
 * Run the proxy server loop.
 *
 * @param servers Array of servers to run
 * @param n       Number of servers
 */
void run_servers(struct proxy_server *servers, size_t n);


#endif /* OAPROXY_SERVER_H */
