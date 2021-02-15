#define _GNU_SOURCE

#include <locale.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <syslog.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

#include "gaccounts.h"

#include "ssl.h"
#include "smtp.h"
#include "imap.h"

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
    /** Server socket file descriptor */
    int sock_fd;

    /** Remote server host */
    const char *host;
};

/**
 * Create a socket for a given proxy server.
 *
 * @param server Proxy server state.
 * @param port   Local proxy port.
 *
 * @return True if the socket was created and bound to the port
 *   successfully.
 */
static bool open_server_sock(struct proxy_server *server, int port);

/**
 * Run the proxy server loop.
 *
 * @param servers Array of servers to run
 * @param n       Number of servers
 */
static void run_servers(struct proxy_server *servers, size_t n);


int main(int argc, char *argv[])
{
    GError *error = NULL;

    setlocale(LC_ALL, "");

    if (argc < 5) {
        fputs("Usage: oaproxy [SMTP port] [SMTP host] [IMAP port] [IMAP host]\n", stderr);
        return 1;
    }

    char *endptr;
    int s_port = strtol(argv[1], &endptr, 10);

    if (endptr && *endptr) {
        fprintf(stderr, "Invalid SMTP port number: %s\n", argv[1]);
        return 1;
    }

    int i_port = strtol(argv[3], &endptr, 10);

    if (endptr && *endptr) {
        fprintf(stderr, "Invalid IMAP port number: %s\n", argv[3]);
        return 1;
    }

    openlog(NULL, LOG_PID | LOG_PERROR, LOG_USER);

    initialize_ssl();

    struct proxy_server servers[2];

    servers[0].type = TYPE_SMTP;
    servers[0].host = argv[2];

    servers[1].type = TYPE_IMAP;
    servers[1].host = argv[4];

    if (!open_server_sock(&servers[0], s_port)) return 1;
    if (!open_server_sock(&servers[1], i_port)) return 1;

    // Initialize Gnome Online Accounts Client
    if (!get_goaclient(&error)) {
        syslog(LOG_ERR | LOG_USER, "Could not create GoaClient: %s", error->message);
        return 1;
    }

    run_servers(servers, 2);
    destroy_ssl();

    return 0;
}


/* Local SMTP Server */

bool open_server_sock(struct proxy_server *server, int port) {
    struct sockaddr_in s_addr;
    server->sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (server->sock_fd < 0) {
        syslog(LOG_USER | LOG_ERR, "Error opening socket: %m");
        goto error;
    }

    s_addr.sin_family = AF_INET;
    s_addr.sin_addr.s_addr = INADDR_ANY;
    s_addr.sin_port = htons(port);

    if (bind(server->sock_fd, (struct sockaddr *)&s_addr, sizeof(s_addr))) {
        syslog(LOG_USER | LOG_ERR, "Error binding to port %d: %m", port);
        goto error;
    }

    if (listen(server->sock_fd, SOMAXCONN)) {
        syslog(LOG_USER | LOG_ERR, "Error listening for incoming connections on port %d: %m", port);
        goto error;
    }

    return true;

error:
    close(server->sock_fd);
    return false;
}

void run_servers(struct proxy_server *servers, size_t n) {
    int maxfd = -1;

    // Determine largest numbered file server socket file descriptor
    for (int i = 0; i < n; ++i) {
        if (servers[i].sock_fd > maxfd)
            maxfd = servers[i].sock_fd;
    }

    maxfd += 1;

    while (1) {
        fd_set rfds;

        FD_ZERO(&rfds);

        for (int i = 0; i < n; ++i) {
            FD_SET(servers[i].sock_fd, &rfds);
        }

        int retval = select(maxfd+1, &rfds, NULL, NULL, NULL);

        if (retval < 0) {
            syslog(LOG_USER | LOG_ERR, "SMTP: select() error: %m");
            break;
        }

        for (int i = 0; i < n; ++i) {
            if (FD_ISSET(servers[i].sock_fd, &rfds)) {
                int clientfd = accept(servers[i].sock_fd, NULL, NULL);

                if (clientfd < 0) {
                    syslog(LOG_USER | LOG_ERR, "Error accepting client connection: %m");
                    continue;
                }

                switch (servers[i].type) {
                case TYPE_SMTP:
                    smtp_handle_client(clientfd, servers[i].host);
                    break;

                case TYPE_IMAP:
                    imap_handle_client(clientfd, servers[i].host);
                    break;
                }
            }
        }
    }
}
