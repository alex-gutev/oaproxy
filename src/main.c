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

/**
 * Run the SMTP proxy server loop.
 *
 * @param port Port to listen on
 * @param host SMTP server host
 */
static void run_server(int port, const char *host);

int main(int argc, char *argv[])
{
    GError *error = NULL;

    setlocale(LC_ALL, "");

    if (argc < 2) {
        fputs("Usage: oaproxy [port] [SMTP host]\n", stderr);
        return 1;
    }

    char *endptr;
    int port = strtol(argv[1], &endptr, 10);

    if (endptr && *endptr) {
        fprintf(stderr, "Invalid port number: %s\n", argv[1]);
        return 1;
    }

    openlog(NULL, LOG_PID | LOG_PERROR, LOG_USER);

    initialize_ssl();

    // Initialize Gnome Online Accounts Client
    if (!get_goaclient(&error)) {
        syslog(LOG_ERR | LOG_USER, "Could not create GoaClient: %s", error->message);
        return 1;
    }

    run_server(port, argv[2]);
    destroy_ssl();



    return 0;
}


/* Local SMTP Server */

void run_server(int port, const char *host) {
    struct sockaddr_in server;
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0) {
        syslog(LOG_USER | LOG_ERR, "Error opening socket: %m");
        exit(EXIT_FAILURE);
    }

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *)&server, sizeof(server))) {
        syslog(LOG_USER | LOG_ERR, "Error binding to port %d: %m", port);
        exit(EXIT_FAILURE);
    }

    if (listen(sockfd, SOMAXCONN)) {
        syslog(LOG_USER | LOG_ERR, "Error listening for incoming connections on port %d: %m", port);
        exit(EXIT_FAILURE);
    }

    while (1) {
        int clientfd = accept(sockfd, NULL, NULL);

        if (clientfd >= 0) {
            smtp_handle_client(clientfd, host);
        }
        else {
            syslog(LOG_USER | LOG_ERR, "Error accepting client connection: %m");
        }
    }
}
