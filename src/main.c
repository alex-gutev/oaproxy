#define GOA_API_IS_SUBJECT_TO_CHANGE
#include <goa/goa.h>

#include <locale.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

#define RECV_BUF_SIZE 1024

/**
 * SMTP command
 */
typedef enum smtp_command {
    /* Generic Command */
    SMTP_CMD = 0,
    /* AUTH - Authorization Command */
    SMTP_AUTH = 1,
    /* QUIT - End Session Command */
    SMTP_QUIT
} smtp_command;

/**
 * Run the SMTP proxy server loop.
 *
 * @param port Port to listen on.
 */
static void run_server(int port);

/**
 * Handle SMTP client connection.
 *
 * @param fd Client socket descriptor.
 */
static void handle_smtp_client(int fd);

/**
 * Parse an SMTP command from the client response.
 *
 * @param response Client response
 * @param len Number of bytes in client response
 */
static smtp_command smtp_parse_command(char *response, size_t len);
int main(int argc, char *argv[])
{
    if (argc < 1) {
        fputs("Usage: oaproxy [SMTP port]\n", stderr);
        return 1;
    }

    char *endptr;
    int port = strtol(argv[1], &endptr, 10);

    if (endptr && *endptr) {
        fprintf(stderr, "Invalid SMTP port: %s\n", argv[1]);
        return -1;
    }

    run_server(port);
    return 0;
}
/* Local SMTP Server */

void run_server(int port) {
    struct sockaddr_in server;
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0) {
        perror("Error opening server socket");
        exit(EXIT_FAILURE);
    }

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *)&server, sizeof(server))) {
        perror("Error binding to port");
        exit(EXIT_FAILURE);
    }

    if (listen(sockfd, SOMAXCONN)) {
        perror("Error listening for incoming connections");
        exit(EXIT_FAILURE);
    }

    while (1) {
        int clientfd = accept(sockfd, NULL, NULL);

        if (clientfd >= 0) {
            handle_smtp_client(clientfd);
        }
        else {
            perror("Error accepting connection");
        }
    }
}

void handle_smtp_client(int fd) {
    char buf[RECV_BUF_SIZE];

    ssize_t sz = 0;

    while ((sz = recv(fd, buf, RECV_BUF_SIZE, 0))) {
        if (sz < 0 && errno != EINTR) {
            perror("Error receiving data");
            break;
        }

        smtp_command cmd = smtp_parse_command(buf, sz);

        switch (cmd) {
        case SMTP_AUTH:
            printf("Received AUTH command\n");
            break;

        case SMTP_QUIT:
            printf("Received QUIT command\n");
            goto close;
            break;

        default:
            buf[sz] = 0;
            printf("Received %ld bytes: %s\n", sz, buf);
        }
    }

close:

    printf("Connection Closed\n");
    close(fd);
}

smtp_command smtp_parse_command(char *response, size_t len) {
    if (len > 4) {
        if (strncasecmp("AUTH", response, 4) == 0 &&
            response[4] == ' ') {
            return SMTP_AUTH;
        }
        else if (strncasecmp("QUIT", response, 4) == 0 &&
                 response[4] == '\r' || response[4] == '\n') {
            return SMTP_QUIT;
        }
    }

    return SMTP_CMD;
}
