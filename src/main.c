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

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

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

/**
 * Initialize the OpenSSL library.
 */
static void initialize_ssl();

/**
 * Free the OpenSSL library.
 */
static void destroy_ssl();
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

    initialize_ssl();
    run_server(port);
    destroy_ssl();

    return 0;
}

/* OpenSSL Utilities */

void initialize_ssl() {
    SSL_load_error_strings();
    ERR_load_crypto_strings();

    OpenSSL_add_all_algorithms();
    SSL_library_init();
}

void destroy_ssl() {
    ERR_free_strings();
    EVP_cleanup();
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
    char s_data[RECV_BUF_SIZE];
    char c_data[RECV_BUF_SIZE];

    ssize_t s_n = 0, c_n = 0;

    // Connect to SMTP server

    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL) {
        fputs("Error loading SSL context\n", stderr);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    BIO *bio = BIO_new_ssl_connect(ctx);
    SSL *ssl;

    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    BIO_set_conn_hostname(bio, "smtp.gmail.com:465");

    if (BIO_do_connect(bio) <= 0) {
        BIO_free_all(bio);
        fputs("Error connecting to server\n", stderr);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    BIO_set_nbio(bio, 1);

    int bfd = BIO_get_fd(bio, NULL);
    int maxfd = fd < bfd ? bfd : fd;


    while (1) {
        fd_set rfds;

        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        FD_SET(bfd, &rfds);

        int retval = select(maxfd+1, &rfds, NULL, NULL, NULL);

        if (retval <= 0) {
            perror("select()");
            break;
        }

        if (FD_ISSET(bfd, &rfds)) {
            s_n = BIO_read(bio, s_data, sizeof(s_data));

            if (s_n < 0) {
                BIO_free_all(bio);
                fputs("Error reading data from server\n", stderr);
                ERR_print_errors_fp(stderr);
                exit(EXIT_FAILURE);
            }
            else if (s_n == 0) {
                break;
            }

            c_n = send(fd, s_data, s_n, 0);

            if (c_n < 0) {
                perror("Error sending data to client");
                exit(EXIT_FAILURE);
            }
        }
        else if (FD_ISSET(fd, &rfds)) {
            c_n = recv(fd, c_data, sizeof(c_data), 0);

            if (c_n < 0) {
                perror("Error reading data from client");
                exit(EXIT_FAILURE);
            }
            else if (c_n == 0) {
                break;
            }

            s_n = BIO_write(bio, c_data, c_n);

            if (s_n < 0) {
                BIO_free_all(bio);
                fputs("Error reading data from server\n", stderr);
                ERR_print_errors_fp(stderr);
                exit(EXIT_FAILURE);
            }
        }
    }

close:

    printf("Connection Closed\n");

    BIO_free_all(bio);
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
