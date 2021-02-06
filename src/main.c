#define GOA_API_IS_SUBJECT_TO_CHANGE
#define _GNU_SOURCE

#include <goa/goa.h>

#include <locale.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <syslog.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "b64.h"
#include "xoauth2.h"

#include "ssl.h"

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
    SMTP_DATA
} smtp_command;

/**
 * Run the SMTP proxy server loop.
 *
 * @param port Port to listen on
 * @param host SMTP server host
 */
static void run_server(int port, const char *host);

/**
 * Handle SMTP client connection.
 *
 * @param fd   Client socket descriptor
 * @param host SMTP server host
 */
static void handle_smtp_client(int fd, const char *host);


/* Handling SMTP Client Command */

/**
 * Read and handle/forward an SMTP command from the client.
 *
 * @param c_fd Client socket file descriptor
 * @param s_bio Server BIO object
 *
 * @return true if the command was handled successfully, false
 *   otherwsie.
 */
static bool handle_smtp_client_cmd(int c_fd, BIO *s_bio);

/**
 * Read an SMTP command from the client.
 *
 * @param c_fd Client socket file descriptor
 * @param buf Buffer in which to read command
 * @param n Buffer size
 *
 * @return Number of bytes read. -1 if an error occurred.
 */
static ssize_t smtp_read_client_cmd(int c_fd, char *buf, size_t n);

/**
 * Parse an SMTP command from the client response.
 *
 * @param response Client response
 * @param eptr Pointer to the first character after command
 * @param len Number of bytes in client response
 *
 * @return SMTP command.
 */
static smtp_command smtp_parse_command(const char *response, const char **eptr, size_t len);

/**
 * Parse the username from an SMTP plain auth command.
 *
 * @param data Data following SMTP AUTH PLAIN command.
 * @param n Size of data
 *
 * @return Username
 */
static const char * smtp_parse_auth_user(const char *data, size_t n);

/**
 * Authenticate the client by sending the AUTH (using XOAUTH2) command
 * to the server.
 *
 * @param c_fd Client socket file descriptor
 * @param s_bio Server BIO object
 * @param account Gnome online account
 * @param user Username
 *
 * @return True if the authentication commands were sent successfully,
 *   false otherwise.
 */
static bool smtp_auth_client(int fd, BIO *bio, GList *account, const char *user);

/**
 * Send data to the server.
 *
 * @param bio Server BIO object
 * @param data Block of data to send
 * @param n Size of data in bytes
 *
 * @return True if the data was sent successfully, false otherwise.
 */
static bool smtp_server_send(BIO *bio, const char *data, size_t n);

/**
 * Send data to the client.
 *
 * @param fd Client socket file descriptor
 * @param data block of data to send
 * @param n Size of data in bytes
 *
 * @return True if the data was sent successfully, false otherwise.
 */
static bool smtp_client_send(int fd, const char *data, size_t n);


/* Handling SMTP Server Response */

/**
 * Read and handle the SMTP response from the server.
 *
 * @param c_fd Client socket file descriptor
 * @param bio Server BIO object
 *
 * @return True if successful, False otherwise.
 */
static bool smtp_server_handle_response(int c_fd, BIO *bio);


/* Gnome online accounts */

/**
 * Find a GOA account for a particular user.
 *
 * @param accounts List of all accounts
 * @param user Username
 *
 * @return Pointer to the node containing the account, NULL if no
 *   account was found for the given username.
 */
GList * find_goaccount(GList *accounts, const char *user);

/**
 * Retrieve the access token for a particular GOA account.
 *
 * @param account GOA account
 *
 * @return Access token, or NULL if their was an error.
 */
gchar *get_access_token(GList *account);

GoaClient *client;

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
        return -1;
    }

    openlog(NULL, LOG_PID | LOG_PERROR, LOG_USER);

    initialize_ssl();

    client = goa_client_new_sync(NULL, &error);
    if (!client) {
        g_error("Could not create GoaClient: %s", error->message);
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
            handle_smtp_client(clientfd, host);
        }
        else {
            syslog(LOG_USER | LOG_ERR, "Error accepting client connection: %m");
        }
    }
}

void handle_smtp_client(int fd, const char *host) {
    char s_data[RECV_BUF_SIZE];
    char c_data[RECV_BUF_SIZE];

    ssize_t s_n = 0, c_n = 0;

    // Connect to SMTP server

    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL) {
        ssl_log_error("Error loading SSL context");
        goto close_client;
    }

    BIO *bio = BIO_new_ssl_connect(ctx);
    SSL *ssl;

    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    BIO_set_conn_hostname(bio, host);

    if (BIO_do_connect(bio) <= 0) {
        ssl_log_error("Error connection to host: %s");
        goto close_server;
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

        if (retval < 0) {
            syslog(LOG_USER | LOG_ERR, "select() error: %m");
            break;
        }

        if (FD_ISSET(bfd, &rfds)) {
            if (!smtp_server_handle_response(fd, bio))
                break;
        }
        else if (FD_ISSET(fd, &rfds)) {
            if (!handle_smtp_client_cmd(fd, bio))
                break;
        }
    }

close_server:
    BIO_free_all(bio);

close_client:
    close(fd);
}


/* Handling SMTP Client Commands */

bool handle_smtp_client_cmd(int c_fd, BIO *s_bio) {
    char c_data[RECV_BUF_SIZE];
    ssize_t c_n = smtp_read_client_cmd(c_fd, c_data, sizeof(c_data));

    if (c_n <= 0) {
        return false;
    }

    const char *eptr = NULL;
    smtp_command cmd = smtp_parse_command(c_data, &eptr, c_n);

    switch (cmd) {
    case SMTP_AUTH: {
        const char *user = smtp_parse_auth_user(eptr, c_n - (eptr - c_data));

        GList *accounts = goa_client_get_accounts(client);
        GList *account = find_goaccount(accounts, user);

        if (account) {
            return smtp_auth_client(c_fd, s_bio, account, user);
        }
        else {
            return false;
        }
    } break;

    default:
        return smtp_server_send(s_bio, c_data, c_n);
    }

    return true;
}

ssize_t smtp_read_client_cmd(int fd, char *buf, size_t n) {
    ssize_t total = 0;

    while (1) {
        ssize_t bytes = recv(fd, buf, n, 0);

        if (bytes <= 0) {
            return bytes;
        }

        total += bytes;

        if (buf[bytes - 1] == '\n') {
            break;
        }

        buf += bytes;
    };

    return total;
}

smtp_command smtp_parse_command(const char *response, const char **eptr, size_t len) {
    if (len > 10) {
        if (strncasecmp("AUTH PLAIN", response, 10) == 0 &&
            (response[10] == ' ' || response[10] == '\r' ||
             response[10] == '\n')) {
            *eptr = response + 10;
            return SMTP_AUTH;
        }
    }

    if (len > 4) {
        if (strncasecmp("DATA", response, 4) == 0 &&
                 response[4] == '\r' || response[4] == '\n') {
            return SMTP_DATA;
        }
    }

    *eptr = NULL;
    return SMTP_CMD;
}

const char * smtp_parse_auth_user(const char *data, size_t n) {
    if (data[0] == ' ' && n > 1) {
        data++;
        n--;
    }

    size_t b_len = 0;

    // Find end of command
    while (n && data[b_len] != '\r' && data[b_len] != '\n') {
        b_len++;
        n--;
    }

    char *dec = base64_decode(data, &b_len);

    // Find first NUL character
    size_t user_start = 0;
    while (b_len && dec[user_start++]) {
        b_len--;
        user_start++;
    }

    // Find end of username
    size_t pass_start = user_start;
    while (b_len && dec[pass_start++]) {
        b_len--;
    }

    size_t user_len = pass_start - user_start;

    char *user = malloc(user_len);
    memcpy(user, dec + user_start, user_len);

    free(dec);

    return user;
}

bool smtp_auth_client(int fd, BIO *bio, GList *account, const char *user) {
    char s_data[RECV_BUF_SIZE];
    ssize_t s_n;

    // Get Access Token

    gchar *token = get_access_token(account);
    char *resp = xoauth2_make_client_response(user, token);

    char *auth_cmd;
    if (asprintf(&auth_cmd, "AUTH XOAUTH2 %s\r\n", resp) == -1) {
        syslog(LOG_USER | LOG_ERR, "asprintf error: %m");
        return false;
    }

    // Send Authentication Command to server

    if (!smtp_server_send(bio, auth_cmd, strlen(auth_cmd)))
        return false;

    // Read Response from server

    s_n = BIO_read(bio, s_data, sizeof(s_data));

    if (s_n < 0) {
        ssl_log_error("Error reading SMTP server response");
        return false;
    }
    else if (s_n == 0) {
        syslog(LOG_USER | LOG_WARNING, "SMTP server closed connection before AUTH response");
        return false;
    }

    return smtp_client_send(fd, s_data, s_n);
}

bool smtp_server_send(BIO *bio, const char *data, size_t n) {
    while (n) {
        ssize_t s_n = BIO_write(bio, data, n);

        if (s_n < 0) {
            ssl_log_error("Error sending data to SMTP server");
            return false;
        }

        n -= s_n;
        data += s_n;
    }

    return true;
}

bool smtp_client_send(int fd, const char *data, size_t n) {
    while (n) {
        ssize_t c_n = send(fd, data, n, 0) ;

        if (c_n < 0) {
            syslog(LOG_USER | LOG_ERR, "Error sending data to client: %m");
            return false;
        }

        n -= c_n;
        data += c_n;
    };

    return true;
}

/* SMTP server response */

bool smtp_server_handle_response(int c_fd, BIO *s_bio) {
    char s_data[RECV_BUF_SIZE];
    ssize_t s_n = BIO_read(s_bio, s_data, sizeof(s_data));

    if (s_n < 0) {
        ssl_log_error("Error reading SMTP server response");
        return false;
    }
    else if (s_n == 0) {
        return false;
    }

    return smtp_client_send(c_fd, s_data, s_n);
}


/* Gnome Online Accounts */

GList * find_goaccount(GList *accounts, const char *user) {
    GList *l;

    for (l = accounts; l != NULL; l = l->next) {
        GoaAccount *account = goa_object_get_account(GOA_OBJECT(l->data));
        const char *acc_id = goa_account_get_presentation_identity(account);

        if (!strcmp(user, acc_id)) {
            break;
        }
    }

    return l;
}

gchar *get_access_token(GList *account) {
    GoaOAuth2Based *oauth2 =
        goa_object_get_oauth2_based(GOA_OBJECT(account->data));

    if (oauth2) {
        gchar *access_token;

        if (goa_oauth2_based_call_get_access_token_sync(oauth2,
                                                        &access_token,
                                                        NULL,
                                                        NULL,
                                                        NULL)) {
            return access_token;
        }

        g_clear_object(&oauth2);
    }

    return NULL;
}
