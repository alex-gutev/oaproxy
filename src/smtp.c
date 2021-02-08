#define _GNU_SOURCE

#include "smtp.h"

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "gaccounts.h"
#include "ssl.h"
#include "b64.h"
#include "xoauth2.h"

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
static bool smtp_client_handle_cmd(int c_fd, BIO *s_bio);

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


/* Implementation */

void smtp_handle_client(int c_fd, const char *host) {
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
        syslog(LOG_USER | LOG_ERR, "Error connecting to SMTP host: %s", host);
        ssl_log_error(NULL);
        goto close_server;
    }

    BIO_set_nbio(bio, 1);

    int s_fd = BIO_get_fd(bio, NULL);
    int maxfd = c_fd < s_fd ? s_fd : c_fd;

    while (1) {
        fd_set rfds;

        FD_ZERO(&rfds);
        FD_SET(c_fd, &rfds);
        FD_SET(s_fd, &rfds);

        int retval = select(maxfd+1, &rfds, NULL, NULL, NULL);

        if (retval < 0) {
            syslog(LOG_USER | LOG_ERR, "select() error: %m");
            break;
        }

        if (FD_ISSET(s_fd, &rfds)) {
            if (!smtp_server_handle_response(c_fd, bio))
                break;
        }
        else if (FD_ISSET(c_fd, &rfds)) {
            if (!smtp_client_handle_cmd(c_fd, bio))
                break;
        }
    }

close_server:
    BIO_free_all(bio);

close_client:
    close(c_fd);
}


/* Handling SMTP Client Commands */

bool smtp_client_handle_cmd(int c_fd, BIO *s_bio) {
    char c_data[RECV_BUF_SIZE];
    ssize_t c_n = smtp_read_client_cmd(c_fd, c_data, sizeof(c_data));

    if (c_n < 0) {
        syslog(LOG_USER | LOG_ERR, "Error reading data from client: %m");
        return false;
    }
    else if (c_n == 0) {
        syslog(LOG_USER | LOG_NOTICE, "Client closed connection");
        return false;
    }

    const char *eptr = NULL;
    smtp_command cmd = smtp_parse_command(c_data, &eptr, c_n);

    switch (cmd) {
    case SMTP_AUTH: {
        const char *user = smtp_parse_auth_user(eptr, c_n - (eptr - c_data));

        GList *accounts = goa_client_get_accounts(get_goaclient(NULL));
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

        if (bytes < 0) {
            return bytes;
        }
        else if (bytes == 0) {
            return total;
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


/* Handle SMTP server response */

bool smtp_server_handle_response(int c_fd, BIO *s_bio) {
    char s_data[RECV_BUF_SIZE];
    ssize_t s_n = BIO_read(s_bio, s_data, sizeof(s_data));

    if (s_n < 0) {
        ssl_log_error("Error reading SMTP server response");
        return false;
    }
    else if (s_n == 0) {
        syslog(LOG_USER | LOG_NOTICE, "SMTP server closed connection");
        return false;
    }

    return smtp_client_send(c_fd, s_data, s_n);
}
