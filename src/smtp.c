#define _GNU_SOURCE

#include "smtp.h"

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <assert.h>

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

#include "smtp_reply.h"
#include "smtp_cmd.h"

#define RECV_BUF_SIZE 512 * 4

/* Handling SMTP Client Command */

/**
 * Read and handle/forward an SMTP command from the client.
 *
 * @param stream SMTP command stream
 * @param s_bio Server BIO object
 *
 * @return true if the command was handled successfully, false
 *   otherwsie.
 */
static bool smtp_client_handle_cmd(struct smtp_cmd_stream *stream, BIO *s_bio);


/* Command Parsing */

/**
 * Parse the username from an SMTP plain auth command.
 *
 * @param data Data following SMTP AUTH PLAIN command.
 * @param n Size of data
 *
 * @return Username
 */
static char * smtp_parse_auth_user(const char *data, size_t n);

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


/* Sending Data */

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
 * @param stream SMTP reply stream
 *
 * @return True if successful, False otherwise.
 */
static bool smtp_server_handle_reply(int c_fd, struct smtp_reply_stream *stream);


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

    struct smtp_cmd_stream * c_stream = smtp_cmd_stream_create(c_fd);
    struct smtp_reply_stream * s_stream = smtp_reply_stream_create(bio);

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
            if (!smtp_server_handle_reply(c_fd, s_stream))
                break;
        }
        else if (FD_ISSET(c_fd, &rfds)) {
            if (!smtp_client_handle_cmd(c_stream, bio))
                break;
        }
    }

    smtp_cmd_stream_free(c_stream);
    smtp_reply_stream_free(s_stream);

close_server:
    BIO_free_all(bio);

close_client:
    close(c_fd);
}


/* Handling SMTP Client Commands */

bool smtp_client_handle_cmd(struct smtp_cmd_stream *stream, BIO *s_bio) {
    struct smtp_cmd cmd;
    ssize_t c_n = smtp_cmd_next(stream, &cmd);

    if (c_n < 0) {
        syslog(LOG_USER | LOG_ERR, "Error reading data from client: %m");
        return false;
    }
    else if (c_n == 0) {
        syslog(LOG_USER | LOG_NOTICE, "Client closed connection");
        return false;
    }

    switch (cmd.command) {
    case SMTP_CMD_AUTH: {
        char *user = smtp_parse_auth_user(cmd.data, cmd.data_len);

        if (user) {
            GList *accounts = goa_client_get_accounts(get_goaclient(NULL));
            GList *account = find_goaccount(accounts, user);

            if (account) {
                bool auth = smtp_auth_client(smtp_cmd_stream_fd(stream), s_bio, account, user);

                free(user);
                g_list_free_full(accounts, (GDestroyNotify)g_object_unref);

                return auth;
            }

            syslog(LOG_USER | LOG_WARNING, "Could not find GNOME Online Account for username %s", user);

            free(user);
            g_list_free_full(accounts, (GDestroyNotify)g_object_unref);
        }
    }

    default:
        return smtp_server_send(s_bio, cmd.line, cmd.total_len);
    }

    return true;
}



/* Parsing SMTP Commands */


char * smtp_parse_auth_user(const char *data, size_t n) {
    char *dec = base64_decode(data, &n);
    if (!dec) return NULL;

    // Find first NUL character
    size_t user_start = 0;
    while (n && dec[user_start++]) {
        n--;
        user_start++;
    }

    // Find end of username
    size_t pass_start = user_start;
    while (n && dec[pass_start++]) {
        n--;
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

bool smtp_server_handle_reply(int c_fd, struct smtp_reply_stream *stream) {
    struct smtp_reply reply;
    reply.last = false;

    while (!reply.last) {
        if (smtp_reply_next(stream, &reply) <= 0)
            return false;

        smtp_reply_parse(&reply);

        switch (reply.type) {
        case SMTP_REPLY_AUTH: {
            char data[255];

            int sz = snprintf(data, sizeof(data), "%d%cAUTH PLAIN\r\n", reply.code, reply.last ? ' ' : '-');
            assert(sz > 0 && sz < sizeof(data));

            if (!smtp_client_send(c_fd, data, sz))
                return false;
        } break;

        default:
            if (!smtp_client_send(c_fd, reply.data, reply.total_len))
                return false;

            break;
        }
    }

    return true;
}
