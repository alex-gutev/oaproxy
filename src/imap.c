#define _GNU_SOURCE

#include "imap.h"

#include <stdbool.h>
#include <syslog.h>
#include <stdio.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "xmalloc.h"
#include "ssl.h"
#include "gaccounts.h"
#include "xoauth2.h"
#include "b64.h"

#include "imap_cmd.h"

#define RECV_BUF_SIZE 512 * 4

/**
 * Perform the initial IMAP authentication step.
 *
 * Waits for the client to send an authentication command and
 * substitutes it with XOAUTH2. After the authentication commands are
 * sent to the server, this function returns.
 *
 * @param c_fd  Client socket file descriptor
 * @param s_bio Server OpenSSL BIO object
 * @param s_fd  Server file descriptor
 *
 * @return True if all data was sent successfully that is the proxy
 *   should continue running, this does not mean authentication was
 *   successful.
 */
static bool imap_authenticate(int c_fd, BIO * s_bio, int s_fd);

/**
 * Handle a command from the client.
 *
 * @param stream IMAP command stream
 * @param s_bio  Server OpenSSL BIO object
 *
 * @return 1 - if the client has been authenticated, 0 - otherwise, -1
 *   if there was an error sending or receiving data.
 */
static int handle_client_command(struct imap_cmd_stream *stream, BIO *s_bio);

/**
 * Handle an IMAP LOGIN command, by sending XOAUTH2 authentication
 * command to server.
 *
 * @param c_fd Client socket file descriptor
 * @param s_bio Server OpenSSL BIO object
 * @param cmd  IMAP login command structure
 *
 * @return 1 - if the XOAUTH2 authentication command was sent
 *   successfully to the server, 0 - if an invalid user was entered or
 *   there was an error generating the token, -1 if there was an error
 *   sending or receiving data.
 */
static int imap_login(int c_fd, BIO * s_bio, const struct imap_cmd *cmd);


/* Error Reporting */

/**
 * Report authentication error (username not found in gnome online
 * accounts) to client.
 *
 * @param fd  Client socket file descriptor
 * @param tag IMAP command tag
 *
 * @return True if the error response was sent successfully to the
 * client.
 */
static bool imap_invalid_user(int fd, const char *tag);

/**
 * Report gnome online account error to IMAP client.
 *
 * @param fd   Client socket file descriptor
 * @param gerr GOA account error
 * @param tag  IMAP command tag
 *
 * @return True if the error response was sent successfully to the
 *   client.
 */
static bool imap_auth_error(int fd, goa_error gerr, const char *tag);

/**
 * Report a syntax error in LOGIN command to IMAP client.
 *
 * @param fd  Client socket descriptor
 * @param tag IMAP command tag
 *
 * @return True if the error response was sent successfully.
 */
static bool imap_login_syntax_error(int fd, const char *tag);


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
static bool imap_server_send(BIO *bio, const char *data, size_t n);

/**
 * Send data to the client.
 *
 * @param fd Client socket file descriptor
 * @param data block of data to send
 * @param n Size of data in bytes
 *
 * @return True if the data was sent successfully, false otherwise.
 */
static bool imap_client_send(int fd, const char *data, size_t n);


/* Implementation */

void imap_handle_client(int c_fd, const char *host) {
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL) {
        ssl_log_error("IMAP: Error creating SSL context");
        goto close_client;
    }

    BIO *bio = BIO_new_ssl_connect(ctx);
    SSL *ssl;

    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    BIO_set_conn_hostname(bio, host);

    if (BIO_do_connect(bio) <= 0) {
        syslog(LOG_USER | LOG_ERR, "IMAP: Error connecting to SMTP host: %s", host);
        ssl_log_error(NULL);
        goto close_server;
    }

    int s_fd = BIO_get_fd(bio, NULL);
    int maxfd = c_fd < s_fd ? s_fd : c_fd;

    if (!imap_authenticate(c_fd, bio, s_fd)) {
        goto close_server;
    }

    while (1) {
        fd_set rfds;

        FD_ZERO(&rfds);
        FD_SET(c_fd, &rfds);
        FD_SET(s_fd, &rfds);

        int retval = select(maxfd+1, &rfds, NULL, NULL, NULL);

        if (retval < 0) {
            syslog(LOG_USER | LOG_ERR, "IMAP: select() error: %m");
            break;
        }

        if (FD_ISSET(s_fd, &rfds)) {
            char s_data[RECV_BUF_SIZE];
            size_t s_n = BIO_read(bio, s_data, sizeof(s_data));

            if (s_n < 0) {
                ssl_log_error("IMAP: Error reading data from server");
                break;
            }
            else if (s_n == 0) {
                syslog(LOG_USER | LOG_ERR, "IMAP: Server closed connection");
                break;
            }

            if (!imap_client_send(c_fd, s_data, s_n)) {
                break;
            }
        }

        if (FD_ISSET(c_fd, &rfds)) {
            char c_data[RECV_BUF_SIZE];
            size_t c_n = recv(c_fd, c_data, sizeof(c_data), 0);

            if (c_n < 0) {
                syslog(LOG_USER | LOG_ERR, "IMAP: Error sending data to client: %m");
                break;
            }
            else if (c_n == 0) {
                syslog(LOG_USER | LOG_ERR, "IMAP: Client closed connection");
                break;
            }

            if (!imap_server_send(bio, c_data, c_n)) {
                break;
            }
        }
    }

close_server:
    BIO_free_all(bio);

close_client:
    close(c_fd);
}

bool imap_authenticate(int c_fd, BIO * s_bio, int s_fd) {
    bool succ = true;

    struct imap_cmd_stream *c_stream = imap_cmd_stream_create(c_fd);
    int maxfd = c_fd < s_fd ? s_fd : c_fd;

    size_t c_n;
    const char *c_data;

    while (1) {
        fd_set rfds;

        FD_ZERO(&rfds);
        FD_SET(c_fd, &rfds);
        FD_SET(s_fd, &rfds);

        int retval = select(maxfd+1, &rfds, NULL, NULL, NULL);

        if (retval < 0) {
            syslog(LOG_USER | LOG_ERR, "IMAP: select() error: %m");
            succ = false;
            goto close;
        }

        if (FD_ISSET(s_fd, &rfds)) {
            char s_data[RECV_BUF_SIZE];
            ssize_t n = BIO_read(s_bio, s_data, sizeof(s_data));

            if (n < 0) {
                succ = false;
                goto close;
            }
            else if (n == 0) {
                syslog(LOG_USER | LOG_NOTICE, "IMAP: Server closed connection");
                succ = false;
                goto close;
            }

            if (!imap_client_send(c_fd, s_data, n)) {
                succ = false;
                goto close;
            }
        }

        if (FD_ISSET(c_fd, &rfds)) {
            int ret = handle_client_command(c_stream, s_bio);

            if (ret == 1) {
                goto finish;
            }
            else if (ret == -1) {
                goto close;
            }
        }
    }

finish:
    // Send remaining client data in buffer to server
    c_data = imap_cmd_buffer(c_stream, &c_n);

    if (c_data) {
        succ = imap_server_send(s_bio, c_data, c_n);
    }

close:
    imap_cmd_stream_free(c_stream);
    return succ;
}


int handle_client_command(struct imap_cmd_stream *stream, BIO *s_bio) {
    struct imap_cmd cmd;
    bool wait = true;

    while (1) {
        ssize_t c_n = imap_cmd_next(stream, &cmd, wait);

        if (c_n < 0)
            return false;
        else if (c_n == 0)
            return !wait ? 0 : -1;

        switch (cmd.command) {
        case IMAP_CMD_LOGIN: {
            int ret = imap_login(imap_cmd_stream_fd(stream), s_bio, &cmd);

            if (ret) return ret;
        } break;

        default:
            if (!imap_server_send(s_bio, cmd.line, cmd.total_len)) {
                return -1;
            }
            break;
        }

        wait = false;
    }
}

int imap_login(int c_fd, BIO * s_bio, const struct imap_cmd *cmd) {
    int ret = 1;

    char *tag = xmalloc(cmd->tag_len + 1);
    memcpy(tag, cmd->tag, cmd->tag_len);
    tag[cmd->tag_len] = 0;

    char *user = imap_parse_string(cmd->param, cmd->param_len);

    if (!user) {
        ret = imap_login_syntax_error(c_fd, tag) ? 0 : -1;
        goto free_tag;
    }

    GList *accounts = goa_client_get_accounts(get_goaclient(NULL));
    GList *account = find_goaccount(accounts, user);

    if (!account) {
        syslog(LOG_USER | LOG_WARNING, "IMAP: Could not find GNOME Online Account for username %s", user);

        ret = imap_invalid_user(c_fd, tag) ? 0 : -1;
        goto free_user;
    }

    goa_error gerr;
    gchar *token = get_access_token(account, &gerr);

    if (!token) {
        ret = imap_auth_error(c_fd, gerr, tag) ? 0 : -1;
        goto free_accounts;
    }

    char *resp = xoauth2_make_client_response(user, token);
    if (!resp) {
        syslog(LOG_USER | LOG_ERR, "IMAP: Error formatting SASL client response mechanism: %m");
        ret = -1;

        goto free_token;
    }

    char *auth_cmd;
    if (asprintf(&auth_cmd, "%s AUTHENTICATE XOAUTH2 %s\r\n", tag, resp) == -1) {
        syslog(LOG_USER | LOG_ERR, "asprintf error (formatting IMAP AUTHENTICATE command): %m");
        ret = -1;
        goto free_resp;
    }

    // Send AUTHENTICATE command to server
    if (!imap_server_send(s_bio, auth_cmd, strlen(auth_cmd))) {
        ret = -1;
    }

    free(auth_cmd);

free_resp:
    free(resp);

free_token:
    g_free(token);

free_accounts:
    g_list_free_full(accounts, (GDestroyNotify)g_object_unref);

free_user:
    free(user);

free_tag:
    free(tag);

    return ret;
}


/* Error Reporting */

bool imap_invalid_user(int fd, const char *tag) {
    char *err;
    if (asprintf(&err, "%s NO Invalid username\r\n", tag) == -1) {
        syslog(LOG_USER | LOG_ERR, "asprintf (format IMAP LOGIN response): %m");
        return false;
    }

    bool ret = imap_client_send(fd, err, strlen(err));
    free(err);
    return ret;
}

bool imap_auth_error(int fd, goa_error gerr, const char *tag) {
    switch (gerr) {
    case ACCOUNT_ERROR_CRED: {
        char *err;
        if (asprintf(&err, "%s NO Account not authorized for IMAP\r\n", tag) == -1) {
            syslog(LOG_USER | LOG_ERR, "asprintf (format IMAP LOGIN response): %m");
            return false;
        }

        bool ret = imap_client_send(fd, err, strlen(err));
        free(err);
        return ret;
    } break;

    case ACCOUNT_ERROR_TOKEN: {
        char *err;
        if (asprintf(&err, "%s NO Error obtaining access token", tag) == -1) {
            syslog(LOG_USER | LOG_ERR, "asprintf (format IMAP LOGIN response): %m");
            return false;
        }

        bool ret = imap_client_send(fd, err, strlen(err));
        free(err);
        return ret;
    } break;
    }

    assert(false);
    return true;
}

bool imap_login_syntax_error(int fd, const char *tag) {
    char *err;
    if (asprintf(&err, "%s BAD Syntax error in username\r\n", tag) == -1) {
        syslog(LOG_USER | LOG_ERR, "asprintf (format IMAP LOGIN response): %m");
        return false;
    }

    bool ret = imap_client_send(fd, err, strlen(err));
    free(err);
    return ret;
}

/* Sending Data */

bool imap_server_send(BIO *bio, const char *data, size_t n) {
    while (n) {
        ssize_t s_n = BIO_write(bio, data, n);

        if (s_n < 0) {
            ssl_log_error("IMAP: Error sending data to server");
            return false;
        }

        n -= s_n;
        data += s_n;
    }

    return true;
}

bool imap_client_send(int fd, const char *data, size_t n) {
    while (n) {
        ssize_t c_n = send(fd, data, n, 0) ;

        if (c_n < 0) {
            syslog(LOG_USER | LOG_ERR, "IMAP: Error sending data to client: %m");
            return false;
        }

        n -= c_n;
        data += c_n;
    };

    return true;
}
