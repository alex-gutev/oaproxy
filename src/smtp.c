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


/* Authentication */

/**
 * Handle AUTH command from client.
 *
 * Authenticate the user, corresponding to a GOA account, using
 * XOAuth2.
 *
 * @param stream Client command stream
 * @param s_bio  Server OpenSSL Bio Object
 * @param cmd    SMTP command
 *
 * @return Returns true if the command was processed
 *   successfully. This does not mean the user was authenticated, only
 *   that all read/write commands succeeded and that the proxy loop
 *   should continue.
 */
static bool smtp_handle_auth(struct smtp_cmd_stream *stream, BIO *s_bio, const struct smtp_cmd *cmd);

/**
 * Request credentials for AUTH PLAIN from client.
 *
 * @param stream SMTP command stream.
 * @param cmd SMTP command.
 *
 * @return True if the credentials were received successfully. False
 *   if there was an error sending the request for credentials or
 *   receiving the reply.
 */
static bool smtp_get_credentials(struct smtp_cmd_stream *stream, struct smtp_cmd *cmd);

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

/**
 * Report gnome online account error to SMTP client.
 *
 * @param fd client socket descriptor
 * @param gerr GOA account error
 *
 * @return True if the error was reported successfully, false
 *   otherwise.
 */
static bool smtp_auth_error(int fd, goa_error gerr);


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
static bool smtp_server_handle_reply(int c_fd, struct smtp_reply_stream *s_stream, struct smtp_cmd_stream *c_stream);


/* Implementation */

void smtp_handle_client(int c_fd, const char *host) {
    BIO *bio = server_connect(host);

    if (!bio) {
        close(c_fd);
        return;
    }

    int s_fd = BIO_get_fd(bio, NULL);
    int maxfd = c_fd < s_fd ? s_fd : c_fd;

    struct smtp_cmd_stream * c_stream = smtp_cmd_stream_create(c_fd);

    if (!c_stream) {
        BIO_free_all(bio);
        close(c_fd);
        return;
    }

    struct smtp_reply_stream * s_stream = smtp_reply_stream_create(bio);

    if (!s_stream) {
        BIO_free_all(bio);
        goto close_cmd_stream;
    }

    while (1) {
        fd_set rfds;

        FD_ZERO(&rfds);
        FD_SET(c_fd, &rfds);
        FD_SET(s_fd, &rfds);

        int retval = select(maxfd+1, &rfds, NULL, NULL, NULL);

        if (retval < 0) {
            syslog(LOG_ERR, "SMTP: select() error: %m");
            break;
        }

        if (FD_ISSET(s_fd, &rfds)) {
            if (!smtp_server_handle_reply(c_fd, s_stream, c_stream))
                break;
        }
        if (FD_ISSET(c_fd, &rfds)) {
            if (!smtp_client_handle_cmd(c_stream, bio))
                break;
        }
    }

    smtp_reply_stream_free(s_stream);

close_cmd_stream:
    smtp_cmd_stream_free(c_stream);
}


/* Handling SMTP Client Commands */

bool smtp_client_handle_cmd(struct smtp_cmd_stream *stream, BIO *s_bio) {
    struct smtp_cmd cmd;

    do {
        ssize_t c_n = smtp_cmd_next(stream, &cmd);

        if (c_n < 0) {
            syslog(LOG_ERR, "SMTP: Error reading data from client: %m");
            return false;
        }
        else if (c_n == 0) {
            syslog(LOG_NOTICE, "SMTP: Client closed connection");
            return false;
        }

        switch (cmd.command) {
        case SMTP_CMD_AUTH:
            if (cmd.data_len == 0 && !smtp_get_credentials(stream, &cmd)) {
                return false;
            }

            if (!smtp_handle_auth(stream, s_bio, &cmd))
                return false;

            break;

        default:
            if (!smtp_server_send(s_bio, cmd.line, cmd.total_len))
                return false;
            break;
        }
    } while (smtp_cmd_stream_pending(stream));

    return true;
}



/* Authentication */

static bool smtp_get_credentials(struct smtp_cmd_stream *stream, struct smtp_cmd *cmd) {
    char resp[] = "334\r\n";

    if (!smtp_client_send(smtp_cmd_stream_fd(stream), resp, strlen(resp))) {
        return false;
    }

    ssize_t n = smtp_cmd_next(stream, cmd);
    return n > 0;
}

bool smtp_handle_auth(struct smtp_cmd_stream *stream, BIO *s_bio, const struct smtp_cmd *cmd) {
    bool succ = true;
    char *user = smtp_parse_auth_user(cmd->data, cmd->data_len);

    if (!user) {
        char err[] = "501 Syntax error in credentials\r\n";
        succ = smtp_client_send(smtp_cmd_stream_fd(stream), err, strlen(err));

        goto end;
    }

    GList *accounts = goa_client_get_accounts(get_goaclient(NULL));
    GList *account = find_goaccount(accounts, user);

    if (account) {
        succ = smtp_auth_client(smtp_cmd_stream_fd(stream), s_bio, account, user);
    }
    else {
        syslog(LOG_WARNING, "SMTP: Could not find GNOME Online Account for username %s", user);

        char err[] = "535 Invalid username or password\r\n";
        succ = smtp_client_send(smtp_cmd_stream_fd(stream), err, strlen(err));
    }

    g_list_free_full(accounts, (GDestroyNotify)g_object_unref);

end:
    free(user);
    return succ;
}

char * smtp_parse_auth_user(const char *data, size_t n) {
    char *dec = base64_decode(data, &n);
    if (!dec) return NULL;

    // Find first NUL character
    size_t user_start = 0;
    while (n-- && dec[user_start++]);

    // Find end of username
    size_t pass_start = user_start;
    while (n-- && dec[pass_start++]);

    size_t user_len = pass_start - user_start;
    if (user_len <= 1) goto error;

    char *user = malloc(user_len);
    memcpy(user, dec + user_start, user_len);

    free(dec);
    return user;

error:
    free(dec);
    return NULL;
}

bool smtp_auth_client(int fd, BIO *bio, GList *account, const char *user) {
    bool succ = true;

    // Get Access Token

    goa_error gerr;
    gchar *token = get_access_token(account, &gerr);

    if (!token) {
        return smtp_auth_error(fd, gerr);
    }

    char *resp = xoauth2_make_client_response(user, token);

    if (!resp) {
        syslog(LOG_ERR, "SMTP: Error formatting SASL client response mechanism: %m");
        succ = false;

        goto free_token;
    }

    char *auth_cmd;
    if (asprintf(&auth_cmd, "AUTH XOAUTH2 %s\r\n", resp) == -1) {
        syslog(LOG_ERR, "SMTP: asprintf error (formatting AUTH command): %m");
        succ = false;
        goto free_resp;
    }

    // Send Authentication Command to server

    if (!smtp_server_send(bio, auth_cmd, strlen(auth_cmd))) {
        succ = false;
    }

    free(auth_cmd);

free_resp:
    free(resp);

free_token:
    g_free(token);

    return succ;
}

bool smtp_auth_error(int fd, goa_error gerr) {
    switch (gerr) {
    case ACCOUNT_ERROR_CRED: {
        const char *err = "535 Account not authorized for SMTP\r\n";
        return smtp_client_send(fd, err, strlen(err));
    } break;

    case ACCOUNT_ERROR_TOKEN: {
        const char *err = "451 Error obtaining access token\r\n";
        return smtp_client_send(fd, err, strlen(err));
    } break;
    }

    assert(false);
    return true;
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
            syslog(LOG_ERR, "SMTP: Error sending data to client: %m");
            return false;
        }

        n -= c_n;
        data += c_n;
    };

    return true;
}


/* Handle SMTP server response */

bool smtp_server_handle_reply(int c_fd, struct smtp_reply_stream *s_stream, struct smtp_cmd_stream *c_stream) {
    struct smtp_reply reply;
    reply.last = false;

    while (!reply.last) {
        if (smtp_reply_next(s_stream, &reply) <= 0)
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
            smtp_cmd_stream_data_mode(c_stream, reply.code == 354);

            if (!smtp_client_send(c_fd, reply.data, reply.total_len))
                return false;

            break;
        }
    }

    return true;
}
