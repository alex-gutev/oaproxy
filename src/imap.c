#define _GNU_SOURCE

#include "imap.h"

#include <stdbool.h>
#include <syslog.h>
#include <stdio.h>
#include <ctype.h>
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
#include "imap_reply.h"

#define RECV_BUF_SIZE 512 * 4

#define IMAP_CAP_AUTH "AUTH="
#define IMAP_CAP_AUTH_LEN 5

#define IMAP_CAP_LOGINDISABLED "LOGINDISABLED"
#define IMAP_CAP_LOGINDISABLED_LEN 13

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
 * Forward the remaining data in the client command stream's buffer to
 * the server.
 *
 * @param stream Client command stream
 * @param s_bio Server BIO object
 *
 * @return True if all the data in the stream was forwarded
 *   successfully.
 */
static bool send_client_buf_data(struct imap_cmd_stream *stream, BIO *s_bio);

/**
 * Forward the remaining data in the server reply stream's buffer to
 * the client.
 *
 * @param stream Server reply stream
 * @param c_fd   Client socket file descriptor
 *
 * @return True if all the data in the stream was forwarded
 *   successfully.
 */
static bool send_server_buf_data(struct imap_reply_stream *stream, int c_fd);

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


/* Handling Server Replies */

/**
 * Handle a reply from the server.
 *
 * @param stream IMAP reply stream
 * @param c_fd   Client socket descriptor
 *
 * @return True if the reply was handled successfully, false if there
 *   was an error sending/receiving data.
 */
static bool handle_server_reply(struct imap_reply_stream *stream, int c_fd);

/**
 * Process a CAPABILITY response from the server. All AUTH= methods
 * are removed as well as the LOGINDISABLED response before forwarding
 * the response to the client.
 *
 * @param c_fd Client socket file descriptor
 * @param reply IMAP reply
 *
 * @return True if the reply was handled successfully, false if there
 *   was an error sending/receiving data.
 */
static bool send_capabilites(int c_fd, const struct imap_reply *reply);

/**
 * Filter a portion of a CAPABILITY response.
 *
 * AUTH methods and the LOGINDISABLED capability are
 * skipped. Remaining capabilities are copied to the output buffer.
 *
 * @param data Pointer to the capability to filter.
 *
 * @param n Pointer to variable storing number of remaining bytes in
 *   response string. Updated on output.
 *
 * @param out Output buffer to which capability is written. Must be at
 *   least as large as the length of the capability response.
 *
 * @param pos Pointer to variable storing position within output
 *   buffer at which to write next byte. Updated on output.
 *
 * @return Pointer to the first byte following the current capability.
 */
static const char * filter_capability(const char *data, size_t *n, char *out, size_t *pos);

/**
 * Skip past the current bytes in the data buffer until one byte past
 * the next whitespace or till the nearest carriage return.
 *
 * @param data Data buffer.
 *
 * @param n On input pointer to size of buffer. On output this is
 *   updated to the number of remaining bytes from the new position.
 *
 * @return Pointer to the new position in the buffer.
 */
static const char *skip_to_space(const char *data, size_t *n);

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
    BIO *bio = server_connect(host);
    if (!bio) {
        goto close_client;
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
            syslog(LOG_ERR, "IMAP: select() error: %m");
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
                syslog(LOG_NOTICE, "IMAP: Server closed connection");
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
                syslog(LOG_ERR, "IMAP: Error sending data to client: %m");
                break;
            }
            else if (c_n == 0) {
                syslog(LOG_NOTICE, "IMAP: Client closed connection");
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

    struct imap_cmd_stream *c_stream = imap_cmd_stream_create(c_fd, false);
    if (!c_stream) {
        return false;
    }

    struct imap_reply_stream *s_stream = imap_reply_stream_create(s_bio);
    if (!s_stream) {
        succ = false;
        goto close_cmd_stream;
    }

    int maxfd = c_fd < s_fd ? s_fd : c_fd;

    while (1) {
        fd_set rfds;

        FD_ZERO(&rfds);
        FD_SET(c_fd, &rfds);
        FD_SET(s_fd, &rfds);

        int retval = select(maxfd+1, &rfds, NULL, NULL, NULL);

        if (retval < 0) {
            syslog(LOG_ERR, "IMAP: select() error: %m");
            succ = false;
            goto close;
        }

        if (FD_ISSET(s_fd, &rfds)) {
            if (!handle_server_reply(s_stream, c_fd)) {
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
    if (!send_client_buf_data(c_stream, s_bio)) {
        succ = false;
        goto close;
    }

    // Send remaining server relies in buffer to client
    succ = send_server_buf_data(s_stream, c_fd);

close:
    imap_reply_stream_free(s_stream);

close_cmd_stream:
    imap_cmd_stream_free(c_stream);
    return succ;
}

bool send_client_buf_data(struct imap_cmd_stream *stream, BIO *s_bio) {
    char buf[1024];

    ssize_t n;

    while ((n = imap_cmd_buffer(stream, buf, sizeof(buf)))) {
        if (n < 0)
            return false;

        if (!imap_server_send(s_bio, buf, n))
            return false;
    }

    return true;
}

bool send_server_buf_data(struct imap_reply_stream *stream, int c_fd) {
    char buf[1024];

    ssize_t n;

    while ((n = imap_reply_buffer(stream, buf, sizeof(buf)))) {
        if (n < 0)
            return false;

        if (!imap_client_send(c_fd, buf, n))
            return false;
    }

    return true;
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
        syslog(LOG_WARNING, "IMAP: Could not find GNOME Online Account for username %s", user);

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
        syslog(LOG_ERR, "IMAP: Error formatting SASL client response mechanism: %m");
        ret = -1;

        goto free_token;
    }

    char *auth_cmd;
    if (asprintf(&auth_cmd, "%s AUTHENTICATE XOAUTH2 %s\r\n", tag, resp) == -1) {
        syslog(LOG_ERR, "IMAP: asprintf error (formatting AUTHENTICATE command): %m");
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
        syslog(LOG_ERR, "IMAP: asprintf (format LOGIN response): %m");
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
            syslog(LOG_ERR, "IMAP: asprintf (format LOGIN response): %m");
            return false;
        }

        bool ret = imap_client_send(fd, err, strlen(err));
        free(err);
        return ret;
    } break;

    case ACCOUNT_ERROR_TOKEN: {
        char *err;
        if (asprintf(&err, "%s NO Error obtaining access token", tag) == -1) {
            syslog(LOG_ERR, "IMAP: asprintf (format LOGIN response): %m");
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
        syslog(LOG_ERR, "IMAP: asprintf (format LOGIN response): %m");
        return false;
    }

    bool ret = imap_client_send(fd, err, strlen(err));
    free(err);
    return ret;
}


/* Handling Server Reply */

bool handle_server_reply(struct imap_reply_stream *stream, int c_fd) {
    struct imap_reply reply;
    bool wait = true;

    while (1) {
        ssize_t s_n = imap_reply_next(stream, &reply, wait);

        if (s_n < 0)
            return false;
        else if (s_n == 0)
            return !wait;

        switch (reply.code) {
        case IMAP_REPLY_CAP:
            if (!send_capabilites(c_fd, &reply))
                return false;

            break;

        default:
            if (!imap_client_send(c_fd, reply.line, reply.total_len))
                return false;

            break;
        }

        wait = false;
    }
}

bool send_capabilites(int c_fd, const struct imap_reply *reply) {
    const char *data = reply->data;
    size_t n = reply->data_len;

    char *new_cap = xmalloc(reply->total_len);
    size_t pos = data - reply->line;

    memcpy(new_cap, reply->line, pos);

    while (n) {
        data = filter_capability(data, &n, new_cap, &pos);
    }

    new_cap[pos++] = '\r';
    new_cap[pos++] = '\n';

    bool ret = imap_client_send(c_fd, new_cap, pos);
    free(new_cap);

    return ret;
}

static const char * filter_capability(const char *data, size_t *n, char *out, size_t *pos) {
    // Skip space

    size_t i = *pos;
    while (*n && isspace(*data)) {
        out[i++] = *data;
        data++;
        *n = *n - 1;
    }

    if ((*data == 'A' || *data == 'a') &&
        strncasecmp(data, IMAP_CAP_AUTH, IMAP_CAP_AUTH_LEN) == 0) {
        return skip_to_space(data, n);
    }
    else if ((*data == 'L' || *data == 'l') &&
             strncasecmp(data, IMAP_CAP_LOGINDISABLED, IMAP_CAP_LOGINDISABLED_LEN) == 0 &&
             isspace(data[IMAP_CAP_LOGINDISABLED_LEN])) {
        return skip_to_space(data, n);
    }
    else if (*n) {
        while (*n && !isspace(*data)) {
            out[i++] = *data;
            data++;
            *n = *n - 1;
        }

        *pos = i;
    }

    return data;
}

const char *skip_to_space(const char *data, size_t *n) {
    size_t sz = *n;
    while (sz && *data != '\r' && *data != '\n') {
        if (*data == ' ') {
            break;
        }

        data++;
        sz--;
    }

    *n = sz;
    return data;
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
            syslog(LOG_ERR, "IMAP: Error sending data to client: %m");
            return false;
        }

        n -= c_n;
        data += c_n;
    };

    return true;
}
