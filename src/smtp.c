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

#define RECV_BUF_SIZE 512 * 4

#define CMD_AUTH_PLAIN "AUTH PLAIN"
#define CMD_AUTH_PLAIN_LEN 10

#define CMD_DATA "DATA"
#define CMD_DATA_LEN 4

/**
 * SMTP State.
 *
 * Keeps track of whether in Data or command state.
 */
struct smtp_client_state {
    /* True when in Data state */
    bool in_data;
};

/**
 * SMTP Command ID Constants
 */
typedef enum smtp_command_type {
    /* Generic Command */
    SMTP_CMD = 0,
    /* AUTH - Authorization Command */
    SMTP_AUTH = 1,
    /* QUIT - End Session Command */
    SMTP_DATA
} smtp_command_type;

/**
 * SMTP Command
 */
struct smtp_command {
    /** Command */
    smtp_command_type command;
    /** Command data (following command) */
    const char *data;
    /** Command data length */
    size_t len;
};

/* Handling SMTP Client Command */

/**
 * Read and handle/forward an SMTP command from the client.
 *
 * @param state SMTP client state
 * @param c_fd Client socket file descriptor
 * @param s_bio Server BIO object
 *
 * @return true if the command was handled successfully, false
 *   otherwsie.
 */
static bool smtp_client_handle_cmd(struct smtp_client_state *state, int c_fd, BIO *s_bio);

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


/* Command Parsing */

/**
 * Parse an SMTP command from the client response.
 *
 * @param state SMTP client state
 *
 * @param response Client response
 *
 * @param len Number of bytes in client response
 *
 * @param command Pointer to smtp_command struct. Filled with command
 *   data on output.
 *
 * @return True if command was parsed successfully.
 */
static bool smtp_parse_command(struct smtp_client_state *state, const char *response, size_t len, struct smtp_command *command);

/**
 * Find the start of the command auxiliary data.
 *
 * @param data Pointer to first byte following command.
 * @param size Number of bytes in data.
 *
 * @return Pointer to first data byte.
 */
static const char *smtp_command_data_start(const char *data, size_t size);

/**
 * Determine the number of bytes comprising the auxiliary data.
 *
 * @param data Pointer to command data.
 * @param size Number of bytes of remaining response data.
 *
 * @return Number of bytes which comprising command data.
 */
static size_t smtp_command_data_len(const char *data, size_t size);

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

    struct smtp_client_state client_state;
    client_state.in_data = false;

    struct smtp_reply_stream s_stream;
    smtp_reply_stream_init(&s_stream, bio);

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
            if (!smtp_server_handle_reply(c_fd, &s_stream))
                break;
        }
        else if (FD_ISSET(c_fd, &rfds)) {
            if (!smtp_client_handle_cmd(&client_state, c_fd, bio))
                break;
        }
    }

close_server:
    BIO_free_all(bio);

close_client:
    close(c_fd);
}


/* Handling SMTP Client Commands */

bool smtp_client_handle_cmd(struct smtp_client_state *state, int c_fd, BIO *s_bio) {
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

    struct smtp_command cmd;
    smtp_parse_command(state, c_data, c_n, &cmd);

    switch (cmd.command) {
    case SMTP_AUTH: {
        const char *user = smtp_parse_auth_user(cmd.data, cmd.len);

        if (user) {
            GList *accounts = goa_client_get_accounts(get_goaclient(NULL));
            GList *account = find_goaccount(accounts, user);

            free(user);

            if (account) {
                bool auth = smtp_auth_client(c_fd, s_bio, account, user);
                g_list_free_full(accounts, (GDestroyNotify)g_object_unref);

                return auth;
            }

            syslog(LOG_USER | LOG_WARNING, "Could not find GNOME Online Account for username %s", user);

            g_list_free_full(accounts, (GDestroyNotify)g_object_unref);
        }
    }

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


/* Parsing SMTP Commands */

bool smtp_parse_command(struct smtp_client_state *state, const char *response, size_t len, struct smtp_command *command) {
    if (len > CMD_AUTH_PLAIN_LEN &&
        strncasecmp(CMD_AUTH_PLAIN, response, CMD_AUTH_PLAIN_LEN) == 0 &&
        (response[CMD_AUTH_PLAIN_LEN] == ' ' ||
         response[CMD_AUTH_PLAIN_LEN] == '\r' ||
         response[CMD_AUTH_PLAIN_LEN] == '\n')) {

        command->command = SMTP_AUTH;
        command->data = smtp_command_data_start(response + CMD_AUTH_PLAIN_LEN, len - CMD_AUTH_PLAIN_LEN);
        command->len = smtp_command_data_len(command->data, (response + len) - command->data);

        return true;
    }

    if (len > CMD_DATA_LEN &&
        strncasecmp(CMD_DATA, response, CMD_DATA_LEN) == 0 &&
        (response[CMD_DATA_LEN] == ' ' ||
         response[CMD_DATA_LEN] == '\r' ||
         response[CMD_DATA_LEN] == '\n')) {

        command->command = SMTP_DATA;
        command->data = NULL;
        command->len = 0;
    }

    command->command = SMTP_CMD;
    command->data = NULL;
    command->len = 0;

    return true;
}

const char *smtp_command_data_start(const char *data, size_t size) {
    while (size-- && *data == ' ') {
        data++;
    }

    return data;
}

size_t smtp_command_data_len(const char *data, size_t size) {
    size_t len = 0;

    while (size--) {
        if (*data == '\r' || *data == '\n')
            return len;

        data++;
        len++;
    }

    return len;
}

const char * smtp_parse_auth_user(const char *data, size_t n) {
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
