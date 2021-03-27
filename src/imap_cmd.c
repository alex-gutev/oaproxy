#include "imap_cmd.h"

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <syslog.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <openssl/bio.h>

#include "xmalloc.h"

#define OAP_CMD_BUF_SIZE 1024

#define CMD_LOGIN "LOGIN "
#define CMD_LOGIN_LEN 6

struct imap_cmd_stream {
    /** Client BIO stream */
    BIO *bio;

    /** Size of last IMAP command line */
    size_t size;

    /** Buffer into which IMAP command is read */
    char data[OAP_CMD_BUF_SIZE + 1];
};

/**
 * Parse an IMAP command.
 *
 * @param cmd Pointer to imap_cmd struct. On input the line, and
 *   total_len fields should be filled.
 *
 * @return True if the command was parsed successfully.
 */
static bool parse_cmd(struct imap_cmd *cmd);

/**
 * Parse the tag at the start of an IMAP command.
 *
 * @param cmd Pointer to IMAP command
 *
 * @return True if the tag was parsed successfully.
 */
static bool parse_tag(struct imap_cmd *cmd);

/**
 * Parse the command name.
 *
 * @param cmd Pointer to IMAP command
 *
 * @return True if the command name was parsed successfully.
 */
static bool parse_cmd_name(struct imap_cmd *cmd);

/**
 * Parse a quoted string.
 *
 * @param data Data buffer from which to parse
 * @param n Number of bytes in data buffer
 *
 * @return Pointer to the parsed string. NULL if there is a syntax
 *   error.
 */
static char * parse_quoted_str(const char *data, size_t n);


/* Implementation */

struct imap_cmd_stream * imap_cmd_stream_create(int fd, bool close) {
    // Create socket BIO
    BIO *sbio = BIO_new_socket(fd, close);
    if (!sbio) return NULL;

    // Create Buffered BIO
    BIO *bbio = BIO_new(BIO_f_buffer());
    if (!bbio) goto free_sbio;

    // Chain BIOs
    BIO *chain = BIO_push(bbio, sbio);
    if (!chain) goto free_bbio;

    // Create stream struct

    struct imap_cmd_stream *stream = xmalloc(sizeof(struct imap_cmd_stream));

    stream->bio = chain;
    stream->size = 0;

    return stream;

free_bbio:
    BIO_free_all(bbio);

free_sbio:
    BIO_free_all(sbio);

    return NULL;
}

void imap_cmd_stream_free(struct imap_cmd_stream *stream) {
    assert(stream != NULL);

    BIO_free_all(stream->bio);
    free(stream);
}

int imap_cmd_stream_fd(struct imap_cmd_stream *stream) {
    return BIO_get_fd(stream->bio, NULL);
}

ssize_t imap_cmd_next(struct imap_cmd_stream *stream, struct imap_cmd *cmd, const bool wait) {
    if (!wait && !BIO_ctrl_pending(stream->bio))
        return 0;

    ssize_t n = BIO_gets(stream->bio, stream->data, OAP_CMD_BUF_SIZE);
    if (n <= 0) {
        return n;
    }

    stream->size = n;

    cmd->line = stream->data;
    cmd->total_len = n;

    parse_cmd(cmd);
    return n;
}

bool parse_cmd(struct imap_cmd *cmd) {
    cmd->command = IMAP_CMD;

    cmd->tag = NULL;
    cmd->tag_len = 0;
    cmd->param = NULL;
    cmd->param_len = 0;

    if (!parse_tag(cmd))
        return false;

    return parse_cmd_name(cmd);
}

bool parse_tag(struct imap_cmd *cmd) {
    const char *data = cmd->line;

    cmd->tag = data;
    cmd->tag_len = 0;

    while (*data && *data != ' ') {
        if (!isalnum(*data++)) {
            return false;
        }

        cmd->tag_len++;
    }

    return true;
}

bool parse_cmd_name(struct imap_cmd *cmd) {
    const char *data = cmd->tag + cmd->tag_len;

    while (*data && *data == ' ') {
        data++;
    };

    if (strncasecmp(CMD_LOGIN, data, CMD_LOGIN_LEN) == 0) {
        cmd->command = IMAP_CMD_LOGIN;
        cmd->param = data + CMD_LOGIN_LEN;
        cmd->param_len = ((cmd->line + cmd->total_len) - cmd->param) - 2;
    }

    return true;
}

ssize_t imap_cmd_buffer(struct imap_cmd_stream *stream, char *buf, size_t size) {
    size_t pending = BIO_ctrl_pending(stream->bio);

    if (pending < size) {
        size = pending;
    }

    size_t total = 0;

    while (size) {
        ssize_t n = BIO_read(stream->bio, buf, size);

        if (n < 0) {
            return n;
        }
        else if (n == 0) {
            break;
        }

        size -= n;
        total += n;
        buf += n;
    }

    return total;
}

/* Parsing Strings */

char * imap_parse_string(const char *data, size_t n) {
    // Skip whitespace
    while (n && *data == ' ') {
        n--;
        data++;
    }

    // Check if quoted
    if (*data == '"') {
        return parse_quoted_str(data + 1, n - 1);
    }

    size_t buf_size = 255, index = 0;
    char *str_buf = xmalloc(buf_size);

    while (n--) {
        char c = *data++;

        if (c <= 0x1f || c == 0x7f ||
            c == '(' || c == ')' || c == '{' ||
            c == '%' || c == '*' || c == '"' ||
            c == '\\' || isspace(c))
            break;

        if (index >= buf_size) {
            buf_size *= 2;
            str_buf = xrealloc(str_buf, buf_size);
        }

        str_buf[index++] = c;
    }

    str_buf = xrealloc(str_buf, index + 1);
    str_buf[index] = 0;

    return str_buf;
}

char * parse_quoted_str(const char *data, size_t n) {
    size_t buf_size = 255, index = 0;
    char *str_buf = xmalloc(buf_size);

    while (n--) {
        char c = *data++;

        if (c == '"') {
            str_buf = xrealloc(str_buf, index + 1);
            str_buf[index] = 0;

            return str_buf;
        }

        if (index >= buf_size) {
            buf_size *= 2;
            str_buf = xrealloc(str_buf, buf_size);
        }

        if (c == '\\' && n) {
            str_buf[index++] = *data++;
            n--;
        }
        else {
            str_buf[index++] = c;
        }
    }

    free(str_buf);
    return NULL;
}
