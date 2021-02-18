#include "imap_cmd.h"

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <syslog.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "xmalloc.h"

#define OAP_CMD_BUF_SIZE 1024

#define CMD_LOGIN "LOGIN "
#define CMD_LOGIN_LEN 6

struct imap_cmd_stream {
    /** Socket File Descriptor */
    int fd;

    /** Size of last IMAP command line */
    size_t size;

    /**
     * Offset within the buffer to first byte of unprocessed data.
     */
    size_t offset;

    /** Buffer into which IMAP command is read */
    char data[OAP_CMD_BUF_SIZE + 1];
};

/**
 * Return the length of the next command in the data buffer.
 *
 * @param data Pointer to data buffer
 * @param sz Number of bytes in buffer
 *
 * @return Length of the buffer, or 0 if there isn't a complete
 *   command line in the buffer.
 */
static size_t cmd_length(const char *data, size_t sz);

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

struct imap_cmd_stream * imap_cmd_stream_create(int fd) {
    struct imap_cmd_stream *stream = xmalloc(sizeof(struct imap_cmd_stream));

    stream->fd = fd;
    stream->size = 0;
    stream->offset = 0;

    return stream;
}

void imap_cmd_stream_free(struct imap_cmd_stream *stream) {
    assert(stream != NULL);
    free(stream);
}

int imap_cmd_stream_fd(struct imap_cmd_stream *stream) {
    return stream->fd;
}

ssize_t imap_cmd_next(struct imap_cmd_stream *stream, struct imap_cmd *cmd, const bool wait) {
    while (1) {
        // Check if there is data left in the stream buffer
        if (stream->offset < stream->size) {
            size_t len = cmd_length(stream->data + stream->offset, stream->size - stream->offset);

            // If complete return command
            if (len) {
                cmd->line = stream->data + stream->offset;
                cmd->total_len = len;

                parse_cmd(cmd);

                stream->offset += len;
                return len;
            }

            // Move partial command to beginning of buffer
            if (stream->offset) {
                memmove(stream->data, stream->data + stream->offset, stream->size - stream->offset);
                stream->size -= stream->offset;
                stream->offset = 0;
            }
        }
        else {
            stream->offset = 0;
            stream->size = 0;
        }

        if (!wait)
            return 0;

        // Read next block of data
        ssize_t n = recv(stream->fd, stream->data + stream->size, OAP_CMD_BUF_SIZE - stream->size, 0);

        if (n < 0) {
            syslog(LOG_USER | LOG_ERR, "IMAP: Error reading command from client: %m");
            return n;
        }
        else if (n == 0) {
            syslog(LOG_USER | LOG_ERR, "IMAP client closed connection.");
            return 0;
        }

        stream->size += n;
    }
}

size_t cmd_length(const char *data, size_t sz) {
    size_t total = 0;

    while (sz--) {
        char c = *data++;

        if (sz && c == '\r' && *data == '\n') {
            return total + 2;
        }

        total++;
    }

    return 0;
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
    size_t n = cmd->total_len;

    cmd->tag = data;
    cmd->tag_len = 0;

    while (n-- && *data != ' ') {
        if (!isalnum(*data++)) {
            return false;
        }

        cmd->tag_len++;
    }

    return true;
}

bool parse_cmd_name(struct imap_cmd *cmd) {
    const char *data = cmd->tag + cmd->tag_len;
    size_t n = cmd->total_len - cmd->tag_len;

    while (n && *data == ' ') {
        n--;
        data++;
    };

    if (strncasecmp(CMD_LOGIN, data, CMD_LOGIN_LEN) == 0) {
        cmd->command = IMAP_CMD_LOGIN;
        cmd->param = data + CMD_LOGIN_LEN;
        cmd->param_len = n - 2 - CMD_LOGIN_LEN;
    }

    return true;
}

const char *imap_cmd_buffer(struct imap_cmd_stream *stream, size_t *size) {
    if (stream->offset < stream->size) {
        *size = stream->size - stream->offset;
        return stream->data + stream->offset;
    }

    return NULL;
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
            c == '\\' || c == ' ')
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
