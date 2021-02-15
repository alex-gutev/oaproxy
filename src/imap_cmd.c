#include "imap_cmd.h"

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

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
    /** Buffer into which IMAP command is read */
    char data[OAP_CMD_BUF_SIZE + 1];
};

/**
 * Read an IMAP command from the client.
 *
 * Reads data until a complete command line (terminated by CRLF) is
 * read.
 *
 * @param fd Client socket file descriptor.
 * @param buf Buffer into which to read command
 * @param n Buffer size
 *
 * @return Number of bytes read. -1 if an error occurred.
 */
static ssize_t read_cmd(int fd, char *buf, size_t n);

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

    return stream;
}

void imap_cmd_stream_free(struct imap_cmd_stream *stream) {
    assert(stream != NULL);
    free(stream);
}


ssize_t imap_cmd_next(struct imap_cmd_stream *stream, struct imap_cmd *cmd) {
    ssize_t n = read_cmd(stream->fd, stream->data, OAP_CMD_BUF_SIZE);

    if (n <= 0) return n;

    stream->data[n] = 0;
    stream->size = n;

    cmd->line = stream->data;
    cmd->total_len = n;

    parse_cmd(cmd);

    return n;
}

ssize_t read_cmd(int fd, char *buf, size_t n) {
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
    char *data = cmd->line;
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
    char *data = cmd->tag + cmd->tag_len;
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
            str_buf[index] = *data++;
            n--;
        }
        else {
            str_buf[index] = c;
        }
    }

    free(str_buf);
    return NULL;
}
