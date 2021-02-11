#include "smtp_cmd.h"

#include <string.h>
#include <syslog.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>

#define CMD_AUTH_PLAIN "AUTH PLAIN"
#define CMD_AUTH_PLAIN_LEN 10

#define CMD_DATA "DATA"
#define CMD_DATA_LEN 4

/**
 * Read an SMTP command from the client.
 *
 * Reads data until a complete command (terminated by a CRLF) is
 * read.
 *
 * @param c_fd Client socket file descriptor
 * @param buf Buffer in which to read command
 * @param n Buffer size
 *
 * @return Number of bytes read. -1 if an error occurred.
 */
static ssize_t read_cmd(int c_fd, char *buf, size_t n);

/**
 * Parse an SMTP command from the client response.
 *
 * @param stream SMTP command stream
 *
 * @param command Pointer to smtp_command struct. On input the pointer
 *   to the start of the command data should be filled. On output, it
 *   is filled with parsed command data.
 *
 * @return True if command was parsed successfully.
 */
static bool parse_cmd(struct smtp_cmd_stream *stream, struct smtp_cmd *command);

/**
 * Find the start of the command data.
 *
 * @param data Pointer to first byte following command.
 * @param size Number of bytes in data.
 *
 * @return Pointer to first data byte.
 */
static const char *cmd_data_start(const char *data, size_t size);

/**
 * Determine the number of bytes comprising the command data.
 *
 * @param data Pointer to start of command data.
 * @param size Number of remaining bytes in command line.
 *
 * @return Number of bytes comprising command data.
 */
static size_t cmd_data_len(const char *data, size_t size);


/* Implementations */

void smtp_cmd_stream_init(struct smtp_cmd_stream *stream, int fd) {
    stream->fd = fd;
    stream->size = 0;

    stream->in_data = false;
}

ssize_t smtp_cmd_next(struct smtp_cmd_stream *stream, struct smtp_cmd *cmd) {
    ssize_t n = stream->in_data ? recv(stream->fd, stream->data, OAP_CMD_BUF_SIZE, 0) :
        read_cmd(stream->fd, stream->data, OAP_CMD_BUF_SIZE);

    if (n <= 0) {
        return n;
    }

    stream->size = n;

    if (!stream->in_data) {
        parse_cmd(stream, cmd);
        stream->in_data = cmd->command == SMTP_CMD_DATA;
    }

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

bool parse_cmd(struct smtp_cmd_stream *stream, struct smtp_cmd *command) {
    if (stream->size > CMD_AUTH_PLAIN_LEN &&
        strncasecmp(CMD_AUTH_PLAIN, stream->data, CMD_AUTH_PLAIN_LEN) == 0 &&
        (stream->data[CMD_AUTH_PLAIN_LEN] == ' ' ||
         stream->data[CMD_AUTH_PLAIN_LEN] == '\r' ||
         stream->data[CMD_AUTH_PLAIN_LEN] == '\n')) {

        command->command = SMTP_CMD_AUTH;
        command->data = cmd_data_start(stream->data + CMD_AUTH_PLAIN_LEN, stream->size - CMD_AUTH_PLAIN_LEN);
        command->len = cmd_data_len(command->data, (stream->data + stream->size) - command->data);

        return true;
    }

    if (stream->size > CMD_DATA_LEN &&
        strncasecmp(CMD_DATA, stream->data, CMD_DATA_LEN) == 0 &&
        (stream->data[CMD_DATA_LEN] == ' ' ||
         stream->data[CMD_DATA_LEN] == '\r' ||
         stream->data[CMD_DATA_LEN] == '\n')) {

        stream->in_data = true;

        command->command = SMTP_CMD_DATA;
        command->data = NULL;
        command->len = 0;
    }

    command->command = SMTP_CMD;
    command->data = NULL;
    command->len = 0;

    return true;
}

const char *cmd_data_start(const char *data, size_t size) {
    while (size-- && *data == ' ') {
        data++;
    }

    return data;
}

size_t cmd_data_len(const char *data, size_t size) {
    size_t len = 0;

    while (size--) {
        if (*data == '\r' || *data == '\n')
            return len;

        data++;
        len++;
    }

    return len;
}
