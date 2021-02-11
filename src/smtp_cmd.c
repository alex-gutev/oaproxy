#include "smtp_cmd.h"

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdio.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "xmalloc.h"

#define OAP_CMD_BUF_SIZE 1024

#define CMD_AUTH_PLAIN "AUTH PLAIN"
#define CMD_AUTH_PLAIN_LEN 10

#define CMD_DATA "DATA"
#define CMD_DATA_LEN 4

#define DATA_TERM "\r\n.\r\n"
#define DATA_TERM_LEN 5


struct smtp_cmd_stream {
    /* File descriptor */
    int fd;

    /**
     * True if sending message data. False if sending SMTP commands.
     */
    bool in_data;

    /**
     * Size of SMTP command.
     */
    size_t size;

    /**
     * Buffer into which SMTP command is read.
     */
    char data[OAP_CMD_BUF_SIZE + 1];

    /**
     * Size of prefix of data terminator at the end of the previous
     * data block sent by the client.
     */
    size_t data_term_len;
};

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

/**
 * Determine the length of the prefix of the data terminator located
 * at the end of a client data block.
 *
 * @param data Client data block.
 * @param len Data block length.
 *
 * @return Length of data terminator prefix.
 */
static size_t data_term_pref_len(const char *data, size_t len);

/* Implementations */

struct smtp_cmd_stream * smtp_cmd_stream_create(int fd) {
    struct smtp_cmd_stream *stream = xmalloc(sizeof(struct smtp_cmd_stream));

    stream->fd = fd;
    stream->size = 0;

    stream->in_data = false;

    return stream;
}

void smtp_cmd_stream_free(struct smtp_cmd_stream *stream) {
    assert(stream != NULL);
    free(stream);
}

int smtp_cmd_stream_fd(struct smtp_cmd_stream *stream) {
    return stream->fd;
}

ssize_t smtp_cmd_next(struct smtp_cmd_stream *stream, struct smtp_cmd *cmd) {
    ssize_t n = stream->in_data ? recv(stream->fd, stream->data, OAP_CMD_BUF_SIZE, 0) :
        read_cmd(stream->fd, stream->data, OAP_CMD_BUF_SIZE);

    if (n <= 0) {
        return n;
    }

    // Add terminating NUL character
    stream->data[n] = 0;
    stream->size = n;

    cmd->line = stream->data;
    cmd->total_len = n;

    if (!stream->in_data) {
        parse_cmd(stream, cmd);
        stream->data_term_len = 0;
    }
    else {
        cmd->command = SMTP_CMD;
        cmd->data = NULL;
        cmd->data_len = 0;

        // Check whether data terminator is sent

        const char *part_term = DATA_TERM;
        part_term += stream->data_term_len;

        // Check if partial data terminator is at beginning of client
        // data.

        if (strncmp(stream->data, part_term, DATA_TERM_LEN - stream->data_term_len) == 0) {
            stream->in_data = false;
            stream->data_term_len = 0;
        }
        else {
            // Check if prefix of data terminator is at end of client
            // data.

            size_t blk_sz = stream->size > DATA_TERM_LEN ? DATA_TERM_LEN : stream->size;
            blk_sz = data_term_pref_len(stream->data + (stream->size - blk_sz), blk_sz);

            stream->data_term_len = blk_sz;

            // Check if full data terminator is at end of client data.
            if (stream->data_term_len == DATA_TERM_LEN) {
                stream->in_data = false;
                stream->data_term_len = 0;
            }
            else {
                // Check whether full data terminator is somewhere in
                // client data.
                stream->in_data = strstr(stream->data, DATA_TERM) == NULL;
            }
        }
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
        command->data_len = cmd_data_len(command->data, (stream->data + stream->size) - command->data);

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
        command->data_len = 0;
        return true;
    }

    command->command = SMTP_CMD;
    command->data = NULL;
    command->data_len = 0;

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

size_t data_term_pref_len(const char *data, size_t len) {
    const char *end = DATA_TERM;

    size_t count = 0;

    while (len--) {
        if (*data == end[count])
            count++;
        else
            count = 0;

        data++;
    }

    return count;
}
