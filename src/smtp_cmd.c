#include "smtp_cmd.h"

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdio.h>
#include <ctype.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <openssl/bio.h>

#include "xmalloc.h"

#define OAP_CMD_BUF_SIZE 1024

#define CMD_AUTH_PLAIN "AUTH PLAIN"
#define CMD_AUTH_PLAIN_LEN strlen(CMD_AUTH_PLAIN)

#define CMD_DATA "DATA"
#define CMD_DATA_LEN strlen(CMD_DATA)

struct smtp_cmd_stream {
    /* Client BIO stream */
    BIO *bio;

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
};

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
 * @return Pointer to first data byte.
 */
static const char *cmd_data_start(const char *data);

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

struct smtp_cmd_stream * smtp_cmd_stream_create(int fd) {
    // Create socket BIO
    BIO *sbio = BIO_new_socket(fd, true);
    if (!sbio) return NULL;

    // Create Buffered BIO
    BIO *bbio = BIO_new(BIO_f_buffer());
    if (!bbio) goto free_sbio;

    // Chain BIOs
    BIO *chain = BIO_push(bbio, sbio);
    if (!chain) goto free_bbio;


    // Create stream struct

    struct smtp_cmd_stream *stream = xmalloc(sizeof(struct smtp_cmd_stream));

    stream->bio = chain;
    stream->size = 0;

    stream->in_data = false;

    return stream;

free_bbio:
    BIO_free_all(bbio);

free_sbio:
    BIO_free_all(sbio);

    return NULL;
}

void smtp_cmd_stream_free(struct smtp_cmd_stream *stream) {
    assert(stream != NULL);

    BIO_free_all(stream->bio);
    free(stream);
}

int smtp_cmd_stream_fd(struct smtp_cmd_stream *stream) {
    return BIO_get_fd(stream->bio, NULL);
}

bool smtp_cmd_stream_pending(struct smtp_cmd_stream *stream) {
    return BIO_ctrl_pending(stream->bio) != 0;
}

void smtp_cmd_stream_data_mode(struct smtp_cmd_stream *stream, bool in_data) {
    stream->in_data = in_data;
}

ssize_t smtp_cmd_next(struct smtp_cmd_stream *stream, struct smtp_cmd *cmd) {
    ssize_t n = BIO_gets(stream->bio, stream->data, OAP_CMD_BUF_SIZE);

    if (n <= 0) {
        return n;
    }

    // Add terminating NUL character in case reading data rather than
    // line
    stream->data[n] = 0;
    stream->size = n;

    cmd->line = stream->data;
    cmd->total_len = n;

    if (!stream->in_data) {
        parse_cmd(stream, cmd);
    }
    else {
        cmd->command = SMTP_CMD;
        cmd->data = NULL;
        cmd->data_len = 0;
    }

    return n;
}

bool parse_cmd(struct smtp_cmd_stream *stream, struct smtp_cmd *command) {
    if (strncasecmp(CMD_AUTH_PLAIN, stream->data, CMD_AUTH_PLAIN_LEN) == 0 &&
        isspace(stream->data[CMD_AUTH_PLAIN_LEN])) {

        command->command = SMTP_CMD_AUTH;
        command->data = cmd_data_start(stream->data + CMD_AUTH_PLAIN_LEN);
        command->data_len = cmd_data_len(command->data, stream->size - (command->data - stream->data));

        return true;
    }

    if (strncasecmp(CMD_DATA, stream->data, CMD_DATA_LEN) == 0 &&
        isspace(stream->data[CMD_DATA_LEN])) {

        command->command = SMTP_CMD_DATA;
        command->data = NULL;
        command->data_len = 0;
        return true;
    }

    command->command = SMTP_CMD;
    command->data = stream->data;
    command->data_len = cmd_data_len(command->data, stream->size);

    return true;
}

const char *cmd_data_start(const char *data) {
    while (*data && *data == ' ') {
        data++;
    }

    return data;
}

size_t cmd_data_len(const char *data, size_t size) {
    if (size >= 1 && data[size-1] == '\n') {
        if (size >= 2 && data[size-2] == '\r') {
            return size - 2;
        }

        return size - 1;
    }

    return size;
}
