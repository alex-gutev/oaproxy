#ifndef OAPROXY_SMTP_CMD_H
#define OAPROXY_SMTP_CMD_H

#include <stdbool.h>
#include <stddef.h>

#include <unistd.h>

/**
 * Stream of SMTP client commands
 */
struct smtp_cmd_stream;

/**
 * SMTP Command Type Codes
 */
typedef enum smtp_cmd_type {
    /* Generic Command */
    SMTP_CMD = 0,
    /* AUTH - Authorization Command */
    SMTP_CMD_AUTH = 1,
    /* DATA - Begin message data transmission */
    SMTP_CMD_DATA
} smtp_cmd_type;

/**
 * SMTP Command
 */
struct smtp_cmd {
    /** Command Type Code */
    smtp_cmd_type command;

    /** Pointer to start of command data line */
    const char *line;
    /** Length of entire command data line */
    size_t total_len;

    /** Data following command */
    const char *data;
    /** Data length */
    size_t data_len;
};

/**
 * Create an SMTP command stream.
 *
 * @param fd SMTP client socket file descriptor. The stream takes
 *   responsibility of closing the file.
 *
 * @return Pointer to the smtp_cmd_stream struct
 */
struct smtp_cmd_stream * smtp_cmd_stream_create(int fd);

/**
 * Free the memory held by an SMTP command stream, and close the
 * underlying socket.
 *
 * @param stream Pointer to SMTP command stream.
 */
void smtp_cmd_stream_free(struct smtp_cmd_stream *stream);

/**
 * Return the socket file descriptor of an SMTP command stream.
 *
 * @param stream Pointer to SMTP command stream.
 *
 * @return socket file descriptor
 */
int smtp_cmd_stream_fd(struct smtp_cmd_stream *stream);

/**
 * Returns true if there is pending data in the stream.
 *
 * This does not mean there is a full command in the stream, and hence
 * does not mean a call to smtp_cmd_next wont block.
 *
 * @param stream SMTP command stream.
 *
 * @return True if there is data in the stream.
 */
bool smtp_cmd_stream_pending(struct smtp_cmd_stream *stream);

/**
 * Read and parse the next command from the command stream.
 *
 * @param stream SMTP command stream.
 *
 * @param cmd Pointer to smtp_cmd struct which is filled on output.
 *
 * @return Number of bytes read, 0 if no bytes are read (client closed
 *   connection), -1 if an error occurred.
 */
ssize_t smtp_cmd_next(struct smtp_cmd_stream *stream, struct smtp_cmd *cmd);

/**
 * Change the mode of the stream to/from command/data mode.
 *
 * @param in_data True to put stream in data mode. False to put stream
 *   in command mode.
 */
void smtp_cmd_stream_data_mode(struct smtp_cmd_stream *stream, bool in_data);

#endif /* OAPROXY_SMTP_CMD_H */
