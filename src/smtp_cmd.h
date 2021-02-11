#ifndef OAPROXY_SMTP_CMD_H
#define OAPROXY_SMTP_CMD_H

#include <stdbool.h>
#include <stddef.h>

#include <unistd.h>

#define OAP_CMD_BUF_SIZE 1024

/**
 * Stream of SMTP client commands
 */
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
    char data[OAP_CMD_BUF_SIZE];
};

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
 * Initialize SMTP command stream.
 *
 * @param stream Pointer to smtp_cmd_stream struct.
 * @param fd Client socket file descriptor.
 */
void smtp_cmd_stream_init(struct smtp_cmd_stream *stream, int fd);

/**
 * Read and parse the next command from the command stream.
 *
 * @param stream SMTP command stream.
 *
 * @param cmd Pointer to smtp_cmd struct which is filled on output.
 *
 * @param Number of bytes read, 0 if no bytes are read (client closed
 *   connection), -1 if an error occurred.
 */
ssize_t smtp_cmd_next(struct smtp_cmd_stream *stream, struct smtp_cmd *cmd);

#endif /* OAPROXY_SMTP_CMD_H */
