#ifndef OAPROXY_IMAP_CMD_H
#define OAPROXY_IMAP_CMD_H

#include <stdbool.h>
#include <stddef.h>

#include <unistd.h>

/**
 * Stream of IMAP client commands
 */
struct imap_cmd_stream;

/**
 * IMAP Command Codes
 */
typedef enum imap_cmd_type {
    /* Generic Command */
    IMAP_CMD = 0,
    /* LOGIN command */
    IMAP_CMD_LOGIN = 1,
} imap_cmd_type;

/**
 * IMAP command
 */
struct imap_cmd {
    /** IMAP Command Code */
    imap_cmd_type command;

    /** Pointer to start of command data line */
    char *line;
    /** Length of entire command data line */
    size_t total_len;

    /** Pointer to start of command ID tag */
    char *tag;
    /** Length of command tag */
    size_t tag_len;

    /** Pointer to start of command parameters */
    char *param;
    /** Length of command parameters */
    size_t param_len;
};

/**
 * Create an IMAP command stream.
 *
 * @param fd IMAP Client socket file descriptor
 *
 * @return Pointer to imap_cmd_stream struct
 */
struct imap_cmd_stream * imap_cmd_stream_create(int fd);

/**
 * Free the memory held by an IMAP command stream.
 *
 * @param Pointer to the IMAP command stream
 */
void imap_cmd_stream_free(struct imap_cmd_stream *stream);

/**
 * Read and parse the next command from the command stream.
 *
 * @param stream IMAP command stream.
 * @param cmd Pointer to imap_cmd struct, filled on output.
 *
 * @return Number of bytes read, 0 if no bytes are read (client closed
 *   connection), -1 if an error occurred.
 */
ssize_t imap_cmd_next(struct imap_cmd_stream *stream, struct imap_cmd *cmd);

/**
 * Parse a string from an IMAP command parameter.
 *
 * @param data Pointer to the command parameter
 * @param size Number of bytes in parameter
 *
 * @return The parsed string. NULL if there is a syntax error. This
 *   pointer should be freed with free.
 */
char * imap_parse_string(const char *data, size_t size);

#endif /* OAPROXY_IMAP_CMD_H */
