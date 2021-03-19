#ifndef OAPROXY_SMTP_REPLY_H
#define OAPROXY_SMTP_REPLY_H

#include <stdbool.h>

#include <openssl/bio.h>

/**
 * Maximum SMTP reply line length
 */
#define SMTP_REPLY_MAX 514

/**
 * Stream of SMTP server replies
 */
struct smtp_reply_stream;

/**
 * SMTP Reply Type Codes
 */
typedef enum smtp_reply_type {
    /* Generic (Unknown) Reply */
    SMTP_REPLY = 0,
    /* Supported Authentication Types Reply */
    SMTP_REPLY_AUTH = 1
} smtp_reply_type;

/**
 * SMTP Reply Information
 */
struct smtp_reply {
    /**
     * Pointer to the reply line
     */
    char *data;

    /**
     * Number of bytes in the SMTP reply line, excluding the
     * terminating CRLF.
     */
    size_t data_len;
    /**
     * Total number of bytes in the SMTP reply line including the
     * terminating CRLF.
     */
    size_t total_len;


    /**
     * The following fields are only filled after parsing the reply
     * line, using smtp_reply_parse.
     */

    /** Reply Code */
    int code;

    /** Reply type constant */
    smtp_reply_type type;

    /**
     * Pointer to the start of the reply message following the status
     * code.
     */
    char *msg;

    /**
     * True if this is the last reply line, false otherwise.
     */
    bool last;
};

/**
 * Create an SMTP reply stream.
 *
 * @param bio SMTP Server OpenSSL BIO object. The stream takes
 *   responsibility for freeing the BIO.
 *
 * @return The smtp_reply_stream struct.
 */
struct smtp_reply_stream * smtp_reply_stream_create(BIO *bio);

/**
 * Free the memory held by an SMTP reply stream and free the
 * underlying BIO stream.
 *
 * @param stream Pointer to the smtp_reply_stream struct.
 */
void smtp_reply_stream_free(struct smtp_reply_stream *stream);

/**
 * Read the next complete reply line from the SMTP reply stream.
 *
 * @param stream Pointer to SMTP reply stream.
 *
 * @param reply Pointer to smtp_reply struct, which is filled
 *   on output. Only the data, data_len and total_len fields are
 *   filled.
 *
 * @return Number of bytes read, 0 if no bytes are read (server closed
 *   connection), -1 if an error occurred.
 */
ssize_t smtp_reply_next(struct smtp_reply_stream *stream, struct smtp_reply *reply);

/**
 * Parse an SMTP reply line.
 *
 * If parsing was unsuccessful, the SMTP reply type is set to the
 * generic reply type SMTP_REPLY.
 *
 * @param reply Pointer to smtp_reply struct which is filled with the
 *   parsed reply details.
 *
 * @return True if the reply was parsed successfully.
 */
bool smtp_reply_parse(struct smtp_reply *reply);

#endif /* OAPROXY_SMTP_REPLY_H */
