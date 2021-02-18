#ifndef OAPROXY_IMAP_REPLY_H
#define OAPROXY_IMAP_REPLY_H

#include <stddef.h>
#include <stdbool.h>

#include <openssl/bio.h>

/**
 * Stream of IMAP server replies.
 */
struct imap_reply_stream;

/**
 * IMAP Reply Codes
 */
typedef enum imap_reply_code {
    /* Generic Reply */
    IMAP_REPLY = 0,
    /* CAPABILITY Reply */
    IMAP_REPLY_CAP
} imap_reply_code;

/**
 * IMAP Response Type
 */
typedef enum imap_reply_type {
    /**
     * Tagged response, matching the corresponding command tag.
     */
    IMAP_REPLY_TAGGED = 0,
    /**
     * Untagged response
     */
    IMAP_REPLY_UNTAGGED,
    /**
     * Continuation (request for client data) response.
     */
    IMAP_REPLY_CONT
} imap_reply_type;

/**
 * IMAP Reply
 */
struct imap_reply {
    /** Reply Code */
    imap_reply_code code;
    /** Reply Type */
    imap_reply_type type;

    /** Pointer to start of reply data line */
    const char *line;
    /** Length of entire reply line */
    size_t total_len;

    /** Tag Length */
    size_t tag_len;

    /**
     * Pointer to reply data following reply code.
     */
    const char *data;
    /** Length of reply data */
    size_t data_len;
};

/**
 * Create an IMAP reply strean
 *
 * @param bio IMAP server OpenSSL BIO object
 *
 * @return Pointer to imap_reply_stream struct
 */
struct imap_reply_stream * imap_reply_stream_create(BIO *bio);

/**
 * Free the memory held by an IMAP reply stream.
 *
 * @param stream Pointer to the IMAP reply stream
 */
void imap_reply_stream_free(struct imap_reply_stream *stream);

/**
 * Read and parse the next reply from the reply stream.
 *
 * @param stream IMAP reply stream.
 *
 * @param reply Pointer to imap_reply struct, filled on output.
 *
 * @param wait If true, will block until new data is received,
 *   otherwise will return immediately.
 *
 * @return Number of bytes read, 0 if no bytes are read (client closed
 *   connection), -1 if an error occurred. If wait is false, a return
 *   value of 0 indicates that there isn't a complete command left in
 *   the buffer.
 */
ssize_t imap_reply_next(struct imap_reply_stream *stream, struct imap_reply *reply, const bool wait);

/**
 * Return the remaining data in the stream's buffer.
 *
 * @param stream IMAP reply stream.
 *
 * @param size Pointer to size_t which will receive the size of the
 *   buffer.
 *
 * @return Pointer to the buffer. NULL if there is no unprocessed data
 *   in the buffer.
 */
const char *imap_reply_buffer(struct imap_reply_stream *stream, size_t *size);

#endif /* OAPROXY_IMAP_REPLY_H */
