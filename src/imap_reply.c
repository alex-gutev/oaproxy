#include "imap_reply.h"

#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <syslog.h>
#include <assert.h>

#include "xmalloc.h"

#define OAP_REPLY_BUF_SIZE 1024

#define REPLY_CAP "CAPABILITY "
#define REPLY_CAP_LEN 11

struct imap_reply_stream {
    /** Server BIO object */
    BIO *bio;

    /** Size of data in buffer */
    size_t size;
    /** Offset within buffer to first unprocessed byte */
    size_t offset;

    /** Data Buffer */
    char data[OAP_REPLY_BUF_SIZE];
};

/**
 * Return the length of the next reply in the data buffer.
 *
 * @param data Pointer to data buffer
 * @param sz Number of bytes in buffer
 *
 * @return Length of the line, or 0 if there isn't a complete line in
 *    the buffer.
 */
static size_t reply_length(const char *data, size_t n);

/**
 * Parse an IMAP reply.
 *
 * @param reply Pointer to imap_reply struct. On input the line, and
 *   total_len fields should be filled.
 *
 * @return True if the reply was parsed successfully.
 */
static bool parse_reply(struct imap_reply *reply);

/**
 * Parse the type of reply.
 *
 * @param reply Pointer to imap_reply struct. On input the line, and
 *   total_len fields should be filled.
 *
 * @return True if the reply type was parsed successfully.
 */
static bool parse_reply_type(struct imap_reply *reply);

/**
 * Parse the tag at the start of an IMAP reply. Only applicable for
 * tagged replies.
 *
 * @param reply Pointer to IMAP reply
 *
 * @return True if the tag was parsed successfully.
 */
static bool parse_reply_tag(struct imap_reply *reply);

/**
 * Parse the reply code.
 *
 * @param reply Pointer to IMAP reply
 *
 * @return True if the reply code was parsed successfully.
 */
static bool parse_reply_code(struct imap_reply *reply);


/* Implementation */

struct imap_reply_stream * imap_reply_stream_create(BIO *bio) {
    struct imap_reply_stream *stream = xmalloc(sizeof(struct imap_reply_stream));

    stream->bio = bio;

    stream->size = 0;
    stream->offset = 0;

    return stream;
}

void imap_reply_stream_free(struct imap_reply_stream *stream) {
    assert(stream != NULL);
    free(stream);
}

ssize_t imap_reply_next(struct imap_reply_stream *stream, struct imap_reply *reply, const bool wait) {
    while (1) {
        if (stream->offset < stream->size) {
            size_t len = reply_length(stream->data + stream->offset, stream->size - stream->offset);

            // If complete reply
            if (reply) {
                reply->line = stream->data + stream->offset;
                reply->total_len = len;

                parse_reply(reply);

                stream->offset += len;
                return len;
            }

            // Move partial reply to beginning of buffer
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
        ssize_t n = BIO_read(stream->bio, stream->data + stream->size, OAP_REPLY_BUF_SIZE - stream->size);

        if (n < 0) {
            syslog(LOG_USER | LOG_ERR, "IMAP: Error reading reply from server: %m");
            return n;
        }
        else if (n == 0) {
            syslog(LOG_USER | LOG_ERR, "IMAP: server closed connection.");
            return 0;
        }

        stream->size += n;
    }

    return 0;
}

size_t reply_length(const char *data, size_t n) {
    size_t total = 0;

    while (n--) {
        char c = *data++;

        if (n && c == '\r' && *data == '\n') {
            return total + 2;
        }

        total++;
    }

    return 0;
}

/* Parsing */

bool parse_reply(struct imap_reply *reply) {
    reply->code = IMAP_REPLY;

    reply->data = NULL;
    reply->data_len = 0;

    if (!parse_reply_type(reply))
        return false;

    return parse_reply_code(reply);
}

bool parse_reply_type(struct imap_reply *reply) {
    reply->tag_len = 0;

    if (reply->total_len > 1) {
        if (reply->line[0] == '*') {
            reply->tag_len = 1;
            reply->type = IMAP_REPLY_UNTAGGED;
        }
        else if (reply->line[0] == '+') {
            reply->tag_len = 1;
            reply->type = IMAP_REPLY_CONT;
        }
        else {
            reply->type = IMAP_REPLY_TAGGED;
            return parse_reply_tag(reply);
        }

        return true;
    }

    return false;
}

bool parse_reply_tag(struct imap_reply *reply) {
    const char *data = reply->line;
    size_t n = reply->total_len;

    reply->tag_len = 0;
    while (n-- && *data != ' ') {
        if (!isalnum(*data++)) {
            return false;
        }

        reply->tag_len++;
    }

    return true;
}

bool parse_reply_code(struct imap_reply *reply) {
    const char *data = reply->line + reply->tag_len;
    size_t n = reply->total_len - reply->tag_len;

    // Skip leading whitespace
    while (n && *data == ' ') {
        n--;
        data++;
    }

    if (reply->type == IMAP_REPLY_UNTAGGED &&
        strncasecmp(REPLY_CAP, data, REPLY_CAP_LEN) == 0) {
        reply->code = IMAP_REPLY_CAP;
        reply->data = data + REPLY_CAP_LEN;
        reply->data_len = n - 2 - REPLY_CAP_LEN;
    }
    else {
        reply->code = IMAP_REPLY;
        reply->data = NULL;
        reply->data_len = 0;
    }

    return true;
}


/* Accessors */

const char *imap_reply_buffer(struct imap_reply_stream *stream, size_t *size) {
    if (stream->offset < stream->size) {
        *size = stream->size - stream->offset;
        return stream->data + stream->offset;
    }

    return NULL;
}
