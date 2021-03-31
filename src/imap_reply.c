#include "imap_reply.h"

#include <stdbool.h>
#include <string.h>
#include <ctype.h>
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

    /** Data Buffer */
    char data[OAP_REPLY_BUF_SIZE];
};

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
    // Create Buffered BIO
    BIO *bbio = BIO_new(BIO_f_buffer());
    if (!bbio) return NULL;

    // Chain BIOs
    BIO *chain = BIO_push(bbio, bio);
    if (!chain) {
        BIO_free_all(bbio);
        return NULL;
    }

    struct imap_reply_stream *stream = xmalloc(sizeof(struct imap_reply_stream));

    stream->bio = chain;
    stream->size = 0;

    return stream;
}

void imap_reply_stream_free(struct imap_reply_stream *stream) {
    assert(stream != NULL);

    BIO_free(stream->bio);
    free(stream);
}

ssize_t imap_reply_next(struct imap_reply_stream *stream, struct imap_reply *reply, const bool wait) {
    if (!wait && !BIO_ctrl_pending(stream->bio))
        return 0;

    ssize_t n = BIO_gets(stream->bio, stream->data, OAP_REPLY_BUF_SIZE);
    if (n <= 0) {
        return n;
    }

    stream->size = n;

    reply->line = stream->data;
    reply->total_len = n;

    parse_reply(reply);
    return n;
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

ssize_t imap_reply_buffer(struct imap_reply_stream *stream, char *buf, size_t size) {
    size_t pending = BIO_ctrl_pending(stream->bio);

    if (pending < size) {
        size = pending;
    }

    size_t total = 0;

    while (size) {
        ssize_t n = BIO_read(stream->bio, buf, size);

        if (n < 0) {
            return n;
        }
        else if (n == 0) {
            break;
        }

        size -= n;
        total += n;
        buf += n;
    }

    return total;
}
