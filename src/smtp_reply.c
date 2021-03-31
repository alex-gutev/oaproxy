#include "smtp_reply.h"

#include <string.h>
#include <ctype.h>
#include <assert.h>

#include "ssl.h"
#include "xmalloc.h"

#define OAP_STREAM_BUF_SIZE 1024

#define STATUS_AUTH "AUTH "
#define STATUS_AUTH_LEN strlen(STATUS_AUTH)

struct smtp_reply_stream {
    /** SMTP server OpenSSL BIO object */
    BIO *bio;

    /**
     * Number of bytes in data buffer
     */
    size_t size;

    /**
     * SMTP server reply data buffer
     */
    char data[OAP_STREAM_BUF_SIZE];
};

/**
 * Determine the length of the reply line, excluding the terminating
 * CRLF.
 *
 * @param data Pointer to the start of the reply line.
 * @param size Number of bytes read.
 *
 * @return Length of reply line excluding CRLF.
 */
static size_t reply_length(const char *data, size_t size);


/* Implementation */

struct smtp_reply_stream * smtp_reply_stream_create(BIO *bio) {
    // Create buffered BIO stream
    BIO *bbio = BIO_new(BIO_f_buffer());
    if (!bbio) return NULL;

    // Chain BIO streams
    BIO *chain = BIO_push(bbio, bio);
    if (!chain) {
        BIO_free_all(bbio);
        return NULL;
    }

    struct smtp_reply_stream *stream = xmalloc(sizeof(struct smtp_reply_stream));

    stream->bio = chain;
    stream->size = 0;

    return stream;
}

void smtp_reply_stream_free(struct smtp_reply_stream *stream) {
    assert(stream != NULL);

    BIO_free_all(stream->bio);
    free(stream);
}

ssize_t smtp_reply_next(struct smtp_reply_stream *stream, struct smtp_reply *reply) {
    ssize_t n = BIO_gets(stream->bio, stream->data, OAP_STREAM_BUF_SIZE);

    if (n <= 0) {
        return n;
    }

    stream->size = n;

    reply->data = stream->data;
    reply->data_len = reply_length(stream->data, stream->size);
    reply->total_len = stream->size;

    return n;
}

static size_t reply_length(const char *data, size_t size) {
    if (size >= 1 && data[size-1] == '\n') {
        if (size >= 2 && data[size-2] == '\r') {
            return size - 2;
        }

        return size - 1;
    }

    return size;
}


/** Parsing Status Response */

bool smtp_reply_parse(struct smtp_reply *status) {
    char *data = status->data;
    size_t len = status->data_len;

    status->code = 0;

    /* Parse Response Code */

    size_t digits = 0;

    status->type = SMTP_REPLY;

    while (len--) {
        char c = *data++;

        if (isdigit(c)) {
            if (digits >= 3) {
                return false;
            }

            digits++;
            status->code = (c - '0') + status->code * 10;
        }
        else if (c == '-') {
            status->last = false;
            break;
        }
        else if (c == ' ') {
            status->last = true;
            break;
        }
        else {
            return false;
        }
    }

    status->msg = data;

    /* Parse Status Type */

    if (strncasecmp(STATUS_AUTH, data, STATUS_AUTH_LEN) == 0) {
        status->type = SMTP_REPLY_AUTH;
    }
    else {
        status->type = SMTP_REPLY;
    }

    return true;
}
