#include "smtp_reply.h"

#include <string.h>
#include <ctype.h>
#include <syslog.h>

#include "ssl.h"

#define STATUS_AUTH "AUTH "
#define STATUS_AUTH_LEN 5

/**
 * Determine the length of the reply line.
 *
 * @param data Pointer to the start of the reply line.
 *
 * @param size Number of bytes read.
 *
 * @param data_len Pointer to size_t in which the length of the reply
 *   line, excluding the terminating CRLF is stored.
 *
 * @param total_len Pointer to size_t in which the total length of the
 *   reply line is stored.
 *
 * @return True if the reply is a complete line, false if there is
 *   more data to be read.
 */
static bool reply_length(const char *data, size_t size, size_t *data_len, size_t *total_len);


void smtp_reply_stream_init(struct smtp_reply_stream *stream, BIO *bio) {
    stream->bio = bio;
    stream->offset = stream->size = 0;
}

ssize_t smtp_reply_next(struct smtp_reply_stream *stream, struct smtp_reply *reply) {
    while (1) {
        // Check if there is data left in the stream buffer
        if (stream->offset < stream->size) {
            size_t data_len, total_len;
            bool complete = reply_length(stream->data + stream->offset, stream->size - stream->offset, &data_len, &total_len);

            // If complete return reply
            if (complete) {
                reply->data = stream->data + stream->offset;
                reply->data_len = data_len;
                reply->total_len = total_len;

                stream->offset += total_len;

                return reply->total_len;
            }

            // Move partial reply to beginning of buffer
            if (stream->offset) {
                memmove(stream->data, stream->data + stream->offset, data_len);
                stream->offset = 0;
                stream->size = data_len;
            }
        }
        else {
            stream->offset = 0;
            stream->size = 0;
        }

        // Read next block of data
        ssize_t n = BIO_read(stream->bio, stream->data + stream->size, OAP_STREAM_BUF_SIZE - stream->size);

        if (n < 0) {
            ssl_log_error("Error reading SMTP server response");
            return n;
        }
        else if (n == 0) {
            // Returning 0 directly since the last line was incomplete anyway.

            syslog(LOG_USER | LOG_NOTICE, "SMTP server closed connection");
            return 0;
        }

        stream->size += n;
    }
}

static bool reply_length(const char *data, size_t size, size_t *data_len, size_t *total_len) {
    *data_len = 0;
    *total_len = 0;

    while (size--) {
        if (*data == '\r' && size && data[1] == '\n') {
            *total_len += 2;
            return true;
        }
        else if (*data == '\n') {
            *total_len += 1;
            return true;
        }

        data++;

        *data_len += 1;
        *total_len += 1;
    }

    return false;
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

    if (len > STATUS_AUTH_LEN &&
        strncasecmp(STATUS_AUTH, data, STATUS_AUTH_LEN) == 0) {
        status->type = SMTP_REPLY_AUTH;
    }
    else {
        status->type = SMTP_REPLY;
    }

    return true;
}
