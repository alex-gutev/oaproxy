#include "b64.h"

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>

#include "xmalloc.h"

static const char *b64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#define NOINDEX ((unsigned char)-1)

/**
 * Convert a base64 alphabet character to the corresponding 6 data
 * bits.
 *
 * @param chr Base64 Character
 *
 * @return Data bits. -1 if the character is not a valid base64
 *   alphabet character.
 */
static unsigned char char_to_index(char chr);

char *base64_encode(const char *data, size_t size) {
    char * out = xmalloc(size * 4);

    int state = 0;
    unsigned chr = 0;
    size_t pos = 0;

    while (size--) {
        unsigned char byte = *data++;

        switch (state) {
        case 0:
            out[pos++] = b64_alphabet[byte >> 2];
            chr = (byte & 0x3) << 4;
            state = 1;
            break;

        case 1:
            chr |= byte >> 4;
            out[pos++] = b64_alphabet[chr];

            chr = (byte & 0x0F) << 2;
            state = 2;
            break;

        case 2:
            chr |= byte >> 6;
            out[pos++] = b64_alphabet[chr];
            out[pos++] = b64_alphabet[byte & 0x3F];

            state = 0;
            break;
        }
    }

    switch (state) {
    case 1:
        out[pos++] = b64_alphabet[chr];
        out[pos++] = '=';
        out[pos++] = '=';
        break;

    case 2:
        out[pos++] = b64_alphabet[chr];
        out[pos++] = '=';
        break;
    }

    out[pos++] = 0;
    out = realloc(out, pos);

    return out;
}

char *base64_decode(const char *data, size_t *size) {
    size_t n = *size;
    unsigned char *out = xmalloc(n * 4);

    int state = 0;
    size_t pos = 0;

    while (n) {
        char chr = *data++;
        n--;

        if (chr == '=') break;
        unsigned char index = char_to_index(chr);

        if (index == NOINDEX) goto error;

        switch (state) {
        case 0:
            out[pos] = index << 2;
            state = 1;
            break;

        case 1:
            out[pos++] |= (index >> 4);
            out[pos] = (index << 4);
            state = 2;
            break;

        case 2:
            out[pos++] |= (index >> 2);
            out[pos] = (index << 6);
            state = 3;
            break;

        case 3:
            out[pos++] |= index;
            state = 0;
            break;
        }
    }

    while (n--) {
        if (*data++ != '=') goto error;
    }

    *size = pos;
    return (char *)out;

error:
    free(out);
    return NULL;
}

unsigned char char_to_index(char chr) {
    if ('A' <= chr && chr <= 'Z')
        return chr - 'A';
    else if ('a' <= chr && chr <= 'z')
        return 26 + (chr - 'a');
    else if ('0' <= chr && chr <= '9')
        return 52 + (chr - '0');
    else if (chr == '+')
        return 62;
    else if (chr == '/')
        return 63;

    return NOINDEX;
}
