#include "b64.h"

#include <stdlib.h>
#include <string.h>

static const char *b64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *base64_encode(const char *data, size_t size) {
    char * out = malloc(size * 4);

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
