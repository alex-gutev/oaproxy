#ifndef OAPROXY_B64_H
#define OAPROXY_B64_H

#include <stddef.h>

/**
 * Encodes a block of data in base64.
 *
 * @param data Data to encode
 * @param size Number of data bytes to encode.
 *
 * @return Base64 string.
 */
char *base64_encode(const char *data, size_t size);

/**
 * Decode a block of base64 encoded data.
 *
 * @param data Base64 string to decode
 *
 * @param size Pointer to size of base64 string on input, on output
 *   contains the length of the original data block.
 *
 * @return Original data block.
 */
char *base64_decode(const char *data, size_t *size);

#endif /* OAPROXY_B64_H */
