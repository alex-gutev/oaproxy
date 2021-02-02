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

#endif /* OAPROXY_B64_H */
