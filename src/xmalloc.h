#ifndef OAPROX_XMALLOC_H
#define OAPROX_XMALLOC_H

#include <stddef.h>

/**
 * Allocates memory (like malloc) but aborts if allocation fails.
 *
 * @param n Size of the memory block.
 *
 * @return Pointer to the allocated memory. Never returns NULL.
 */
void *xmalloc(size_t n);

#endif /* OAPROX_XMALLOC_H */
