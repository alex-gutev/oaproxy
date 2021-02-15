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

/**
 * Reallocate memory (like realloc) but abort if allocation fails.
 *
 * @param ptr Pointer to existing block.
 * @param size New size
 *
 * @return Pointer to reallocated memory. Never returns NULL.
 */
void *xrealloc(void *ptr, size_t size);

#endif /* OAPROX_XMALLOC_H */
