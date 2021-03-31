#include "xmalloc.h"

#include <stdlib.h>
#include <syslog.h>

void *xmalloc(size_t n) {
    void *p = malloc(n);

    if (!p) {
        syslog(LOG_CRIT, "Error allocating memory");
        abort();
    }

    return p;
}

void *xrealloc(void *ptr, size_t size) {
    ptr = realloc(ptr, size);

    if (!ptr) {
        syslog(LOG_CRIT, "Error reallocating memory");
        abort();
    }

    return ptr;
}
