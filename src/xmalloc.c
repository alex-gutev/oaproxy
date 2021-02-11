#include "xmalloc.h"

#include <stdlib.h>
#include <syslog.h>

void *xmalloc(size_t n) {
    void *p = malloc(n);

    if (!p) {
        syslog(LOG_USER | LOG_CRIT, "Error allocating memory");
        abort();
    }

    return p;
}
