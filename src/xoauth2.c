#include "xoauth2.h"

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "b64.h"

char * xoauth2_make_client_response(const char *user, const char *token) {
    char *resp = NULL;

    if (asprintf(&resp, "user=%s\001auth=Bearer %s\001\001", user, token) > 0) {
        char *b64 = base64_encode(resp, strlen(resp));

        free(resp);
        return b64;
    }

    return NULL;
}
