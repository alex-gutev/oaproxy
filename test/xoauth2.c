#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <string.h>

#include <cmocka.h>

#include "xoauth2.h"

static void test_make_client_resp(void ** state) {
    const char *user = "someuser@example.com";
    const char *token = "ya29.vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg";

    const char *exp = "dXNlcj1zb21ldXNlckBleGFtcGxlLmNvbQFhdXRoPUJlYXJlciB5YTI5LnZGOWRmdDRxbVRjMk52"
        "YjNSbGNrQmhkSFJoZG1semRHRXVZMjl0Q2cBAQ==";

    assert_string_equal(xoauth2_make_client_response(user, token), exp);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_make_client_resp)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
