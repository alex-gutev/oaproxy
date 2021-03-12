#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <string.h>

#include <cmocka.h>

#include "b64.h"

/* Test Encoding */

static void test_encode_string(void ** state) {
    const char *str = "Hello World.";

    assert_string_equal(base64_encode(str, strlen(str)), "SGVsbG8gV29ybGQu");
}

static void test_encode_string_pad1(void ** state) {
    const char *str = "Hello World";

    assert_string_equal(base64_encode(str, strlen(str)), "SGVsbG8gV29ybGQ=");
}
static void test_encode_string_pad2(void ** state) {
    const char *str = "Hello Worl";

    assert_string_equal(base64_encode(str, strlen(str)), "SGVsbG8gV29ybA==");
}

static void test_encode_long_string(void ** state) {
    // Taken from wikipedia page on Base64 encoding
    // Quote from Thomas Hobbes's Leviathan

    const char * str = "Man is distinguished, not only by his reason, but by this singular passion from other animals, "
        "which is a lust of the mind, that by a perseverance of delight in the continued and indefatigable "
        "generation of knowledge, exceeds the short vehemence of any carnal pleasure.";

    const char * res = "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlz"
        "IHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlciBhbmltYWxzLCB3aGljaCBpcyBhIGx1c3Qgb2Yg"
        "dGhlIG1pbmQsIHRoYXQgYnkgYSBwZXJzZXZlcmFuY2Ugb2YgZGVsaWdodCBpbiB0aGUgY29udGlu"
        "dWVkIGFuZCBpbmRlZmF0aWdhYmxlIGdlbmVyYXRpb24gb2Yga25vd2xlZGdlLCBleGNlZWRzIHRo"
        "ZSBzaG9ydCB2ZWhlbWVuY2Ugb2YgYW55IGNhcm5hbCBwbGVhc3VyZS4=";

    assert_string_equal(base64_encode(str, strlen(str)), res);
}

static void test_encode_bytes1(void ** state) {
    const char data[] = {1, 2, 3, 4, 5, 20, 30, 40, 100};

    assert_string_equal(base64_encode(data, sizeof(data)), "AQIDBAUUHihk");
}

static void test_encode_bytes2(void ** state) {
    const char data[] = {0x0, 0x16, 0x0e, 0xfc, 0xff, 0x90};

    assert_string_equal(base64_encode(data, sizeof(data)), "ABYO/P+Q");
}


/* Test Decoding */

static void test_decode_string(void ** state) {
    const char *exp = "Hello World.";
    const char *str = "SGVsbG8gV29ybGQu";

    size_t len = strlen(str);
    char *dec = base64_decode(str, &len);

    assert_non_null(dec);
    assert_string_equal(dec, exp);
    assert_int_equal(len, strlen(exp));
}

static void test_decode_string_pad1(void ** state) {
    const char *exp = "Hello World";
    const char *str = "SGVsbG8gV29ybGQ=";

    size_t len = strlen(str);
    char *dec = base64_decode(str, &len);

    assert_non_null(dec);
    assert_string_equal(dec, exp);
    assert_int_equal(len, strlen(exp));
}

static void test_decode_string_pad2(void ** state) {
    const char *exp = "Hello Worl";
    const char *str = "SGVsbG8gV29ybA==";

    size_t len = strlen(str);
    char *dec = base64_decode(str, &len);

    assert_non_null(dec);
    assert_string_equal(dec, exp);
    assert_int_equal(len, strlen(exp));
}

static void test_decode_string_nopad1(void ** state) {
    const char *exp = "Hello World";
    const char *str = "SGVsbG8gV29ybGQ";

    size_t len = strlen(str);
    char *dec = base64_decode(str, &len);

    assert_non_null(dec);
    assert_string_equal(dec, exp);
    assert_int_equal(len, strlen(exp));
}

static void test_decode_string_nopad2(void ** state) {
    const char *exp = "Hello Worl";
    const char *str = "SGVsbG8gV29ybA";

    size_t len = strlen(str);
    char *dec = base64_decode(str, &len);

    assert_non_null(dec);
    assert_string_equal(dec, exp);
    assert_int_equal(len, strlen(exp));
}

static void test_decode_bytes1(void ** state) {
    const char exp[] = {1, 2, 3, 4, 5, 20, 30, 40, 100};
    const char *str = "AQIDBAUUHihk";

    size_t len = strlen(str);
    char *dec = base64_decode(str, &len);

    assert_non_null(dec);
    assert_int_equal(len, sizeof(exp));
    assert_memory_equal(dec, exp, sizeof(exp));
}

static void test_decode_bytes2(void ** state) {
    const char exp[] = {0x0, 0x16, 0x0e, 0xfc, 0xff, 0x90};
    const char *str = "ABYO/P+Q";

    size_t len = strlen(str);
    char *dec = base64_decode(str, &len);

    assert_non_null(dec);
    assert_int_equal(len, sizeof(exp));
    assert_memory_equal(dec, exp, sizeof(exp));
}

static void test_decode_long_string(void ** state) {
    const char * exp = "Man is distinguished, not only by his reason, but by this singular passion from other animals, "
        "which is a lust of the mind, that by a perseverance of delight in the continued and indefatigable "
        "generation of knowledge, exceeds the short vehemence of any carnal pleasure.";

    const char * str = "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlz"
        "IHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlciBhbmltYWxzLCB3aGljaCBpcyBhIGx1c3Qgb2Yg"
        "dGhlIG1pbmQsIHRoYXQgYnkgYSBwZXJzZXZlcmFuY2Ugb2YgZGVsaWdodCBpbiB0aGUgY29udGlu"
        "dWVkIGFuZCBpbmRlZmF0aWdhYmxlIGdlbmVyYXRpb24gb2Yga25vd2xlZGdlLCBleGNlZWRzIHRo"
        "ZSBzaG9ydCB2ZWhlbWVuY2Ugb2YgYW55IGNhcm5hbCBwbGVhc3VyZS4=";

    size_t len = strlen(str);
    char *dec = base64_decode(str, &len);

    assert_non_null(dec);
    assert_string_equal(dec, exp);
    assert_int_equal(len, strlen(exp));
}

/* Decoding Invalid Strings */

static void test_decode_invalid1(void ** state) {
    const char *str = "SGVsb*$%#G8gV29ybA==";

    size_t len = strlen(str);
    char *dec = base64_decode(str, &len);

    assert_null(dec);
}

/* Decoding Invalid Strings */

static void test_decode_invalid2(void ** state) {
    const char *str = "SGVsbG8gV29ybA==BaX";

    size_t len = strlen(str);
    char *dec = base64_decode(str, &len);

    assert_null(dec);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_encode_string),
        cmocka_unit_test(test_encode_string_pad1),
        cmocka_unit_test(test_encode_string_pad2),
        cmocka_unit_test(test_encode_long_string),
        cmocka_unit_test(test_encode_bytes1),
        cmocka_unit_test(test_encode_bytes2),

        cmocka_unit_test(test_decode_string),
        cmocka_unit_test(test_decode_string_pad1),
        cmocka_unit_test(test_decode_string_pad2),
        cmocka_unit_test(test_decode_string_nopad1),
        cmocka_unit_test(test_decode_string_nopad2),
        cmocka_unit_test(test_decode_long_string),
        cmocka_unit_test(test_decode_bytes1),
        cmocka_unit_test(test_decode_bytes2),
        cmocka_unit_test(test_decode_invalid1),
        cmocka_unit_test(test_decode_invalid2)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
