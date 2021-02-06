#include "ssl.h"

#include <syslog.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/**
 * SSL error callback function, logs the error using syslog.
 *
 * @param str Error message
 * @param len Length of error message
 */
static int ssl_log_error_cb(const char *str, size_t len, void *u);

void initialize_ssl(void) {
    SSL_load_error_strings();
    ERR_load_crypto_strings();

    OpenSSL_add_all_algorithms();
    SSL_library_init();
}

void destroy_ssl(void) {
    ERR_free_strings();
    EVP_cleanup();
}

void ssl_log_error(const char *msg) {
    syslog(LOG_USER | LOG_ERR, "%s", msg);
    ERR_print_errors_cb(ssl_log_error_cb, NULL);
}

int ssl_log_error_cb(const char *str, size_t len, void *u) {
    syslog(LOG_USER | LOG_ERR, "SSL Error: %s", str);
    return 0;
}
