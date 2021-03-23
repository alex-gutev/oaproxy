#include "ssl.h"

#include <syslog.h>

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
    if (msg) syslog(LOG_USER | LOG_ERR, "%s", msg);
    ERR_print_errors_cb(ssl_log_error_cb, NULL);
}

int ssl_log_error_cb(const char *str, size_t len, void *u) {
    syslog(LOG_USER | LOG_ERR, "SSL Error: %s", str);
    return 0;
}

BIO *server_connect(const char *host) {
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL) {
        ssl_log_error("SMTP: Error creating SSL context");
        return NULL;
    }

    BIO *bio = BIO_new_ssl_connect(ctx);
    if (!bio) {
        SSL_CTX_free(ctx);
        return NULL;
    }

    SSL *ssl;

    if (BIO_get_ssl(bio, &ssl) <= 0) {
        goto free_bio;
    }

    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    if (!BIO_set_conn_hostname(bio, host)) {
        syslog(LOG_USER | LOG_ERR, "Error setting host: %s", host);
        ssl_log_error(NULL);
        goto free_bio;
    }

    if (BIO_do_connect(bio) <= 0) {
        syslog(LOG_USER | LOG_ERR, "Error connecting to host: %s", host);
        ssl_log_error(NULL);
        goto free_bio;
    }

    return bio;

free_bio:
    BIO_free_all(bio);
    return NULL;
}
