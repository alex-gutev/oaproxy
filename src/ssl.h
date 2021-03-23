#ifndef OAPROXY_SSL_H
#define OAPROXY_SSL_H

#include <openssl/bio.h>

/* SSL Utility Functions */

/**
 * Initialize the OpenSSL library.
 */
void initialize_ssl(void);

/**
 * Free the OpenSSL library.
 */
void destroy_ssl(void);

/**
 * Log a message to syslog followed by a log of the last SSL errors.
 *
 * @param msg Message to log
 */
void ssl_log_error(const char *msg);

/**
 * Connect to a server using a TLS/SSL connection.
 *
 * @param host Server host to connect to.
 *
 * @return BIO stream if connection was successful. NULL otherwise.
 */
BIO *server_connect(const char *host);

#endif /* OAPROXY_SSL_H */
