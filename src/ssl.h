#ifndef OAPROXY_SSL_H
#define OAPROXY_SSL_H

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


#endif /* OAPROXY_SSL_H */
