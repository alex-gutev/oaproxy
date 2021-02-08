#ifndef OAPROXY_SMTP_H
#define OAPROXY_SMTP_H

/**
 * Handle SMTP client connection.
 *
 * @param fd   Client socket descriptor
 * @param host SMTP server host
 */
void smtp_handle_client(int fd, const char *host);

#endif /* OAPROXY_SMTP_H */
