#ifndef OAPROXY_IMAP_H
#define OAPROXY_IMAP_H

/**
 * Handle IMAP client connection.
 *
 * @param fd        Client socket descriptor
 * @param host IMAP server host
 */
void imap_handle_client(int fd, const char *host);

#endif /* OAPROXY_IMAP_H */
