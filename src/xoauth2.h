#ifndef OAPROXY_XOAUTH2
#define OAPROXY_XOAUTH2

/**
 * Generate the XOAUTH2 client response string.
 *
 * @param user  Username
 * @param token Authorization token
 *
 * @return Base64 encoded client response string.
 */
char * xoauth2_make_client_response(const char *user, const char *token);

#endif /* OAPROXY_XOAUTH2 */
