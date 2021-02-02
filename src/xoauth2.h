#ifndef GOAPROXY_XOAUTH2
#define GOAPROXY_XOAUTH2

/**
 * Generate the XOAUTH2 client response string.
 *
 * @param user  Username
 * @param token Authorization token
 *
 * @return Base64 encoded client response string.
 */
char * xoauth2_make_client_response(const char *user, const char *token);

#endif /* GOAPROXY_XOAUTH2 */
