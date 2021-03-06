#ifndef OAPROXY_GACCOUNTS_H
#define OAPROXY_GACCOUNTS_H

#define GOA_API_IS_SUBJECT_TO_CHANGE
#include <goa/goa.h>

/* Gnome online accounts */

/**
 * Enumeration representing Gnome Online Account errors.
 */
typedef enum goa_error {
    /**
     * Account credentials invalid. Account not authorized for
     * SMTP/IMAP access.
     */
    ACCOUNT_ERROR_CRED = 1,

    /**
     * Error obtaining token/oauth2 object.
     */
    ACCOUNT_ERROR_TOKEN,
} goa_error;

/**
 * Retrieve the Gnome Online Accounts client.
 *
 * @param error If given pointer to a GError which is filled with the
 *   error information if an error occurs.
 *
 * @return The GOA client, or NULL if an error occurred.
 */
GoaClient *get_goaclient(GError ** error);

/**
 * Find a GOA account for a particular user.
 *
 * @param accounts List of all accounts
 * @param user Username
 *
 * @return Pointer to the node containing the account, NULL if no
 *   account was found for the given username.
 */
GList * find_goaccount(GList *accounts, const char *user);

/**
 * Retrieve the access token for a particular GOA account.
 *
 * @param account GOA account
 *
 * @param error Pointer to variable receiving goa_error constant on
 *   error.
 *
 * @return Access token, or NULL if their was an error.
 */
gchar *get_access_token(GList *account, goa_error *error);


#endif /* OAPROXY_GACCOUNTS_H */
