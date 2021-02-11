#include "gaccounts.h"

#include <assert.h>
#include <syslog.h>

static GoaClient *client = NULL;

GoaClient *get_goaclient(GError ** error) {
    if (!client) {
        client = goa_client_new_sync(NULL, error);
    }

    return client;
}

GList * find_goaccount(GList *accounts, const char *user) {
    GList *l;

    for (l = accounts; l != NULL; l = l->next) {
        GoaAccount *account = goa_object_get_account(GOA_OBJECT(l->data));
        const char *acc_id = goa_account_get_presentation_identity(account);

        if (!strcmp(user, acc_id)) {
            break;
        }
    }

    return l;
}

gchar *get_access_token(GList *account) {
    GError *error = NULL;

    GoaAccount *acc = goa_object_get_account(GOA_OBJECT(account->data));
    assert(acc);

    if (!goa_account_call_ensure_credentials_sync(acc, NULL, NULL, &error)) {
        syslog(LOG_ERR | LOG_USER, "Could not renew token: %s", error->message);
        return NULL;
    }

    GoaOAuth2Based *oauth2 =
        goa_object_get_oauth2_based(GOA_OBJECT(account->data));

    if (oauth2) {
        gchar *access_token;

        if (goa_oauth2_based_call_get_access_token_sync(oauth2,
                                                        &access_token,
                                                        NULL,
                                                        NULL,
                                                        NULL)) {
            return access_token;
        }

        g_clear_object(&oauth2);
    }

    return NULL;
}
