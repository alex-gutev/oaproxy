#define _GNU_SOURCE

#include <locale.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <syslog.h>
#include <assert.h>

#include "ssl.h"
#include "server.h"

int main(int argc, char *argv[])
{
    setlocale(LC_ALL, "");

    if (argc < 2) {
        fputs("Usage: oaproxy [config file]\n", stderr);
        return 1;
    }

    openlog(NULL, LOG_PID | LOG_PERROR, LOG_USER);

    initialize_ssl();

    size_t n_servers;
    struct proxy_server *servers = parse_servers(argv[1], &n_servers);

    if (!servers) {
        syslog(LOG_USER | LOG_ERR, "Could not parse server settings from config file: %s", argv[1]);
        return 1;
    }

    assert(n_servers > 0);

    for (int i = 0; i < n_servers; ++i) {
        if (!open_server_sock(servers + i, servers[i].port)) {
            return 1;
        }
    }

    run_servers(servers, n_servers);
    destroy_ssl();

    return 0;
}
