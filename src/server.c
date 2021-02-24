#include "server.h"

#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <pthread.h>

#include "gaccounts.h"

#include "ssl.h"
#include "smtp.h"
#include "imap.h"

#include "xmalloc.h"

#define MAX_LINE_LEN 255

#define STR_IMAP "IMAP "
#define STR_IMAP_LEN strlen(STR_IMAP)

#define STR_SMTP "SMTP "
#define STR_SMTP_LEN strlen(STR_SMTP)

/**
 * Represents a connection to a proxy server
 */
struct proxy_client {
    /** Client socket file descriptor */
    int fd;
    /** Remote server details */
    const struct proxy_server *server;
};

/**
 * Parse a line from the server configuration file.
 *
 * @param server Pointer to proxy_server struct, which is filled with
 *   the parsed server details.
 *
 * @param line Line to parse.
 *
 * @return True if the server configuration was parsed successfully,
 *   false otherwise.
 */
static bool parse_line(struct proxy_server *server, const char *line);

/**
 * Parse server type - IMAP or SMTP.
 *
 * @param line String to parse.
 *
 * @param type Pointer to variable which is set to parsed server type.
 *
 * @return Pointer to string following server type, when
 *   successful. NULL if the server type could not be parsed.
 */
static const char * parse_type(const char *line, server_type *type);

/**
 * Parse the local server port.
 *
 * @param line String to parse.
 *
 * @param port Pointer to unsigned long which is set to the port
 *   number.
 *
 * @return Pointer to string following port number, when
 *   successful. NULL if the port number could not be parsed.
 */
static const char * parse_port(const char *line, unsigned long *port);

/**
 * Parse the remote server host.
 *
 * @param line String to parse.
 *
 * @return Pointer to the string containing the parsed host name.
 */
static char * parse_host(const char *line);

/**
 * Skip leading whitespace in string.
 *
 * @param line String
 *
 * @return Pointer to string following leading whitespace.
 */
static const char *skip_ws(const char *line);

/**
 * Handle incoming connections to the server sockets.
 *
 * @param set FD set of sockets which have an incoming connection.
 *
 * @param servers Array of proxy servers.
 *
 * @param n Number of proxy servers.
 */
static void handle_accept(const fd_set *set, struct proxy_server *servers, size_t n);

/**
 * Thread start routine for handling a client connection.
 *
 * @param client Pointer to a proxy_client struct.
 * @return NULL
 */
static void * handle_client(void *client);


/* Parsing Configuration Files */

struct proxy_server *parse_servers(const char *path, size_t *n) {
    FILE *f = fopen(path, "r");

    if (!f) {
        syslog(LOG_USER | LOG_ERR, "Error opening configuration file '%s': %m", path);
        return NULL;
    }

    size_t size = 5, num = 0;
    struct proxy_server *servers = xmalloc(size * sizeof(struct proxy_server));

    char line[MAX_LINE_LEN];
    size_t line_i = 0;

    while (fgets(line, sizeof(line), f)) {
        line_i++;

        if (num >= size) {
            size *= 2;
            servers = xrealloc(servers, size * sizeof(struct proxy_server));
        }

        if (!parse_line(servers + num, line)) {
            syslog(LOG_USER | LOG_ERR, "Config Parse Error: Error parsing line %lu", line_i);
            continue;
        }

        if (open_server_sock(servers + num, servers[num].port)) {
            num++;
        }
    }

    fclose(f);

    if (num) {
        servers = xrealloc(servers, num * sizeof(struct proxy_server));
    }
    else {
        free(servers);
        servers = NULL;
    }

    *n = num;

    return servers;
}

bool parse_line(struct proxy_server *server, const char *line) {
    line = parse_type(line, &server->type);
    if (!line) return false;

    line = parse_port(line, &server->port);
    if (!line) return false;

    server->host = parse_host(line);

    return server->host != NULL;
}

const char * parse_type(const char *line, server_type *type) {
    if (strncasecmp(line, STR_IMAP, STR_IMAP_LEN) == 0) {
        *type = TYPE_IMAP;
        return line + STR_IMAP_LEN;
    }
    else if (strncasecmp(line, STR_SMTP, STR_SMTP_LEN) == 0) {
        *type = TYPE_SMTP;
        return line + STR_SMTP_LEN;
    }

    syslog(LOG_USER | LOG_ERR, "Error parsing server type in: %s", line);
    return NULL;
}

const char * parse_port(const char *line, unsigned long *port) {
    char *end;

    *port = strtoul(line, &end, 10);

    assert(end);
    if (*end && !isspace(*end)) {
        syslog(LOG_USER | LOG_ERR, "Error parsing port at: %s", line);
        return NULL;
    }

    return end;
}

char * parse_host(const char *line) {
    line = skip_ws(line);

    const char *start = line;
    size_t n = 0;

    while (*line && !isspace(*line)) {
        line++;
        n++;
    }

    if (!n) {
        syslog(LOG_USER | LOG_ERR, "Config Parse Error: Empty Host");
        return NULL;
    }

    char *host = xmalloc(n+1);
    memcpy(host, start, n);

    host[n] = 0;

    return host;
}

const char *skip_ws(const char *line) {
    while (*line && isspace(*line)) {
        line++;
    }

    return line;
}


/* Running Servers */

bool open_server_sock(struct proxy_server *server, int port) {
    struct sockaddr_in s_addr;
    server->sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (server->sock_fd < 0) {
        syslog(LOG_USER | LOG_ERR, "Error opening socket: %m");
        goto error;
    }

    s_addr.sin_family = AF_INET;
    s_addr.sin_addr.s_addr = INADDR_ANY;
    s_addr.sin_port = htons(port);

    if (bind(server->sock_fd, (struct sockaddr *)&s_addr, sizeof(s_addr))) {
        syslog(LOG_USER | LOG_ERR, "Error binding to port %d: %m", port);
        goto error;
    }

    if (listen(server->sock_fd, SOMAXCONN)) {
        syslog(LOG_USER | LOG_ERR, "Error listening for incoming connections on port %d: %m", port);
        goto error;
    }

    return true;

error:
    close(server->sock_fd);
    return false;
}

void run_servers(struct proxy_server *servers, size_t n) {
    int maxfd = -1;

    // Determine largest numbered file server socket file descriptor
    for (int i = 0; i < n; ++i) {
        if (servers[i].sock_fd > maxfd)
            maxfd = servers[i].sock_fd;
    }

    maxfd += 1;

    while (1) {
        fd_set rfds;

        FD_ZERO(&rfds);

        for (int i = 0; i < n; ++i) {
            FD_SET(servers[i].sock_fd, &rfds);
        }

        int retval = select(maxfd+1, &rfds, NULL, NULL, NULL);

        if (retval < 0) {
            syslog(LOG_USER | LOG_ERR, "SMTP: select() error: %m");
            break;
        }

        handle_accept(&rfds, servers, n);
    }
}

void handle_accept(const fd_set *rfds, struct proxy_server *servers, size_t n) {
    for (int i = 0; i < n; ++i) {
        if (FD_ISSET(servers[i].sock_fd, rfds)) {
            int clientfd = accept(servers[i].sock_fd, NULL, NULL);

            if (clientfd < 0) {
                syslog(LOG_USER | LOG_ERR, "Error accepting client connection: %m");
                continue;
            }

            struct proxy_client *client = malloc(sizeof(struct proxy_client));
            if (!client) {
                syslog(LOG_USER | LOG_CRIT, "Memory allocation failed");
                close(clientfd);
                continue;
            }

            client->fd = clientfd;
            client->server = &servers[i];

            pthread_t thread;

            if (pthread_create(&thread, NULL, handle_client, client)) {
                syslog(LOG_USER | LOG_ERR, "Error creating new client thread: %m");

                close(clientfd);
                free(client);
            }
        }
    }
}

void * handle_client(void *obj) {
    struct proxy_client *client = obj;
    GError *error = NULL;

    if (!get_goaclient(&error)) {
        syslog(LOG_ERR | LOG_USER, "Could not create GoaClient: %s", error->message);

        close(client->fd);
        goto end;
    }

    switch (client->server->type) {
    case TYPE_SMTP:
        smtp_handle_client(client->fd, client->server->host);
        break;

    case TYPE_IMAP:
        imap_handle_client(client->fd, client->server->host);
        break;
    }

end:
    free(client);
    return NULL;
}
