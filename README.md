# OAProxy

OAProxy is a local IMAP/SMTP proxy server which provides OAUTH2
authentication functionality to email clients which don't provide
support for it natively. Currently this is implemented using the Gnome
Online Accounts system.

This means you can use any email client to receive and send email
messages even with service providers which only support OAUTH2,
provided the service provider is supported by Gnome online accounts.

## How it Works

OAProxy is a local proxy server, running in the background, which is
configured to forward IMAP/SMTP requests from a given local port to
the remote IMAP/SMTP server. The email client is configured to
communicate with the proxy server, on localhost, rather than the
remote server.

The proxy server accepts standard basic authentication methods, namely
namely `AUTH PLAIN` for SMTP and `LOGIN` for IMAP, which is supported
by all email clients. The authentication commands, using the basic
authentication method, are replaced with OAUTH2 authentication
commands, which allows the user to be authenticated by the server,
even though the email client does not support OAUTH2
authentication. After successfully authenticating the user, all data
is simply forwarded to and from the server as though the client is
connected directly to the server, allowing email messages to be
sent/received.

## Configuration

_This section will follow shortly._
