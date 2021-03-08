# OAProxy

OAProxy is a local IMAP/SMTP proxy server, for Linux, which provides
OAUTH2 authentication functionality to email clients which don't
provide support for it natively. Currently this is implemented using
the Gnome Online Accounts system.

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

## Installation

### Dependencies

OAProxy depends on the following libraries which must be installed
prior to building.

* [OpenSSL](https://www.openssl.org/) version 1.1.1 or greater
* [GOA (Gnome Online Accounts)](https://wiki.gnome.org/Projects/GnomeOnlineAccounts) version 3.28 or greater

### Compilation

Download the latest version from Releases. Unpack the archive to a
directory of your choice and navigate to that directory. Run the
following commands:

```sh
./configure
make
sudo make install
```

### Systemd Service

If you're running on a system with systemd, you can launch oaproxy as
a service, running in the background, with the following command:

```sh
systemctl --user start oaproxy
```

**NOTE:** OAProxy is run as the current user (hence the `--user`
option and the lack of `sudo`) rather than `root`.

To stop OAProxy run the following command:

```sh
systemctl --user stop oaproxy
```

To launch OAProxy automatically on each login (of the current user)
run the following command:

```sh
systemctl --user enable oaproxy
```

Similarly, to disable OAProxy so that it is not launched on each
login, run the following command:

```sh
systemctl --user disable oaproxy
```

## Server Configuration

The remote IMAP and SMTP server settings are stored in the file
`/usr/local/etc/oaproxy.conf` (or `/usr/etc/oaproxy.conf` depending
on your installation settings).

Each non-blank line holds the configuration settings for a single
IMAP/SMTP server. The settings for a server are of the following form:

    [IMAP/SMTP] [local port] [remote server host]

The line begins with a keyword identifying the type of server, `IMAP`
or `SMTP`, followed by the local port, after a space, on which OAProxy
will listen for connections from email clients. Following the local
port is the remote server's host name which must be of the form
`host:port` where `host` is either the IP address or domain name and
port is the port on which connections to the remote server will be
made.

**NOTE:** Currently OAProxy only supports TLS/SSL connections to the
remote server thus the remote server must be able to accept a TLS
connection on the given port.

### Examples

    SMTP 3001 smtp.gmail.com:465

This specifies that OAProxy will listen for **SMTP** connections on
`localhost` port 3001 and will forward the data to the server
`smtp.gmail.com` on port 465.

    IMAP 3002 imap.gmail.com:993
	
This specifies that OAProxy will listen for **IMAP** connections on
`localhost` port 3002 and will forward the data to the server
`imap.gmail.com` on port 993.

These settings are the default settings in the `oaproxy.conf` file
included with the distribution.


## Email Client Configuration

Prior to setting up your email client you must configure a Gnome
Online Account for your email account. Instructions on how to do so
are provided at
<https://help.gnome.org/users/gnome-help/stable/accounts.html.en>.

### Server Settings

To allow email clients to connect to email providers via OAUTH2,
without supporting it natively, they must be configured to connect to
OAProxy which will forward the data to the correct remote server,
whilst taking care of OAUTH2 authentication.

Both the IMAP (receiving) and SMTP (sending) servers should be changed
to `localhost`, with the correct ports, as specified in
`oaproxy.conf`, matching the configuration for the original remote
server. For example, using the example `oaproxy.conf` given in the
previous section, if the original IMAP server host is `imap.gmail.com`
with local port `3001`, the IMAP server in the email client should be
changed to `localhost` on port 3001.

**IMPORTANT:** TLS/SSL and STARTTLS, should be disabled for both IMAP
and SMTP. For example in Claws and Sylpheed go to the `SSL` settings
for your account and check the `Don't use SSL` radio button. This does
not mean your data is transmitted over the Internet in plain text,
OAProxy communicates with the remote server over TLS. Only the
communication between your email client and OAProxy, which is local to
the machine, happens in plain text.

### IMAP (Receiving Mail) Settings

OAProxy recognizes only the `LOGIN` IMAP authentication
command. Therefore under the IMAP settings of your email client, the
authentication method should be changed to either **LOGIN**
(e.g. Sylpheed) or **Plain Text** (e.g. Claws Mail), depending on the
terminology used by your email client.

### SMTP (Sending Mail) Settings

OAProxy recognizes only the `PLAIN` SMTP authentication
method. Therefore in the SMTP settings of your email client, the
authentication method should be changed to **PLAIN**.

### User Settings

The username should be changed to the username corresponding to the
Gnome Online account, this is generally the full email address. The
password is currently not used or checked by OAProxy thus can be left
blank or filled with a dummy password.
