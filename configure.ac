# Initialization
AC_INIT([oaproxy], [0.1.0], [alex.gutev@mail.bg])
AC_CONFIG_SRCDIR([src/main.c])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])
AM_SILENT_RULES([yes])

# Required Tools

AC_PROG_CC
PKG_PROG_PKG_CONFIG

# Libraries

AX_PTHREAD

PKG_CHECK_MODULES([GOA], [goa-1.0 >= 3.28])
PKG_CHECK_MODULES([OPENSSL], [openssl >= 1.1.1])

# Unit Testing

PKG_CHECK_MODULES([CMOCKA], [cmocka],
    [AC_DEFINE([HAVE_CMOCKA], [1], [Found cmocka unit test library.])],
    [AC_DEFINE([HACE_CMOCKA], [0], [Found cmocka unit test library.])]
)

# Systemd

AC_ARG_WITH([systemduserunitdir],
     [AS_HELP_STRING([--with-systemduserunitdir=DIR], [Directory for systemd service files])],,
     [with_systemduserunitdir=auto])

AS_IF([test "x$with_systemduserunitdir" = "xyes" -o "x$with_systemduserunitdir" = "xauto"],
      [def_systemduserunitdir=$($PKG_CONFIG --variable=systemduserunitdir systemd)

      AS_IF([test "x$def_systemduserunitdir" = "x"],
            [AS_IF([test "x$with_systemduserunitdir" = "xyes"],
                   [AC_MSG_ERROR([systemd support requested but pkg-config unable to query systemd package])])
             with_systemduserunitdir=no],
            [with_systemduserunitdir="$def_systemduserunitdir"])])

AS_IF([test "x$with_systemduserunitdir" != "xno"],
      [AC_SUBST([systemduserunitdir], [$with_systemduserunitdir])])

AM_CONDITIONAL([HAVE_SYSTEMD], [test "x$with_systemduserunitdir" != "xno"])

# Output

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
