# Initialization
AC_INIT([goaproxy], [0.1.0], [alex.gutev@mail.bg])
AC_CONFIG_SRCDIR([src/main.c])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])
AM_SILENT_RULES([yes])


# Required Tools

AC_PROG_CC
PKG_PROG_PKG_CONFIG

# Libraries

PKG_CHECK_MODULES([GOA], [goa-1.0])

# Output

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
