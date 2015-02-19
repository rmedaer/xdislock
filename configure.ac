#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([xdislock], [1.0.0], [dev@straightforward.me])
AM_INIT_AUTOMAKE([xdislock], [1.0.0])
AC_CONFIG_SRCDIR([src/])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([X11], [XOpenDisplay], [], [
    echo "X11 is required to control X server"
    exit -1])
AC_CHECK_LIB([pam], [pam_start], [], [
    echo "libpam is required to authenticate user"
    exit -1])
AC_CHECK_LIB([pthread], [pthread_mutex_lock], [], [
    echo "libpthread is required to synchronize threads"
    exit -1])

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h stdio.h unistd.h security/pam_appl.h X11/X.h X11/Xlib.h X11/Xutils.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([])

AC_CONFIG_FILES([Makefile
        man/Makefile
        src/Makefile])

AC_OUTPUT
