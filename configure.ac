#
#   LDAP Utilities
#   Copyright (c) 2008 David M. Syzdek <david@syzdek.net>.
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
#
#   configure.ac - automate compiling on a unix platform
#

# +-=-=-=-=-=-=-=-=-+
# |                 |
# |  Autoconf Init  |
# |                 |
# +-=-=-=-=-=-=-=-=-+

AC_PREREQ(2.62)

AC_COPYRIGHT([Copyright (c) 2008 David M. Syzdek <ldap-utils-project@syzdek.net>.])
AC_REVISION($Revision$)
AC_INIT([LDAP Utilities],[0.1.2],[syzdek@users.sourceforge.net],[ldap-utils])
AC_SUBST([RELEASE_MONTH],["October 2008"])

# Version Info:
#    Current    -- the current version number of this API
#    Revision   -- the revision of the implementation of the API version
#    Age        -- How many seqential past API versions is supported by
#                  this implementation
# Format => Current:Revision:Age
AC_SUBST(LIB_VERSION_INFO, 0:0:0)
AC_SUBST(LIB_RELEASE_INFO, 0) # used by Win32 DLLs

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_SRCDIR([.])
AC_CONFIG_HEADERS([config.h])

# determines host type
AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

# configures for automake
AM_INIT_AUTOMAKE(gnu std-options subdir-objects)

# Compilers                                                       
AC_PROG_CC 
AM_PROG_CC_C_O
AC_PROG_INSTALL

# checks for Unix Variants
AC_USE_SYSTEM_EXTENSIONS # replaces AC_AIX AC_GNU_SOURCE AC_MINIX
#AC_AIX
#AC_GNU_SOURCE
#AC_MINIX
AC_C_BIGENDIAN

# gnulib support
#gl_EARLY
#gl_INIT

# binary locations
AC_PATH_PROG([SHELL],   sh bash,        [AC_MSG_ERROR([missing "sh"])], [$PATH])
AC_CHECK_TOOLS(AR,      ar gar,         [AC_MSG_ERROR([missing binutil "ar"])])
AC_CHECK_TOOLS(LD,      ld gld,         [AC_MSG_ERROR([missing binutil "ld"])])
AC_CHECK_TOOLS(NM,      nm gnm,         [AC_MSG_ERROR([missing binutil "nm"])])
AC_CHECK_TOOLS(RANLIB,  ranlib granlib, [AC_MSG_ERROR([missing binutil "ranlib"])])
AC_CHECK_TOOLS(STRIP,   strip gstrip,   [AC_MSG_ERROR([missing binutil "strip"])])

# shell programs
AC_PROG_AWK
AC_PROG_EGREP
AC_PROG_FGREP
AM_PROG_LEX
AC_PROG_LN_S

# GNU Libtool Support
AC_LIBTOOL_DLOPEN
AC_DISABLE_FAST_INSTALL
AC_LIBTOOL_WIN32_DLL
AC_PROG_LIBTOOL

# GNU gettext support
AM_GNU_GETTEXT([external])

# Defines macros
AC_CHECK_LIB(ws2_32, write)
AC_CHECK_LIB(socket, socket,,resolv)
AC_CHECK_HEADERS([termios.h])
AC_CHECK_HEADERS([ldap.h],,            [AC_MSG_ERROR([missing required header])])
AC_CHECK_HEADERS([getopt.h],,          [AC_MSG_ERROR([missing required header])])
AC_SEARCH_LIBS([getopt_long],          c gnugetopt,,AC_MSG_ERROR([missing required function]))
AC_SEARCH_LIBS([ldap_first_entry],     ldap,,AC_MSG_ERROR([missing required function]), [-llber])
AC_SEARCH_LIBS([ldap_free_urldesc],    ldap,,AC_MSG_ERROR([missing required function]), [-llber])
AC_SEARCH_LIBS([ldap_get_dn],          ldap,,AC_MSG_ERROR([missing required function]), [-llber])
AC_SEARCH_LIBS([ldap_initialize],      ldap,,AC_MSG_ERROR([missing required function]), [-llber])
AC_SEARCH_LIBS([ldap_result],          ldap,,AC_MSG_ERROR([missing required function]), [-llber])
AC_SEARCH_LIBS([ldap_sasl_bind_s],     ldap,,AC_MSG_ERROR([missing required function]), [-llber])
AC_SEARCH_LIBS([ldap_search_ext],      ldap,,AC_MSG_ERROR([missing required function]), [-llber])
AC_SEARCH_LIBS([ldap_set_option],      ldap,,AC_MSG_ERROR([missing required function]), [-llber])
AC_SEARCH_LIBS([ldap_unbind_ext_s],    ldap,,AC_MSG_ERROR([missing required function]), [-llber])
AC_SEARCH_LIBS([ldap_url_parse],       ldap,,AC_MSG_ERROR([missing required function]), [-llber])
#AC_CHECK_TYPES([LDAPURLDesc],,         [AC_MSG_ERROR([missing required datatype])],[#include <ldap.h>])

AC_LDAP_UTILS_ENABLE_WARNINGS

# checks host
case "${host_os}" in
   *mingw32*) WINTEST=yes ;;
   *win32*)   WINTEST=yes ;;
   *cygwin*)  WINTEST=yes ;;
esac
AM_CONDITIONAL([WIN32], [test "x${WINTEST}" = "xyes"])

AC_SYZDEK_GIT_PACKAGE_VERSION

# Creates outputs
AC_CONFIG_FILES([Makefile po/Makefile.in])
AC_OUTPUT

# Show local config
AC_MSG_NOTICE([ ])
AC_MSG_NOTICE([   LDAP Utilities])
AC_MSG_NOTICE([ ])
AC_MSG_NOTICE([   Use Warnings                  $USE_WARNINGS])
AC_MSG_NOTICE([   Use Strict Warnings           $USE_STRICTWARNINGS])
AC_MSG_NOTICE([ ])
AC_MSG_NOTICE([   Please send suggestions to:   $PACKAGE_BUGREPORT])
AC_MSG_NOTICE([ ])
AC_MSG_NOTICE([   run `make all'])
AC_MSG_NOTICE([ ])

# end of autoconf script
