#
#   LDAP Utilities
#   Copyright (C) 2015, 2019, 2023 David M. Syzdek <david@syzdek.net>.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are
#   met:
#
#      1. Redistributions of source code must retain the above copyright
#         notice, this list of conditions and the following disclaimer.
#
#      2. Redistributions in binary form must reproduce the above copyright
#         notice, this list of conditions and the following disclaimer in the
#         documentation and/or other materials provided with the distribution.
#
#      3. Neither the name of the copyright holder nor the names of its
#         contributors may be used to endorse or promote products derived from
#         this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
#   IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
#   THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
#   PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
#   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
#   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
#   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
#   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
#   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
#   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#   configure.ac - automate compiling on a unix platform
#

# +-=-=-=-=-=-=-=-=-+
# |                 |
# |  Autoconf Init  |
# |                 |
# +-=-=-=-=-=-=-=-=-+

AC_PREREQ(2.65)

AC_COPYRIGHT([Copyright (C) 2015, 2019, 2020, 2023 David M. Syzdek <david@syzdek.net>.])
AC_REVISION(0.1)
AC_INIT([LDAP Utilities],[0.6],[david@syzdek.net],[ldap-utils])

AC_SUBST([RELEASE_MONTH],["January 2023"])

PACKAGE_COPYRIGHT="Copyright (C) 2008, 2009, 2015, 2019, 2020, 2023 David M. Syzdek <david@syzdek.net>."
AC_DEFINE_UNQUOTED(PACKAGE_COPYRIGHT, ["${PACKAGE_COPYRIGHT}"], [Copyright notice.])
AC_SUBST([PACKAGE_COPYRIGHT], [${PACKAGE_COPYRIGHT}])


# directory locations
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_SRCDIR([build-aux/git-tar-name.txt])
#AC_CONFIG_LIBOBJ_DIR(compat)
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# determines host type
AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

# configures for automake
AM_INIT_AUTOMAKE(gnu std-options subdir-objects foreign)

# Compilers                                                       
AC_USE_SYSTEM_EXTENSIONS # replaces AC_AIX AC_GNU_SOURCE AC_MINIX
AC_PROG_CC
#AC_PROG_OBJC
AC_PROG_CXX
AM_PROG_CC_C_O
AC_PROG_LEX(yywrap)
AC_PROG_YACC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_C_BIGENDIAN
AC_C_INLINE
AC_C_RESTRICT

# Version Info:
#    Current    -- the current version number of this API
#    Revision   -- the revision of the implementation of the API version
#    Age        -- How many seqential past API versions is supported by
#                  this implementation
# Format => Current:Revision:Age
# Convenience macro:
#    AC_BINDLE_LIBTOOL_VERSION_INFO(current, revision, age)
AC_BINDLE_LIBTOOL_VERSION_INFO(0, 0, 0)

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
AC_PROG_MKDIR_P
AC_PROG_SED

# GNU Libtool Support
LT_INIT(dlopen disable-fast-install win32-dll)

# check for common functions
AC_FUNC_ALLOCA
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STRERROR_R

# Type checks
AC_TYPE_INT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UID_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
#AC_CHECK_TYPES([LDAPURLDesc],,         [AC_MSG_ERROR([missing required datatype])],[#include <ldap.h>])
AC_CHECK_TYPES([ptrdiff_t],,            [AC_MSG_ERROR([missing required datatype])],[#include <stddef.h>])

# check for required functions
AC_CHECK_FUNCS([bzero],          [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([getpass],        [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([gettimeofday],   [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([memset],         [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([regcomp],        [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([setlocale],      [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([socket],         [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([strcasecmp],     [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([strchr],         [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([strdup],         [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([strerror],       [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([strncasecmp],    [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([strrchr],        [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([strtol],         [], [AC_MSG_ERROR([missing required functions])])
AC_CHECK_FUNCS([strtoull],       [], [AC_MSG_ERROR([missing required functions])])

# check for required libraries
AC_SEARCH_LIBS([getopt_long],          c gnugetopt,,AC_MSG_ERROR([missing required function]))
AC_SEARCH_LIBS([ldap_dn2str],          ldap,,AC_MSG_ERROR([missing required function]), [-llber])
AC_SEARCH_LIBS([ldap_dnfree],          ldap,,AC_MSG_ERROR([missing required function]), [-llber])
AC_SEARCH_LIBS([ldap_explode_dn],      ldap,,AC_MSG_ERROR([missing required function]), [-llber])
AC_SEARCH_LIBS([ldap_first_entry],     ldap,,AC_MSG_ERROR([missing required function]), [-llber])
AC_SEARCH_LIBS([ldap_free_urldesc],    ldap,,AC_MSG_ERROR([missing required function]), [-llber])
AC_SEARCH_LIBS([ldap_get_dn],          ldap,,AC_MSG_ERROR([missing required function]), [-llber])
AC_SEARCH_LIBS([ldap_initialize],      ldap,,AC_MSG_ERROR([missing required function]), [-llber])
AC_SEARCH_LIBS([ldap_result],          ldap,,AC_MSG_ERROR([missing required function]), [-llber])
AC_SEARCH_LIBS([ldap_sasl_bind_s],     ldap,,AC_MSG_ERROR([missing required function]), [-llber])
AC_SEARCH_LIBS([ldap_search_ext],      ldap,,AC_MSG_ERROR([missing required function]), [-llber])
AC_SEARCH_LIBS([ldap_set_option],      ldap,,AC_MSG_ERROR([missing required function]), [-llber])
AC_SEARCH_LIBS([ldap_str2dn],          ldap,,AC_MSG_ERROR([missing required function]), [-llber])
AC_SEARCH_LIBS([ldap_unbind_ext_s],    ldap,,AC_MSG_ERROR([missing required function]), [-llber])
AC_SEARCH_LIBS([ldap_url_parse],       ldap,,AC_MSG_ERROR([missing required function]), [-llber])
AC_SEARCH_LIBS([ldap_value_free],      ldap,,AC_MSG_ERROR([missing required function]), [-llber])
AC_SEARCH_LIBS([socket],               socket,,AC_MSG_ERROR([missing required function]), [-lresolv])

# check for headers
AC_CHECK_HEADER_STDBOOL
AC_CHECK_HEADERS([fcntl.h],,           [AC_MSG_ERROR([missing required header])])
AC_CHECK_HEADERS([getopt.h],,          [AC_MSG_ERROR([missing required header])])
AC_CHECK_HEADERS([inttypes.h],,        [AC_MSG_ERROR([missing required header])])
AC_CHECK_HEADERS([ldap.h],,            [AC_MSG_ERROR([missing required header])])
AC_CHECK_HEADERS([signal.h],,          [AC_MSG_ERROR([missing required header])])
AC_CHECK_HEADERS([stdint.h],,          [AC_MSG_ERROR([missing required header])])
AC_CHECK_HEADERS([string.h],,          [AC_MSG_ERROR([missing required header])])
AC_CHECK_HEADERS([strings.h],,         [AC_MSG_ERROR([missing required header])])
AC_CHECK_HEADERS([termios.h],,         [AC_MSG_ERROR([missing required header])])
AC_CHECK_HEADERS([unistd.h],,          [AC_MSG_ERROR([missing required header])])
AC_CHECK_HEADERS([libintl.h])
AC_CHECK_HEADERS([malloc.h])
AC_CHECK_HEADERS([sgtty.h])
AC_CHECK_HEADERS([stddef.h])

# initiates bindle tools macros
AC_BINDLE(contrib/bindletools)

# determine PACKAGE_VERSION via Git
AC_BINDLE_GIT_PACKAGE_VERSION([contrib/bindletools/build-aux/git-package-version.sh])

# custom configure options
AC_BINDLE_ENABLE_WARNINGS([-Wno-padded -Wno-unknown-pragmas], [-Wpadded])
AC_LDAP_UTILS_UTILITIES
AC_LDAP_UTILS_LIBRARIES
AC_LDAP_UTILS_LIBLDAPSCHEMA
AC_LDAP_UTILS_LIBLDAPUTILS
AC_LDAP_UTILS_LDAP2CSV
AC_LDAP_UTILS_LDAP2JSON
AC_LDAP_UTILS_LDAPCONNS
AC_LDAP_UTILS_LDAPDEBUG
AC_LDAP_UTILS_LDAPDN2STR
AC_LDAP_UTILS_LDAPINFO
AC_LDAP_UTILS_LDAPSCHEMA
AC_LDAP_UTILS_LDAPTREE
AC_LDAP_UTILS_OIDSPECTOOL

# Creates outputs
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

# Show local config
AC_MSG_NOTICE([ ])
AC_MSG_NOTICE([   LDAP Utilities ($PACKAGE_VERSION)])
AC_MSG_NOTICE([ ])
AC_MSG_NOTICE([   Use Warnings                  $USE_WARNINGS])
AC_MSG_NOTICE([   Use Strict Warnings           $USE_STRICTWARNINGS])
AC_MSG_NOTICE([ ])
AC_MSG_NOTICE([   Libraries:])
AC_MSG_NOTICE([      libldapschema.a            $LDAPUTILS_LIBLDAPSCHEMA_STATUS])
AC_MSG_NOTICE([      libldapschema.la           $LDAPUTILS_LTLIBLDAPSCHEMA_STATUS])
AC_MSG_NOTICE([      libldaputils.a             $LDAPUTILS_LIBLDAPUTILS_STATUS])
AC_MSG_NOTICE([ ])
AC_MSG_NOTICE([   Utilities:])
AC_MSG_NOTICE([      ldap2csv                   $LDAPUTILS_LDAP2CSV_STATUS])
AC_MSG_NOTICE([      ldap2json                  $LDAPUTILS_LDAP2JSON_STATUS])
AC_MSG_NOTICE([      ldapconns                  $LDAPUTILS_LDAPCONNS_STATUS])
AC_MSG_NOTICE([      ldapdebug                  $LDAPUTILS_LDAPDEBUG_STATUS])
AC_MSG_NOTICE([      ldapdn2str                 $LDAPUTILS_LDAPDN2STR_STATUS])
AC_MSG_NOTICE([      ldapinfo                   $LDAPUTILS_LDAPINFO_STATUS])
AC_MSG_NOTICE([      ldapschema                 $LDAPUTILS_LDAPSCHEMA_STATUS])
AC_MSG_NOTICE([      ldaptree                   $LDAPUTILS_LDAPTREE_STATUS])
AC_MSG_NOTICE([ ])
AC_MSG_NOTICE([   Internal Utilities:])
AC_MSG_NOTICE([      oidspectool                $LDAPUTILS_OIDSPECTOOL_STATUS])
AC_MSG_NOTICE([ ])
AC_MSG_NOTICE([   Please send suggestions to:   $PACKAGE_BUGREPORT])
AC_MSG_NOTICE([ ])
AC_MSG_NOTICE([   run 'make all'])
AC_MSG_NOTICE([ ])

# end of configure.ac
