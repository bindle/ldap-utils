#
#   LDAP Utilities
#   Copyright (c) 2008 David M. Syzdek <ldap-utils-project@syzdek.net>.
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
#   acinclude.m4 - custom m4 macros used by configure.ac
#

# AC_LDAP_UTILS_ENABLE_WARNINGS()
# ______________________________________________________________________________
AC_DEFUN([AC_LDAP_UTILS_ENABLE_WARNINGS],[dnl

   # prerequists
   AC_REQUIRE([AC_PROG_CC])

   # sets compiler
   if test "x${CC}" == "x";then
      ac_ldap_utils_cc=cc;
   else
      ac_ldap_utils_cc=${CC};
   fi

   # display options
   enableval=""
   AC_ARG_ENABLE(
      warnings,
      [AC_HELP_STRING([--disable-warnings], [disable compiler warnings])],
      [ EWARNINGS=$enableval ],
      [ EWARNINGS=$enableval ]
   )
   enableval=""
   AC_ARG_ENABLE(
      strictwarnings,
      [AC_HELP_STRING([--enable-strictwarnings], [enable strict compiler warnings])],
      [ ESTRICTWARNINGS=$enableval ],
      [ ESTRICTWARNINGS=$enableval ]
   )

   # sets options
   if test "x${ESTRICTWARNINGS}" != "xyes";then
      USE_STRICTWARNINGS=no
   else
      USE_STRICTWARNINGS=yes
   fi
   if test "x${EWARNINGS}" != "xno";then
      USE_WARNINGS=yes
   else
      USE_WARNINGS=no
      USE_STRICTWARNINGS=no
   fi

   # list of args
   ac_ldap_utils_warnings_list=""
   if test "x${USE_WARNINGS}" == "xyes";then
      ac_ldap_utils_warnings_list=" ${ac_ldap_utils_warnings_list} -W"
      ac_ldap_utils_warnings_list=" ${ac_ldap_utils_warnings_list} -Wall"
      ac_ldap_utils_warnings_list=" ${ac_ldap_utils_warnings_list} -Werror"
   fi
   if test "x${USE_STRICTWARNINGS}" == "xyes";then
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -std=gnu99"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -pedantic"
      #ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wtraditional"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wpragma-once"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wextra-tokens"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wnewline-eof"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wsequence-point"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wdiv-by-zero"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wfloat-equal"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wdisabled-optimization"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wchar-subscripts"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wcomment"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wformat"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wimplicit"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wmain"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wmissing-braces"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wparentheses"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wreturn-type"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wswitch"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wswitch-default"   # for some reason any call to memset() fails with this flag
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wtrigraphs"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wunused"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wunknown-pragmas"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wuninitialized"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wmultichar"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wundef"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wendif-labels"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wshadow"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wlarger-than-4096"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wpointer-arith"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wbad-function-cast"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wcast-qual"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wcast-align"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wwrite-strings"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wconversion"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wsign-compare"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Waggregate-return"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wstrict-prototypes"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wstrict-aliasing"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wmissing-prototypes"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wmissing-declarations"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wmissing-noreturn"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wmissing-format-attribute" # vprintf is failing this warning
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wredundant-decls"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wunreachable-code"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Winvalid-pch"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wpacked"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wpadded"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wnested-externs"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wenum-clash"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Winline"
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wlong-long"
   fi

   # creates test source code
   AC_LANG_CONFTEST(
      [AC_LANG_PROGRAM(
         [[int main(void);]],
         [[return(0);]]
      )])

   # loops throough options
   CFLAGS_WARNINGS=""
   for ac_ldap_utils_warning in ${ac_ldap_utils_warnings_list};do
      AC_MSG_CHECKING(for gcc flag ${ac_ldap_utils_warning})
      ${ac_ldap_utils_cc} ${CFLAGS_WARNINGS} ${ac_ldap_utils_warning} conftest.c -o conftest.o > /dev/null 2>&1
      if test "x$?" == "x0";then
         CFLAGS_WARNINGS="${CFLAGS_WARNINGS} ${ac_ldap_utils_warning}"
         AC_MSG_RESULT(yes)
      else
         AC_MSG_RESULT(no)
      fi
   done

   # export variables
   AC_SUBST(CFLAGS_WARNINGS, "$CFLAGS_WARNINGS")
])dnl

# end of M4 file
