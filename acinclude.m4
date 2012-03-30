#
#   LDAP Utilities
#   Copyright (C) 2012 Bindle Binaries <syzdek@bindlebinaries.com>.
#
#   @BINDLE_BINARIES_BSD_LICENSE_START@
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are
#   met:
#
#      * Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#      * Redistributions in binary form must reproduce the above copyright
#        notice, this list of conditions and the following disclaimer in the
#        documentation and/or other materials provided with the distribution.
#      * Neither the name of Bindle Binaries nor the
#        names of its contributors may be used to endorse or promote products
#        derived from this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
#   IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
#   THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
#   PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL BINDLE BINARIES BE LIABLE FOR
#   ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#   CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
#   LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
#   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
#   SUCH DAMAGE.
#
#   @BINDLE_BINARIES_BSD_LICENSE_END@
#
#   acinclude.m4 - custom m4 macros used by configure.ac
#

# AC_DMS_GIT_PACKAGE_VERSION()
# -----------------------------------
AC_DEFUN([AC_DMS_GIT_PACKAGE_VERSION],[dnl

   if test -f ${srcdir}/.git/config;then
      GPV=$(${ac_aux_dir}/git-package-version.sh "${srcdir}")
      if test "x${GPV}" != "x";then
         AC_MSG_NOTICE([using git package version ${GPV}])
      fi
   elif test -f ${ac_aux_dir}/git-package-version;then
      GPV=$(cat ${ac_aux_dir}/git-package-version 2> /dev/null)
      if test "x${GPV}" != "x";then
         AC_MSG_NOTICE([using cached git package version ${GPV}])
      fi
   fi

   if test "x${GPV}" = "x";then
      AC_MSG_WARN([unable to determine package version from Git tags])
   else
      #
      # set internal variables
      GIT_PACKAGE_VERSION=${GPV}
      PACKAGE_VERSION=${GPV}
      VERSION=${GPV}
      #
      # set substitution variables
      AC_SUBST([GIT_PACKAGE_VERSION], [${GPV}])
      AC_SUBST([PACKAGE_VERSION], [${GPV}])
      AC_SUBST([VERSION], [${GPV}])
      #
      # set C/C++/Objc preprocessor macros
      AC_DEFINE_UNQUOTED([GIT_PACKAGE_VERSION], ["${GIT_PACKAGE_VERSION}"], [package version determined from git repository])
      AC_DEFINE_UNQUOTED([PACKAGE_VERSION], ["${GIT_PACKAGE_VERSION}"], [package version determined from git repository])
      AC_DEFINE_UNQUOTED([VERSION], ["${GIT_PACKAGE_VERSION}"], [package version determined from git repository])
   fi
])dnl


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
      ac_ldap_utils_warnings_list="${ac_ldap_utils_warnings_list} -Wswitch-default"
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
   for ac_ldap_utils_warning in ${ac_ldap_utils_warnings_list};do
      AC_MSG_CHECKING(for gcc flag ${ac_ldap_utils_warning})
      ${ac_ldap_utils_cc} ${CFLAGS} ${ac_ldap_utils_warning} conftest.c -o conftest.o > /dev/null 2>&1
      if test "x$?" == "x0";then
         CFLAGS="${CFLAGS} ${ac_ldap_utils_warning}"
         AC_MSG_RESULT(yes)
      else
         AC_MSG_RESULT(no)
      fi
   done
])dnl

# end of M4 file
