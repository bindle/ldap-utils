#
#   LDAP Utilities
#   Copyright (C) 2019 David M. Syzdek <david@syzdek.net>.
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
#   acinclude.m4 - custom m4 macros used by configure.ac
#

# AC_LDAP_UTILS_LDAP2CSV
# ______________________________________________________________________________
AC_DEFUN([AC_LDAP_UTILS_LDAP2CSV],[dnl

   enableval=""
   AC_ARG_ENABLE(
      ldap2csv,
      [AS_HELP_STRING([--disable-ldap2csv], [disable building ldap2csv])],
      [ ELDAP2CSV=$enableval ],
      [ ELDAP2CSV=$enableval ]
   )

   if test "x${ELDAP2CSV}" != "xno";then
      ELDAP2CSV=yes
   fi
   LDAPUTILS_LDAP2CSV=${ELDAP2CSV}

   AM_CONDITIONAL([LDAPUTILS_LDAP2CSV], [test "x$LDAPUTILS_LDAP2CSV" = "xyes"])
])dnl


# AC_LDAP_UTILS_LDAPTREE
# ______________________________________________________________________________
AC_DEFUN([AC_LDAP_UTILS_LDAPTREE],[dnl

   enableval=""
   AC_ARG_ENABLE(
      ldaptree,
      [AS_HELP_STRING([--disable-ldaptree], [disable building ldaptree])],
      [ ELDAPTREE=$enableval ],
      [ ELDAPTREE=$enableval ]
   )

   if test "x${ELDAPTREE}" != "xno";then
      ELDAPTREE=yes
   fi
   LDAPUTILS_LDAPTREE=${ELDAPTREE}

   AM_CONDITIONAL([LDAPUTILS_LDAPTREE], [test "x$LDAPUTILS_LDAPTREE" = "xyes"])
])dnl



# end of M4 file
