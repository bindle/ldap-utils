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

   # prerequists
   AC_REQUIRE([AC_LDAP_UTILS_UTILITIES])

   enableval=""
   AC_ARG_ENABLE(
      ldap2csv,
      [AS_HELP_STRING([   --disable-ldap2csv], [disable building ldap2csv utility])],
      [ ELDAP2CSV=$enableval ],
      [ ELDAP2CSV=$enableval ]
   )

   if test "x${ELDAP2CSV}" != "x${LDAPUTILS_UTILITIES_ALT}";then
      ELDAP2CSV=${LDAPUTILS_UTILITIES}
   fi
   LDAPUTILS_LDAP2CSV=${ELDAP2CSV}

   AM_CONDITIONAL([LDAPUTILS_LDAP2CSV], [test "x$LDAPUTILS_LDAP2CSV" = "xyes"])
])dnl


# AC_LDAP_UTILS_LDAP2JSON
# ______________________________________________________________________________
AC_DEFUN([AC_LDAP_UTILS_LDAP2JSON],[dnl

   # prerequists
   AC_REQUIRE([AC_LDAP_UTILS_UTILITIES])

   enableval=""
   AC_ARG_ENABLE(
      ldap2csv,
      [AS_HELP_STRING([   --disable-ldap2json], [disable building ldap2json utility])],
      [ ELDAP2JSON=$enableval ],
      [ ELDAP2JSON=$enableval ]
   )

   if test "x${ELDAP2JSON}" != "x${LDAPUTILS_UTILITIES_ALT}";then
      ELDAP2JSON=${LDAPUTILS_UTILITIES}
   fi
   LDAPUTILS_LDAP2JSON=${ELDAP2CSV}

   AM_CONDITIONAL([LDAPUTILS_LDAP2JSON], [test "x$LDAPUTILS_LDAP2JSON" = "xyes"])
])dnl


# AC_LDAP_UTILS_LDAPDEBUG
# ______________________________________________________________________________
AC_DEFUN([AC_LDAP_UTILS_LDAPDEBUG],[dnl

   # prerequists
   AC_REQUIRE([AC_LDAP_UTILS_UTILITIES])

   enableval=""
   AC_ARG_ENABLE(
      ldapdebug,
      [AS_HELP_STRING([   --enable-ldapdebug], [enable building ldapdebug utility])],
      [ ELDAPDEBUG=$enableval ],
      [ ELDAPDEBUG=$enableval ]
   )

   if test "x${ELDAPDEBUG}" != "xyes";then
      ELDAPDEBUG=no
   fi
   LDAPUTILS_LDAPDEBUG=${ELDAPDEBUG}

   AM_CONDITIONAL([LDAPUTILS_LDAPDEBUG], [test "x$LDAPUTILS_LDAPDEBUG" = "xyes"])
])dnl


# AC_LDAP_UTILS_LDAPDN2STR
# ______________________________________________________________________________
AC_DEFUN([AC_LDAP_UTILS_LDAPDN2STR],[dnl

   # prerequists
   AC_REQUIRE([AC_LDAP_UTILS_UTILITIES])

   enableval=""
   AC_ARG_ENABLE(
      ldapdn2str,
      [AS_HELP_STRING([   --disable-ldapdn2str], [disable building ldapdn2str utility])],
      [ ELDAPDN2STR=$enableval ],
      [ ELDAPDN2STR=$enableval ]
   )

   if test "x${ELDAPDN2STR}" != "x${LDAPUTILS_UTILITIES_ALT}";then
      ELDAPDN2STR=${LDAPUTILS_UTILITIES}
   fi
   LDAPUTILS_LDAPDN2STR=${ELDAPDN2STR}

   AM_CONDITIONAL([LDAPUTILS_LDAPDN2STR], [test "x$LDAPUTILS_LDAPDN2STR" = "xyes"])
])dnl


# AC_LDAP_UTILS_LDAPINFO
# ______________________________________________________________________________
AC_DEFUN([AC_LDAP_UTILS_LDAPINFO],[dnl

   # prerequists
   AC_REQUIRE([AC_LDAP_UTILS_UTILITIES])

   enableval=""
   AC_ARG_ENABLE(
      ldapinfo,
      [AS_HELP_STRING([   --disable-ldapinfo], [disable building ldapinfo utility])],
      [ ELDAPINFO=$enableval ],
      [ ELDAPINFO=$enableval ]
   )

   if test "x${ELDAPINFO}" != "x${LDAPUTILS_UTILITIES_ALT}";then
      ELDAPINFO=${LDAPUTILS_UTILITIES}
   fi
   LDAPUTILS_LDAPINFO=${ELDAPINFO}

   AM_CONDITIONAL([LDAPUTILS_LDAPINFO], [test "x$LDAPUTILS_LDAPINFO" = "xyes"])
])dnl


# AC_LDAP_UTILS_LDAPSCHEMA
# ______________________________________________________________________________
AC_DEFUN([AC_LDAP_UTILS_LDAPSCHEMA],[dnl

   enableval=""
   AC_ARG_ENABLE(
      ldapschema,
      [AS_HELP_STRING([   --enable-ldapschema], [enable ldapschema utility (experimental)])],
      [ ELDAPSCHEMA=$enableval ],
      [ ELDAPSCHEMA=$enableval ]
   )

   if test "x${ELDAPSCHEMA}" != "xyes";then
      ELDAPSCHEMA=no
   fi
   LDAPUTILS_LDAPSCHEMA=${ELDAPSCHEMA}

   AM_CONDITIONAL([LDAPUTILS_LDAPSCHEMA], [test "x$LDAPUTILS_LDAPSCHEMA" = "xyes"])
])dnl


# AC_LDAP_UTILS_LDAPTREE
# ______________________________________________________________________________
AC_DEFUN([AC_LDAP_UTILS_LDAPTREE],[dnl

   # prerequists
   AC_REQUIRE([AC_LDAP_UTILS_UTILITIES])

   enableval=""
   AC_ARG_ENABLE(
      ldaptree,
      [AS_HELP_STRING([   --disable-ldaptree], [disable building ldaptree utility])],
      [ ELDAPTREE=$enableval ],
      [ ELDAPTREE=$enableval ]
   )

   if test "x${ELDAPTREE}" != "x${LDAPUTILS_UTILITIES_ALT}";then
      ELDAPTREE=${LDAPUTILS_UTILITIES}
   fi
   LDAPUTILS_LDAPTREE=${ELDAPTREE}

   AM_CONDITIONAL([LDAPUTILS_LDAPTREE], [test "x$LDAPUTILS_LDAPTREE" = "xyes"])
])dnl


# AC_LDAP_UTILS_LIBLDAPSCHEMA
# ______________________________________________________________________________
AC_DEFUN([AC_LDAP_UTILS_LIBLDAPSCHEMA],[dnl

   enableval=""
   AC_ARG_ENABLE(
      libldapschema,
      [AS_HELP_STRING([   --enable-libldapschema], [enable ldapschema library (experimental)])],
      [ ELIBLDAPSCHEMA=$enableval ],
      [ ELIBLDAPSCHEMA=$enableval ]
   )

   #if test "x${ELIBLDAPSCHEMA}" != "x${LDAPUTILS_LIBRARIES_ALT}";then
   #   ELIBLDAPSCHEMA=${LDAPUTILS_LIBRARIES}
   #fi
   if test "x${ELIBLDAPSCHEMA}" != "xyes";then
      ELIBLDAPSCHEMA=no
   fi
   LDAPUTILS_LIBLDAPSCHEMA=${ELIBLDAPSCHEMA}

   AM_CONDITIONAL([LDAPUTILS_LIBLDAPSCHEMA], [test "x$LDAPUTILS_LIBLDAPSCHEMA" = "xyes"])
])dnl


# AC_LDAP_UTILS_LIBRARIES
# ______________________________________________________________________________
AC_DEFUN([AC_LDAP_UTILS_LIBRARIES],[dnl

   enableval=""
   AC_ARG_ENABLE(
      libraries,
      [AS_HELP_STRING([--disable-libraries], [disable libraries])],
      [ ELDAPLIBRARIES=$enableval ],
      [ ELDAPLIBRARIES=$enableval ]
   )

   if test "x${ELDAPLIBRARIES}" != "xno";then
      ELDAPLIBRARIES=yes
      LDAPUTILS_LIBRARIES=yes
      LDAPUTILS_LIBRARIES_ALT=no
   else
      LDAPUTILS_LIBRARIES=no
      LDAPUTILS_LIBRARIES_ALT=yes
   fi

])dnl


# AC_LDAP_UTILS_OIDSPECTOOL
# ______________________________________________________________________________
AC_DEFUN([AC_LDAP_UTILS_OIDSPECTOOL],[dnl

   # prerequists
   AC_REQUIRE([AC_LDAP_UTILS_LDAPSCHEMA])
   AC_REQUIRE([AC_LDAP_UTILS_LIBLDAPSCHEMA])

   LDAPUTILS_OIDSPECTOOL="no"
   if test "x${LDAPUTILS_LDAPSCHEMA}" == "xyes" ||
      test "x${LDAPUTILS_LIBLDAPSCHEMA}" == "xyes";then
      LDAPUTILS_OIDSPECTOOL="yes"
   fi

   AM_CONDITIONAL([LDAPUTILS_OIDSPECTOOL], [test "x$LDAPUTILS_OIDSPECTOOL" = "xyes"])
])dnl


# AC_LDAP_UTILS_UTILITIES
# ______________________________________________________________________________
AC_DEFUN([AC_LDAP_UTILS_UTILITIES],[dnl

   enableval=""
   AC_ARG_ENABLE(
      utilities,
      [AS_HELP_STRING([--disable-utilities], [disable utilities])],
      [ ELDAPUTILITIES=$enableval ],
      [ ELDAPUTILITIES=$enableval ]
   )

   if test "x${ELDAPUTILITIES}" != "xno";then
      ELDAPUTILITIES=yes
      LDAPUTILS_UTILITIES=yes
      LDAPUTILS_UTILITIES_ALT=no
   else
      LDAPUTILS_UTILITIES=no
      LDAPUTILS_UTILITIES_ALT=yes
   fi

])dnl


# end of M4 file
