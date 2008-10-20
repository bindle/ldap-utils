/*
 *  LDAP Utilities
 *  Copyright (C) 2008 David M. Syzdek <david@syzdek.net>.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
/*
 *  include/ldap-utils.h - common includes and prototypes
 */
#ifndef _LDAP_UTILS_H
#define _LDAP_UTILS_H 1

///////////////
//           //
//  Headers  //
//           //
///////////////

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef WIN32
#include <windows.h>
#endif

#include <inttypes.h>
#include <ldap.h>


//////////////
//          //
//  Macros  //
//          //
//////////////

/*
 * The macro "PARAMS" is taken verbatim from section 7.1 of the
 * Libtool 1.5.14 manual.
 */
/* PARAMS is a macro used to wrap function prototypes, so that
   compilers that don't understand ANSI C prototypes still work,
   and ANSI C compilers can issue warnings about type mismatches. */
#undef PARAMS
#if defined (__STDC__) || defined (_AIX) \
        || (defined (__mips) && defined (_SYSTYPE_SVR4)) \
        || defined(WIN32) || defined (__cplusplus)
# define PARAMS(protos) protos
#else
# define PARAMS(protos) ()
#endif


///////////////////
//               //
//  i18l Support //
//               //
///////////////////

#ifdef HAVE_GETTEXT
#   include <gettext.h> 
#   include <libintl.h>
#   define _(String) gettext (String) 
#   define gettext_noop(String) String 
#   define N_(String) gettext_noop (String) 
#else
#   define _(String) (String) 
#   define N_(String) String 
#   define textdomain(Domain) 
#   define bindtextdomain(Package, Directory) 
#endif



///////////////////
//               //
//  Definitions  //
//               //
///////////////////

#ifndef PACKAGE_BUGREPORT
#define PACKAGE_BUGREPORT ""
#endif
#ifndef PACKAGE_COPYRIGHT
#define PACKAGE_COPYRIGHT "Copyright (C) 2008 David M. Syzdek."
#endif
#ifndef PACKAGE_NAME
#define PACKAGE_NAME "LDAP Utilities"
#endif
#ifndef PACKAGE_TARNAME
#define PACKAGE_TARNAME "ldap-utils"
#endif
#ifndef PACKAGE_VERSION
#define PACKAGE_VERSION ""
#endif


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////

typedef struct ldap_utils_entry LDAPUtilsEntry;
struct ldap_utils_entry
{
   char   * dn;
   char   * sortval;
   size_t   count;
   struct ldap_utils_attribute ** attributes;
};


typedef struct ldap_utils_attribute LDAPUtilsAttribute;
struct ldap_utils_attribute
{
   char           * name;
   struct berval ** vals;
};

#endif /* end of header */
