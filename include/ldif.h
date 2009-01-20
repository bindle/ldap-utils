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
/** 
 *  @file include/ldif.h - prototypes and datatypes for libldif.la
 */
#ifndef _LDAP_UTILS_LDIF_H
#define _LDAP_UTILS_LDIF_H 1

//////////////
//          //
//  Macros  //
//          //
//////////////

/*
 * The macros "BEGIN_C_DECLS" and "END_C_DECLS" are taken verbatim
 * from section 7.1 of the Libtool 1.5.14 manual.
 */
/* BEGIN_C_DECLS should be used at the beginning of your declarations,
   so that C++ compilers don't mangle their names. Use END_C_DECLS at
   the end of C declarations. */
#undef BEGIN_C_DECLS
#undef END_C_DECLS
#if defined(__cplusplus) || defined(c_plusplus)
#define BEGIN_C_DECLS  extern "C" {    ///< exports as C functions
#define END_C_DECLS    }               ///< exports as C functions
#else
#define BEGIN_C_DECLS  /* empty */     ///< exports as C functions
#define END_C_DECLS    /* empty */     ///< exports as C functions
#endif


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
# define PARAMS(protos) protos   ///< wraps function arguments in order to support ANSI C
#else
# define PARAMS(protos) ()       ///< wraps function arguments in order to support ANSI C
#endif


/*
 * The following macro is taken verbatim from section 5.40 of the GCC
 * 4.0.2 manual.
 */
#if __STDC_VERSION__ < 199901L
# if __GNUC__ >= 2
# define __func__ __FUNCTION__
# else
# define __func__ "<unknown>"
# endif
#endif


// Exports function type
#ifdef WIN32
#   ifdef LDIF_LIBS_DYNAMIC
#      define LDIF_F(type)   extern __declspec(dllexport) type   ///< used for library calls
#      define LDIF_V(type)   extern __declspec(dllexport) type   ///< used for library calls
#   else
#      define LDIF_F(type)   extern __declspec(dllimport) type   ///< used for library calls
#      define LDIF_V(type)   extern __declspec(dllimport) type   ///< used for library calls
#   endif
#else
#   ifdef LDIF_LIBS_DYNAMIC
#      define LDIF_F(type)   type                                ///< used for library calls
#      define LDIF_V(type)   type                                ///< used for library calls
#   else
#      define LDIF_F(type)   extern type                         ///< used for library calls
#      define LDIF_V(type)   extern type                         ///< used for library calls
#   endif
#endif


///////////////
//           //
//  Headers  //
//           //
///////////////

#include <ldap.h>


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////

typedef struct ldif_data           LDIF;
typedef struct ldif_entry_data     LDIFEntry;
typedef struct ldif_attribute_data LDIFAttribute;


///////////////
//           //
//  Structs  //
//           //
///////////////

struct ldif_entry_data
{
   int              changetype;
   unsigned         attribute_count;
   unsigned         dn_node_count;
   unsigned         child_count;
   char           * dn;
   char          ** dn_nodes;
   LDIFAttribute  * attributes;
   LDIFEntry      * parent;
   LDIFEntry     ** children;
};


struct ldif_attribute_data
{
   int              changetype;
   int              vals_count;
   char           * name;
   struct berval ** vals;
};


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
BEGIN_C_DECLS

// returns package version
LDIF_F(const char *) ldif_package_version PARAMS((void));


END_C_DECLS
#endif /* end of header */
