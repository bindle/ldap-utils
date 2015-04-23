/*
 *  LDAP Utilities
 *  Copyright (C) 2012 Bindle Binaries <syzdek@bindlebinaries.com>.
 *
 *  @BINDLE_BINARIES_BSD_LICENSE_START@
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are
 *  met:
 *
 *     1. Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *
 *     2. Redistributions in binary form must reproduce the above copyright
 *        notice, this list of conditions and the following disclaimer in the
 *        documentation and/or other materials provided with the distribution.
 *
 *     3. Neither the name of the copyright holder nor the names of its
 *        contributors may be used to endorse or promote products derived from
 *        this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 *  IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 *  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 *  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 *  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  @BINDLE_BINARIES_BSD_LICENSE_END@
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
