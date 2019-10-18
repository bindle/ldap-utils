/*
 *  LDAP Utilities
 *  Copyright (C) 2019 David M. Syzdek <david@syzdek.net>.
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
 */
/*
 *  include/ldapschema.h - common includes and prototypes
 */
#ifndef __LDAPSCHEMA_H
#define __LDAPSCHEMA_H 1
#undef  __LDAPSCHEMA_PMARK

///////////////
//           //
//  Headers  //
//           //
///////////////
#ifdef __LDAPSCHEMA_PMARK
#pragma mark - Headers
#endif

#ifdef WIN32
#include <windows.h>
#endif

#ifdef __APPLE__
#  include "TargetConditionals.h"
#  ifdef TARGET_OS_MAC
#     include <libkern/OSAtomic.h>
#  endif
#endif

#include <inttypes.h>


//////////////
//          //
//  Macros  //
//          //
//////////////
#ifdef __LDAPSCHEMA_PMARK
#pragma mark - Macros
#endif

// Exports function type
#undef LDAPSCHEMA_C_DECLS
#undef LDAPSCHEMA_BEGIN_C_DECLS
#undef LDAPSCHEMA_END_C_DECLS
#undef _LDAPSCHEMA_I
#undef _LDAPSCHEMA_F
#undef _LDAPSCHEMA_V
#if defined(__cplusplus) || defined(c_plusplus)
#   define _LDAPSCHEMA_I             extern "C" inline
#   define LDAPSCHEMA_C_DECLS        "C"             ///< exports as C functions
#   define LDAPSCHEMA_BEGIN_C_DECLS  extern "C" {    ///< exports as C functions
#   define LDAPSCHEMA_END_C_DECLS    }               ///< exports as C functions
#else
#   define _LDAPSCHEMA_I             inline
#   define LDAPSCHEMA_C_DECLS        /* empty */     ///< exports as C functions
#   define LDAPSCHEMA_BEGIN_C_DECLS  /* empty */     ///< exports as C functions
#   define LDAPSCHEMA_END_C_DECLS    /* empty */     ///< exports as C functions
#endif
#ifdef WIN32
#   ifdef _LIB_LIBLDAPSCHEMA_H
#      define _LDAPSCHEMA_F   extern LDAPSCHEMA_C_DECLS __declspec(dllexport)   ///< used for library calls
#      define _LDAPSCHEMA_V   extern LDAPSCHEMA_C_DECLS __declspec(dllexport)   ///< used for library calls
#   else
#      define _LDAPSCHEMA_F   extern LDAPSCHEMA_C_DECLS __declspec(dllimport)   ///< used for library calls
#      define _LDAPSCHEMA_V   extern LDAPSCHEMA_C_DECLS __declspec(dllimport)   ///< used for library calls
#   endif
#else
#   ifdef _LIB_LIBLDAPSCHEMA_H
#      define _LDAPSCHEMA_F   /* empty */                                      ///< used for library calls
#      define _LDAPSCHEMA_V   extern LDAPSCHEMA_C_DECLS                         ///< used for library calls
#   else
#      define _LDAPSCHEMA_F   extern LDAPSCHEMA_C_DECLS                         ///< used for library calls
#      define _LDAPSCHEMA_V   extern LDAPSCHEMA_C_DECLS                         ///< used for library calls
#   endif
#endif


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#ifdef __LDAPSCHEMA_PMARK
#pragma mark - Definitions
#endif

// result codes
#define LDAPSCHEMA_SUCCESS                            0x00     ///< operation was successful
#define LDAPSCHEMA_NO_MEMORY                          (-10)    ///< an memory allocation failed


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#ifdef __LDAPSCHEMA_PMARK
#pragma mark - Datatypes
#endif

/// LDAP schema descriptor state
typedef struct ldap_schema LDAPSchema;


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#ifdef __LDAPSCHEMA_PMARK
#pragma mark - Prototypes
#endif
LDAPSCHEMA_BEGIN_C_DECLS

//-----------------//
// error functions //
//-----------------//
#pragma mark error functions

_LDAPSCHEMA_F const char *
ldapschema_err2string(
         int                     err );

_LDAPSCHEMA_F int
ldapschema_errno(
         LDAPSchema            * lsd );


//------------------//
// memory functions //
//-------=----------//
#pragma mark memory functions

_LDAPSCHEMA_F int
ldap_count_values(
         char ** vals );

_LDAPSCHEMA_F int
ldap_count_values_len(
         struct berval        ** vals );

_LDAPSCHEMA_F void
ldapschema_free(
         LDAPSchema            * lsd );

_LDAPSCHEMA_F int
ldapschema_initialize(
         LDAPSchema           ** lsdp );

_LDAPSCHEMA_F void
ldapschema_value_free(
         char                 ** vals );

_LDAPSCHEMA_F void
ldapschema_value_free_len(
         struct berval        ** vals );


LDAPSCHEMA_END_C_DECLS
#endif /* end of header */
