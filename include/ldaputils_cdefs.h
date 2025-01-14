/*
 *  LDAP Utilities
 *  Copyright (C) 2012, 2019 David M. Syzdek <david@syzdek.net>.
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
 *  include/ldap-utils.h - common includes and prototypes
 */
#ifndef __LDAPUTILS_CDEFS_H
#define __LDAPUTILS_CDEFS_H 1
#undef  __LDAPUTILS_PMARK
#ifndef __LDAPUTILS_H
#error "do not include ldaputils_cdefs.h directly, include libreotp.h."
#endif

///////////////
//           //
//  Headers  //
//           //
///////////////
// MARK: - Headers

#ifdef HAVE_CONFIG_H
#include <config.h>
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


//////////////
//          //
//  Macros  //
//          //
//////////////
// MARK: - Macros

// Exports function type
#undef LDAPUTILS_C_DECLS
#undef LDAPUTILS_BEGIN_C_DECLS
#undef LDAPUTILS_END_C_DECLS
#undef _LDAPUTILS_I
#undef _LDAPUTILS_F
#undef _LDAPUTILS_V
#if defined(__cplusplus) || defined(c_plusplus)
#   define _LDAPUTILS_I             extern "C" inline
#   define LDAPUTILS_C_DECLS        "C"             ///< exports as C functions
#   define LDAPUTILS_BEGIN_C_DECLS  extern "C" {    ///< exports as C functions
#   define LDAPUTILS_END_C_DECLS    }               ///< exports as C functions
#else
#   define _LDAPUTILS_I             inline
#   define LDAPUTILS_C_DECLS        /* empty */     ///< exports as C functions
#   define LDAPUTILS_BEGIN_C_DECLS  /* empty */     ///< exports as C functions
#   define LDAPUTILS_END_C_DECLS    /* empty */     ///< exports as C functions
#endif
#ifdef WIN32
#   ifdef _LIB_LIBLDAPUTILS_H
#      define _LDAPUTILS_F   extern LDAPUTILS_C_DECLS __declspec(dllexport)   ///< used for library calls
#      define _LDAPUTILS_V   extern LDAPUTILS_C_DECLS __declspec(dllexport)   ///< used for library calls
#   else
#      define _LDAPUTILS_F   extern LDAPUTILS_C_DECLS __declspec(dllimport)   ///< used for library calls
#      define _LDAPUTILS_V   extern LDAPUTILS_C_DECLS __declspec(dllimport)   ///< used for library calls
#   endif
#else
#   ifdef _LIB_LIBLDAPUTILS_H
#      define _LDAPUTILS_F   /* empty */                                      ///< used for library calls
#      define _LDAPUTILS_V   extern LDAPUTILS_C_DECLS                         ///< used for library calls
#   else
#      define _LDAPUTILS_F   extern LDAPUTILS_C_DECLS                         ///< used for library calls
#      define _LDAPUTILS_V   extern LDAPUTILS_C_DECLS                         ///< used for library calls
#   endif
#endif


#endif /* end of header */
