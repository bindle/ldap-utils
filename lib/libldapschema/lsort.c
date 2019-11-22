
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
/**
 *   @file src/ldapschema/llexer.c  contains error functions and variables
 */
#define _LIB_LIBLDAPSCHEMA_LSORT_C 1
#include "lsort.h"

///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

#include <string.h>
#include <strings.h>


////////////////////////
//                    //
//  Inline Functions  //
//                    //
////////////////////////
#pragma mark - Inline Functions

extern inline int
ldapschema_alias_cmp(
         const void * ap,
         const void * bp );


extern inline int
ldapschema_extension_cmp(
         const void * ap,
         const void * bp );


extern inline int
ldapschema_model_cmp(
         const void * ap,
         const void * bp );


extern inline int
ldapschema_syntax_cmp(
         const void * ap,
         const void * bp );


extern inline int
ldapschema_value_cmp(
         const void * ap,
         const void * bp );


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions


/* end of source file */
