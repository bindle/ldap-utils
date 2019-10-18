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
 *  @file src/ldaputils_ldap.c  contains shared functions and variables
 */
#ifndef _LIB_LIBLDAPSCHEMA_H
#define _LIB_LIBLDAPSCHEMA_H 1


///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Functions

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define LDAP_DEPRECATED 1
#include <ldap.h>
#include <ldapschema.h>


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#pragma mark - Definitions


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#pragma mark - Datatypes

/// LDAP schema descriptor state
struct ldap_schema
{
   int                  errcode;          ///< last error code
   int                  pad0;
   LDAPSchemaSyntax  ** syntaxes;         ///< array of syntaxes
   size_t               syntaxes_len;     /// length of syntaxes array
};


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

//-----------------//
// lexer functions //
//-----------------//

int
ldapschema_definition_split(
         LDAPSchema            * lsd,
         const struct berval   * def,
         char                *** argvp );


//------------------//
// memory functions //
//-------=----------//

void
ldapschema_syntax_free(
         LDAPSchemaSyntax      * syntax );

char **
ldapschema_value_add(
         char                 ** vals,
         const char            * val,
         int                   * countp );


#endif /* end of header file */
