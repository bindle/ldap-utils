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
/**
 *   @file lib/libldapschema/llexer.h  contains prototypes for lexer functions and variables
 */
#ifndef _LIB_LIBLDAPSCHEMA_LLEXER_H
#define _LIB_LIBLDAPSCHEMA_LLEXER_H 1


///////////////
//           //
//  Headers  //
//           //
///////////////
// MARK: - Headers

#include "libldapschema.h"


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
// MARK: - Definitions


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
// MARK: - Prototypes

int
ldapschema_definition_split(
         LDAPSchema *                  lsd,
         LDAPSchemaModel *             mod,
         const char *                  str,
         size_t                        strlen,
         char ***                      argvp );

int
ldapschema_definition_split_len(
         LDAPSchema *                  lsd,
         LDAPSchemaModel *             mod,
         const struct berval *         def,
         char ***                      argvp );

int
ldapschema_line_split(
         LDAPSchema *                  lsd,
         const char *                  str,
         char ***                      argvp );

int
ldapschema_objectclass_attribute(
         LDAPSchema *                  lsd,
         LDAPSchemaObjectclass *       objcls,
         LDAPSchemaAttributeType *     attr,
         int                           must,
         int                           inherited );

LDAPSchemaAttributeType *
ldapschema_parse_attributetype(
         LDAPSchema *                  lsd,
         const struct berval *         def );

int
ldapschema_parse_ext(
         LDAPSchema *                  lsd,
         LDAPSchemaModel *             model,
         const char *                  key,
         const char *                  valstr );

LDAPSchemaMatchingRule *
ldapschema_parse_matchingrule(
         LDAPSchema *                  lsd,
         const struct berval *         def );

LDAPSchemaObjectclass *
ldapschema_parse_objectclass(
         LDAPSchema *                  lsd,
         const struct berval *         def );

LDAPSchemaSyntax *
ldapschema_parse_syntax(
         LDAPSchema *                  lsd,
         const struct berval *         def );


#endif /* end of header file */
