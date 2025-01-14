
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
 *  @file lib/libldapschema/lmemory.h  contains prototypes for memory functions and variables
 */
#ifndef _LIB_LIBLDAPSCHEMA_LMEMORY_H
#define _LIB_LIBLDAPSCHEMA_LMEMORY_H 1


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
ldapschema_append(
         LDAPSchema *                  lsd,
         void ***                      listp,
         size_t *                      lenp,
         void *                        obj );

void
ldapschema_attributetype_free(
         LDAPSchemaAttributeType *     attr );

LDAPSchemaCur
ldapschema_curalloc(
         LDAPSchema *                  lsd );

void
ldapschema_ext_free(
         LDAPSchemaExtension *         ext );

LDAPSchemaExtension *
ldapschema_ext_initialize(
         LDAPSchema *                  lsd,
         const char *                  name );

int
ldapschema_insert(
         LDAPSchema *                  lsd,
         void ***                      listp,
         size_t *                      lenp,
         void *                        obj,
         int (*compar)(const void *, const void *) );

void
ldapschema_matchingrule_free(
         LDAPSchemaMatchingRule *      rule);

void
ldapschema_model_free(
         LDAPSchemaModel *             model );

LDAPSchemaModel *
ldapschema_model_initialize(
         LDAPSchema *                  lsd,
         const char *                  oid,
         uint32_t                      type,
         const struct berval *         def);

int
ldapschema_model_register(
         LDAPSchema *                  lsd,
         LDAPSchemaModel *             mod );

void
ldapschema_object_free(
         LDAPSchemaModel *             model );

void
ldapschema_objectclass_free(
         LDAPSchemaObjectclass *       objectclass );

void *
ldapschema_oid(
         LDAPSchema *                  lsd,
         const char *                  oid,
         uint32_t                      type );

char *
ldapschema_stradd(
         char **                       s1,
         const char *                  s2 );

void
ldapschema_syntax_free(
         LDAPSchemaSyntax *            syntax );

char **
ldapschema_value_dup(
         char **                       vals );

char **
ldapschema_value_add(
         char **                       vals,
         const char *                  val,
         int *                         countp );

#endif /* end of header file */
