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

#include <assert.h>

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
   int32_t                                errcode;          ///< last error code
   int32_t                                pad32;
   LDAPSchemaPointer                    * oids;             ///< array of all known oids
   size_t                                 oids_len;         ///< length of oids array
   LDAPSchemaSyntax                    ** syntaxes;         ///< array of syntaxes
   size_t                                 syntaxes_len;     ///< length of syntaxes array
   LDAPSchemaAttributeType             ** attrs;            ///< array of attributeTypes
   size_t                                 attrs_len;        ///< length of attributeTypes array
   LDAPSchemaSpec                      ** specs;            ///< sorted list of specifications
   size_t                                 specs_len;        ///< length of sorted list of specifications
};


/// LDAP schema extension
struct ldap_schema_extension
{
   char                                 * extension;
   char                                ** values;
   size_t                                 values_len;
};


/// LDAP schema base data model
struct ldap_schema_model
{
   size_t                                 size;             ///< size of data struct
   uint32_t                               type;             ///< LDAP schema data type
   uint32_t                               flags;
   char                                 * definition;       ///< defintion of object
   char                                 * oid;              ///< oid of object
   char                                 * desc;             ///< description of object;
   const LDAPSchemaSpec                 * spec;
   LDAPSchemaExtension                 ** extensions;
   size_t                                 extensions_len;
};


/// LDAP schema attributeType
struct ldap_schema_attributetype
{
   LDAPSchemaModel                        model;
   LDAPSchemaSyntax                     * syntax;
   uint64_t                               usage;
   size_t                                 names_len;
   size_t                                 allowed_by_len;
   size_t                                 required_by_len;
   uint64_t                               min_upper;
   char                                 * sup_name;
   char                                ** names;
   LDAPSchemaObjectclass               ** allowed_by;
   LDAPSchemaObjectclass               ** required_by;
};


/// LDAP schema objectclass
struct ldap_schema_objectclass
{
   LDAPSchemaModel                        model;
   size_t                                 names_len;
   size_t                                 must_len;
   size_t                                 may_len;
   size_t                                 all_must_len;
   size_t                                 all_may_len;
   LDAPSchemaObjectclass                * sup;
   char                                ** names;
   LDAPSchemaAttributeType             ** must;
   LDAPSchemaAttributeType             ** may;
   LDAPSchemaAttributeType             ** all_must;
   LDAPSchemaAttributeType             ** all_may;
};


union ldap_schema_pointer
{
   LDAPSchemaModel                      * model;
   LDAPSchemaSyntax                     * syntax;
   LDAPSchemaObjectclass                * objectclass;
   LDAPSchemaAttributeType              * attributetype;
   LDAPSchemaMatchingRule               * matchingrule;
};


/// LDAP schema syntax
struct ldap_schema_syntax
{
   LDAPSchemaModel                        model;
   regex_t                                re;
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
#pragma mark lexer functions

int
ldapschema_definition_split(
         LDAPSchema            * lsd,
         const char            * str,
         size_t                  strlen,
         char                *** argvp );

int
ldapschema_definition_split_len(
         LDAPSchema            * lsd,
         const struct berval   * def,
         char                *** argvp );

int
ldapschema_parse_ext(
         LDAPSchema            * lsd,
         LDAPSchemaModel       * model,
         const char            * key,
         const char            * valstr );


//------------------//
// memory functions //
//-------=----------//
#pragma mark memory functions

void
ldapschema_attributetype_free(
         LDAPSchemaAttributeType  * attr );

LDAPSchemaAttributeType *
ldapschema_attributetype_initialize(
         LDAPSchema            * lsd );

void
ldapschema_ext_free(
         LDAPSchemaExtension   * ext );

LDAPSchemaExtension *
ldapschema_ext_initialize(
         LDAPSchema            * lsd,
         const char            * name );

int
ldapschema_insert(
         LDAPSchema            * lsd,
         void                *** listp,
         size_t                * lenp,
         void                  * obj,
         int (*compar)(const void *, const void *) );

void
ldapschema_model_free(
         LDAPSchemaModel       * model );

void
ldapschema_object_free(
         LDAPSchemaModel       * model );

void
ldapschema_syntax_free(
         LDAPSchemaSyntax      * syntax );

void *
ldapschema_oid(
         LDAPSchema            * lsd,
         const char            * oid,
         size_t                  type );

LDAPSchemaSyntax *
ldapschema_syntax_initialize(
         LDAPSchema            * lsd );

char **
ldapschema_value_add(
         char                 ** vals,
         const char            * val,
         int                   * countp );


#endif /* end of header file */
