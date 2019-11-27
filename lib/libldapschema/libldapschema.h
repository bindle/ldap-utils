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
   size_t                                 objerrs_len;      ///< number of objects with errors
   LDAPSchemaPointer *                    objerrs;          ///< objects with errors
   LDAPSchemaPointer *                    dups;             ///< array of duplicate oids
   size_t                                 dups_len;         ///< length of duplicate array
   LDAPSchemaPointer *                    oids;             ///< array of all known oids
   size_t                                 oids_len;         ///< length of oids array
   LDAPSchemaAlias **                     syntaxes;         ///< array of syntaxes
   size_t                                 syntaxes_len;     ///< length of syntaxes array
   LDAPSchemaAlias **                     attrs;            ///< array of attributeTypes
   size_t                                 attrs_len;        ///< length of attributeTypes array
   LDAPSchemaAlias **                     mtchngrls;        ///< array of objectClasses
   size_t                                 mtchngrls_len;    ///< length of objectClasses array
   LDAPSchemaAlias **                     objclses;         ///< array of objectClasses
   size_t                                 objclses_len;     ///< length of objectClasses array
   char **                                schema_errs;      ///< list of schema errors discovered
};


/// tracks progress of queries
struct ldapschema_cursor
{
   size_t                                 cursor;
};


/// LDAP schema extension
struct ldap_schema_extension
{
   char *                                 extension;
   char **                                values;
   size_t                                 values_len;
};


/// LDAP schema base data model
struct ldap_schema_model
{
   size_t                                 size;             ///< size of data struct
   uint32_t                               type;             ///< LDAP schema data type
   uint32_t                               flags;
   char  *                                definition;       ///< defintion of object
   char  *                                oid;              ///< oid of object
   char  *                                desc;             ///< description of object;
   const LDAPSchemaSpec *                 spec;
   LDAPSchemaExtension  **                extensions;
   size_t                                 extensions_len;
   char **                                errors;
};


/// LDAP schema object alias
struct ldap_schema_alias
{
   const char *                           alias;
   union
   {
      LDAPSchemaModel *                   model;
      LDAPSchemaObjectclass *             objectclass;
      LDAPSchemaAttributeType *           attributetype;
      LDAPSchemaMatchingRule *            matchingrule;
      LDAPSchemaSyntax *                  syntax;
   };
};


/// LDAP schema attributeType
struct ldap_schema_attributetype
{
   LDAPSchemaModel                        model;
   LDAPSchemaSyntax *                     syntax;
   uint64_t                               usage;
   size_t                                 names_len;
   size_t                                 allowed_by_len;
   size_t                                 required_by_len;
   size_t                                 min_upper;
   LDAPSchemaAttributeType *              sup;
   char *                                 sup_name;
   LDAPSchemaMatchingRule *               equality;
   LDAPSchemaMatchingRule *               ordering;
   LDAPSchemaMatchingRule *               substr;
   char **                                names;
   LDAPSchemaObjectclass **               allowed_by;
   LDAPSchemaObjectclass **               required_by;
};


/// LDAP schema objectclass
struct ldap_schema_objectclass
{
   LDAPSchemaModel                        model;
   uint64_t                               kind;
   size_t                                 names_len;
   size_t                                 must_len;
   size_t                                 may_len;
   size_t                                 inherit_must_len;
   size_t                                 inherit_may_len;
   char *                                 sup_name;
   LDAPSchemaObjectclass *                sup;
   char **                                names;
   LDAPSchemaAttributeType **             must;
   LDAPSchemaAttributeType **             may;
   LDAPSchemaAttributeType **             inherit_must;
   LDAPSchemaAttributeType **             inherit_may;
};


union ldap_schema_pointer
{
   LDAPSchemaModel *                      model;
   LDAPSchemaSyntax *                     syntax;
   LDAPSchemaObjectclass *                objectclass;
   LDAPSchemaAttributeType *              attributetype;
   LDAPSchemaMatchingRule *               matchingrule;
};


/// LDAP schema syntax
struct ldap_schema_syntax
{
   LDAPSchemaModel                        model;
   size_t                                 data_class;
   regex_t                                re;
};


struct ldap_schema_matchingrule
{
   LDAPSchemaModel                        model;
   LDAPSchemaSyntax *                     syntax;
   LDAPSchemaAttributeType **             used_by;
   size_t                                 used_by_len;
   char **                                names;
   size_t                                 names_len;
};


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

//------------------//
// memory functions //
//-------=----------//
#pragma mark memory functions


#endif /* end of header file */
