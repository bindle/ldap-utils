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

///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

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
#include <regex.h>
#include <ldap.h>


//////////////
//          //
//  Macros  //
//          //
//////////////
#pragma mark - Macros

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
#pragma mark - Definitions

// result codes
#define LDAPSCHEMA_SUCCESS                            0x00     ///< operation was successful
#define LDAPSCHEMA_SCHEMA_ERROR                       0x7001   ///< schema error
#define LDAPSCHEMA_DUPLICATE                          0x7002   ///< duplicate defintion
#define LDAPSCHEMA_UNKNOWN_FIELD                      0x7003   ///< unknown field
#define LDAPSCHEMA_NO_MEMORY                          (-10)    ///< an memory allocation failed

// model flags
#define LDAPSCHEMA_O_SINGLEVALUE                      0x0001   ///< attributeType: is single value
#define LDAPSCHEMA_O_OBSOLETE                         0x0002
#define LDAPSCHEMA_O_COLLECTIVE                       0x0004   ///< attributeType:
#define LDAPSCHEMA_O_NO_USER_MOD                      0x0008   ///< attributeType: is readonly
#define LDAPSCHEMA_O_OBJECTCLASS                      0x0010   ///< attributeType: is objectClass
#define LDAPSCHEMA_O_READABLE                         0x0020   ///< ldapSyntax: is human readable
#define LDAPSCHEMA_O_COMMON_ABNF                      0x0040   ///< ldapSyntax: uses common ABNF (RFC 4512, Section 1.2)
#define LDAPSCHEMA_O_SCHEMA_ABNF                      0x0080   ///< ldapSyntax: uses schema ABNF (RFC 4512, Section 4.1)
#define LDAPSCHEMA_O_DEPRECATED                       0x0100   ///< object deprecated or removed by RFC

// objectclass types
#define LDAPSCHEMA_STRUCTURAL                         0x0001
#define LDAPSCHEMA_ABSTRACT                           0x0002
#define LDAPSCHEMA_AUXILIARY                          0x0003

// attribute type usage
#define LDAPSCHEMA_USER_APP                           0x0001   ///< AttributeType usage User Applications
#define LDAPSCHEMA_DIRECTORY_OP                       0x0002   ///< AttributeType usage Directory Operation
#define LDAPSCHEMA_DISTRIBUTED_OP                     0x0003   ///< AttributeType usage Distributed Operation
#define LDAPSCHEMA_DSA_OP                             0x0004   ///< AttributeType usage DSA Operation

// LDAP schema data type
#define LDAPSCHEMA_TYPE_MASK                          0xFF000000
#define LDAPSCHEMA_SUBTYPE_MASK                       0x000000FF
#define LDAPSCHEMA_SYNTAX                             0x01
#define LDAPSCHEMA_MATCHINGRULE                       0x02
#define LDAPSCHEMA_MATCHINGRULES                      0x02
#define LDAPSCHEMA_ATTRIBUTETYPE                      0x03
#define LDAPSCHEMA_OBJECTCLASS                        0x04
#define LDAPSCHEMA_DITCONTENTRULE                     0x05
#define LDAPSCHEMA_DITSTRUCTURERULE                   0x06
#define LDAPSCHEMA_NAMEFORM                           0x07
#define LDAPSCHEMA_FEATURE                            0x41
#define LDAPSCHEMA_CONTROL                            0x42
#define LDAPSCHEMA_EXTENSION                          0x43
#define LDAPSCHEMA_UNSOLICITED                        0x44     ///< Unsolicited Notice
#define LDAPSCHEMA_ABNF                               0x45
#define LDAPSCHEMA_TYPE( val )                        (val & LDAPSCHEMA_TYPE_MASK )
#define LDAPSCHEMA_SUBTYPE( val )                     (val & LDAPSCHEMA_SUBTYPE_MASK )
#define LDAPSCHEMA_IS_TYPE( val, type )               ( LDAPSCHEMA_TYPE(val)    == type )
#define LDAPSCHEMA_IS_SUBTYPE( val, type )            ( LDAPSCHEMA_SUBTYPE(val) == type )

// specification types
#define LDAPSCHEMA_SPEC_RFC                           1
#define LDAPSCHEMA_SPEC_URL                           2

// specification classes
#define LDAPSCHEMA_CLASS_UNKNOWN                      0
#define LDAPSCHEMA_CLASS_ASCII                        1
#define LDAPSCHEMA_CLASS_UTF8                         2
#define LDAPSCHEMA_CLASS_INTEGER                      3
#define LDAPSCHEMA_CLASS_UNSIGNED                     4
#define LDAPSCHEMA_CLASS_BOOLEAN                      5
#define LDAPSCHEMA_CLASS_DATA                         6
#define LDAPSCHEMA_CLASS_IMAGE                        7
#define LDAPSCHEMA_CLASS_AUDIO                        8
#define LDAPSCHEMA_CLASS_UTF8_MULTILINE               9


// specification fields
#define LDAPSCHEMA_FLD_OID                            1
#define LDAPSCHEMA_FLD_NAME                           2
#define LDAPSCHEMA_FLD_DESC                           3
#define LDAPSCHEMA_FLD_DEF                            4
#define LDAPSCHEMA_FLD_SOURCE                         5
#define LDAPSCHEMA_FLD_ABNF                           6
#define LDAPSCHEMA_FLD_RE_POSIX                       7
#define LDAPSCHEMA_FLD_RE_PCRE                        8
#define LDAPSCHEMA_FLD_EXAMPLES                       9
#define LDAPSCHEMA_FLD_SPEC                           10
#define LDAPSCHEMA_FLD_SPEC_NAME                      11
#define LDAPSCHEMA_FLD_SPEC_SECTION                   12
#define LDAPSCHEMA_FLD_SPEC_SOURCE                    13
#define LDAPSCHEMA_FLD_SPEC_VENDOR                    14
#define LDAPSCHEMA_FLD_SPEC_TEXT                      15
#define LDAPSCHEMA_FLD_SPEC_TYPE                      16
#define LDAPSCHEMA_FLD_TYPE                           17
#define LDAPSCHEMA_FLD_SUBTYPE                        18
#define LDAPSCHEMA_FLD_CLASS                          19
#define LDAPSCHEMA_FLD_FLAGS                          20
#define LDAPSCHEMA_FLD_NOTES                          21
#define LDAPSCHEMA_FLD_USAGE                          22
#define LDAPSCHEMA_FLD_KIND                           23
#define LDAPSCHEMA_FLD_SUPERIOR                       24
#define LDAPSCHEMA_FLD_SYNTAX                         25


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#pragma mark - Datatypes

/// LDAP schema descriptor state
typedef struct ldap_schema LDAPSchema;

/// LDAP schema base data model
typedef struct ldap_schema_model LDAPSchemaModel;

/// LDAP schema syntax
typedef struct ldap_schema_syntax LDAPSchemaSyntax;

typedef struct ldap_schema_alias LDAPSchemaAlias;

typedef struct ldap_schema_objectclass LDAPSchemaObjectclass;

typedef union ldap_schema_pointer LDAPSchemaPointer;

typedef struct ldap_schema_attributetype LDAPSchemaAttributeType;

typedef struct ldap_schema_matchingrule LDAPSchemaMatchingRule;

typedef struct ldap_schema_extension LDAPSchemaExtension;

typedef struct ldapschema_spec LDAPSchemaSpec;

typedef struct ldapschema_cursor * LDAPSchemaCur;


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes
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

_LDAPSCHEMA_F char **
ldapschema_schema_errors(
         LDAPSchema            * lsd );


//------------------//
// format functions //
//------------------//
#pragma mark format functions

_LDAPSCHEMA_F int
ldapschema_fmt_definition(
         char * restrict         str,
         size_t                  size,
         const char * restrict   def,
         size_t                  width );


//-----------------//
// LDAP functions //
//-----------------//
#pragma mark LDAP functions

_LDAPSCHEMA_F int
ldapschema_fetch(
         LDAPSchema            * lsd,
         LDAP                  * ld );


//------------------//
// memory functions //
//------------------//
#pragma mark memory functions

_LDAPSCHEMA_F int
ldapschema_count_values(
         char ** vals );

_LDAPSCHEMA_F int
ldapschema_count_values_len(
         struct berval        ** vals );

_LDAPSCHEMA_F void
ldapschema_curfree(
         LDAPSchemaCur           cur );

_LDAPSCHEMA_F void
ldapschema_free(
         LDAPSchema            * lsd );

_LDAPSCHEMA_F int
ldapschema_initialize(
         LDAPSchema           ** lsdp );

_LDAPSCHEMA_F void
ldapschema_memfree(
         void                  * p );

_LDAPSCHEMA_F void
ldapschema_memvfree(
         void                 ** v );

_LDAPSCHEMA_F void
ldapschema_value_free(
         char                 ** vals );

_LDAPSCHEMA_F void
ldapschema_value_free_len(
         struct berval        ** vals );


//-----------------------------//
// OID Specification functions //
//-----------------------------//
#pragma mark OID Specification functions

_LDAPSCHEMA_F
const LDAPSchemaSpec *
ldapschema_spec_abnf(
         int                     abnf_type );

_LDAPSCHEMA_F int
ldapschema_spec_field(
         const LDAPSchemaSpec  * spec,
         int                     field,
         void                  * outvalue );

_LDAPSCHEMA_F const LDAPSchemaSpec * const *
ldapschema_spec_list(
         size_t                * lenp );

_LDAPSCHEMA_F const LDAPSchemaSpec *
ldapschema_spec_search(
         const char            * oid);


//------------------//
// output functions //
//------------------//
#pragma mark output functions

_LDAPSCHEMA_F void
ldapschema_print(
         LDAPSchema            * lsd,
         LDAPSchemaModel       * model );

_LDAPSCHEMA_F void
ldapschema_printall(
         LDAPSchema            * lsd,
         int                     type );


//-----------------//
// query functions //
//-----------------//
#pragma mark query functions

// ldapchema_count_XXXX()
_LDAPSCHEMA_F size_t
ldapschema_count_attributetypes(
         LDAPSchema            * lsd );

_LDAPSCHEMA_F size_t
ldapschema_count_ldapsyntaxes(
         LDAPSchema            * lsd );

_LDAPSCHEMA_F size_t
ldapschema_count_matchingrules(
         LDAPSchema            * lsd );

_LDAPSCHEMA_F size_t
ldapschema_count_objectclasses(
         LDAPSchema            * lsd );

// ldapschema_find_XXXX()
_LDAPSCHEMA_F LDAPSchemaAttributeType *
ldapschema_find_attributetype(
         LDAPSchema            * lsd,
         const char            * name );

_LDAPSCHEMA_F LDAPSchemaSyntax *
ldapschema_find_ldapsyntax(
         LDAPSchema            * lsd,
         const char            * name );

_LDAPSCHEMA_F LDAPSchemaMatchingRule *
ldapschema_find_matchingrule(
         LDAPSchema            * lsd,
         const char            * name );

_LDAPSCHEMA_F LDAPSchemaObjectclass *
ldapschema_find_objectclass(
         LDAPSchema            * lsd,
         const char            * name );

// ldapchema_first_XXXX()
_LDAPSCHEMA_F const LDAPSchemaAttributeType *
ldapschema_first_attributetype(
         LDAPSchema            * lsd,
         LDAPSchemaCur         * curp);

_LDAPSCHEMA_F const LDAPSchemaSyntax *
ldapschema_first_ldapsyntax(
         LDAPSchema            * lsd,
         LDAPSchemaCur         * curp);

_LDAPSCHEMA_F const LDAPSchemaMatchingRule *
ldapschema_first_matchingrule(
         LDAPSchema            * lsd,
         LDAPSchemaCur         * curp);

_LDAPSCHEMA_F const LDAPSchemaObjectclass *
ldapschema_first_objectclass(
         LDAPSchema            * lsd,
         LDAPSchemaCur         * curp);

// ldapchema_get_info_XXXX()
_LDAPSCHEMA_F int
ldapschema_get_info_attributetype(
         LDAPSchema            * lsd,
         const LDAPSchemaAttributeType * attr,
         int                     field,
         void                  * outvalue );

_LDAPSCHEMA_F int
ldapschema_get_info_ldapsyntax(
         LDAPSchema            * lsd,
         const LDAPSchemaSyntax * syntax,
         int                     field,
         void                  * outvalue );

_LDAPSCHEMA_F int
ldapschema_get_info_matchingrule(
         LDAPSchema            * lsd,
         const LDAPSchemaMatchingRule * matchingrule,
         int                     field,
         void                  * outvalue );

_LDAPSCHEMA_F int
ldapschema_get_info_model(
         LDAPSchema            * lsd,
         const LDAPSchemaModel * mod,
         int                     field,
         void                  * outvalue );

_LDAPSCHEMA_F int
ldapschema_get_info_objectclass(
         LDAPSchema            * lsd,
         const LDAPSchemaObjectclass * objcls,
         int                     field,
         void                  * outvalue );

// ldapchema_model_XXXX()
_LDAPSCHEMA_F const LDAPSchemaModel *
ldapschema_model_attributetype(
         const LDAPSchemaAttributeType * attr );

_LDAPSCHEMA_F const LDAPSchemaModel *
ldapschema_model_ldapsyntax(
         const LDAPSchemaSyntax * syntax );

_LDAPSCHEMA_F const LDAPSchemaModel *
ldapschema_model_matchingrule(
         const LDAPSchemaMatchingRule * matchingrule );

_LDAPSCHEMA_F const LDAPSchemaModel *
ldapschema_model_objectclass(
         const LDAPSchemaObjectclass * objcls );

// ldapschema_next_XXXX()
_LDAPSCHEMA_F const LDAPSchemaAttributeType *
ldapschema_next_attributetype(
         LDAPSchema            * lsd,
         LDAPSchemaCur           cur);

_LDAPSCHEMA_F const LDAPSchemaSyntax *
ldapschema_next_ldapsyntax(
         LDAPSchema            * lsd,
         LDAPSchemaCur           cur);

_LDAPSCHEMA_F const LDAPSchemaMatchingRule *
ldapschema_next_matchingrule(
         LDAPSchema            * lsd,
         LDAPSchemaCur           cur);

_LDAPSCHEMA_F const LDAPSchemaObjectclass *
ldapschema_next_objectclass(
         LDAPSchema            * lsd,
         LDAPSchemaCur           cur);


//---------------------------//
// sort comparison functions //
//---------------------------//
#pragma mark sort comparison functions

#ifndef _LIB_LIBLDAPSCHEMA_H

_LDAPSCHEMA_F int
ldapschema_compar_aliases(
         const void * ap,
         const void * bp );


_LDAPSCHEMA_F int
ldapschema_compar_attributetypes(
         const void * ap,
         const void * bp );


_LDAPSCHEMA_F int
ldapschema_compar_extensions(
         const void * ap,
         const void * bp );


_LDAPSCHEMA_F int
ldapschema_compar_models(
         const void * ap,
         const void * bp );


_LDAPSCHEMA_F int
ldapschema_compar_objectclasses(
         const void * ap,
         const void * bp );


_LDAPSCHEMA_F int
ldapschema_compar_spec(
         const void * ap,
         const void * bp );


_LDAPSCHEMA_F int
ldapschema_compar_syntaxes(
         const void * ap,
         const void * bp );


_LDAPSCHEMA_F int
ldapschema_compar_values(
         const void * ap,
         const void * bp );

#endif

LDAPSCHEMA_END_C_DECLS
#endif /* end of header */
