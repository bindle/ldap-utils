
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
 *   @file lib/libldapschema/lsort.h  contains prototypes for sort functions and variables
 */
#ifndef _LIB_LIBLDAPSCHEMA_LSORT_H
#define _LIB_LIBLDAPSCHEMA_LSORT_H 1


///////////////
//           //
//  Headers  //
//           //
///////////////
// MARK: - Headers

#include "libldapschema.h"
#include "lspec.h"


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


////////////////////////
//                    //
//  Inline Functions  //
//                    //
////////////////////////
// MARK: - Inline Functions

/// compares the alias field of `ap` and `bp`
/// @param[in]    ap          reference to LDAP model
/// @param[in]    bp          reference to LDAP model
///
/// @return    ldapschema_alias_cmp() returns an integer greater than, equal
///            to, or less than 0, according as the alias of `ap` is
///            lexicographically greater than, equal to, or less than the alias
///            of `bp`.
/// @see       ldapschema_free, ldapschema_initialize, ldapschema_errno
_LDAPSCHEMA_I int
ldapschema_compar_aliases(
         const void *                  ap,
         const void *                  bp )
{
   const LDAPSchemaAlias * a = *(const LDAPSchemaAlias * const *)ap;
   const LDAPSchemaAlias * b = *(const LDAPSchemaAlias * const *)bp;

   if ( (!(a)) && (!(b)) )
      return(0);
   if (!(a))
      return(1);
   if (!(b))
      return(-1);

   if ( (!(a->alias)) && (!(b->alias)) )
      return(0);
   if (!(a->alias))
      return(1);
   if (!(b->alias))
      return(-1);

   return(strcasecmp(a->alias, b->alias));
}


/// compares the LDAP attributeType name and OIDs of `ap` and `bp`
/// @param[in]    ap          reference to LDAP syntax
/// @param[in]    bp          reference to LDAP syntax
///
/// @return    ldapschema_syntax_cmp() returns an integer greater than, equal
///            to, or less than 0, according as the description of `s1` is
///            lexicographically greater than, equal to, or less than the
///            description of `s2`.
/// @see       ldapschema_free, ldapschema_initialize, ldapschema_errno
_LDAPSCHEMA_I int
ldapschema_compar_attributetypes(
         const void *                  ap,
         const void *                  bp )
{
   const LDAPSchemaAttributeType * a = *(const LDAPSchemaAttributeType * const *)ap;
   const LDAPSchemaAttributeType * b = *(const LDAPSchemaAttributeType * const *)bp;
   const char                    * as;
   const char                    * bs;

   if ( (!(a)) && (!(b)) )
      return(0);
   if (!(a))
      return(1);
   if (!(b))
      return(-1);

   as = ((a->names)) ? a->names[0] : a->model.oid;
   bs = ((b->names)) ? b->names[0] : b->model.oid;


   if ( (!(as)) && (!(bs)) )
      return(0);
   if (!(as))
      return(1);
   if (!(bs))
      return(-1);

   return(strcasecmp(as, bs));
}


/// compares the OIDs of `m1` and `m2`
/// @param[in]    ap          reference to LDAP model
/// @param[in]    bp          reference to LDAP model
///
/// @return    ldapschema_model_cmp() returns an integer greater than, equal
///            to, or less than 0, according as the OID of `m1` is
///            lexicographically greater than, equal to, or less than the OID
///            of `m2`.
/// @see       ldapschema_free, ldapschema_initialize, ldapschema_errno
_LDAPSCHEMA_I int
ldapschema_compar_extensions(
         const void *                  ap,
         const void *                  bp )
{
   const LDAPSchemaExtension * a = *(const LDAPSchemaExtension * const *)ap;
   const LDAPSchemaExtension * b = *(const LDAPSchemaExtension * const *)bp;

   if ( (!(a)) && (!(b)) )
      return(0);
   if (!(a))
      return(1);
   if (!(b))
      return(-1);

   if ( (!(a->extension)) && (!(b->extension)) )
      return(0);
   if (!(a->extension))
      return(1);
   if (!(b->extension))
      return(-1);

   return(strcasecmp(a->extension, b->extension));
}


/// compares the OIDs of `m1` and `m2`
/// @param[in]    ap          reference to LDAP model
/// @param[in]    bp          reference to LDAP model
///
/// @return    ldapschema_model_cmp() returns an integer greater than, equal
///            to, or less than 0, according as the OID of `m1` is
///            lexicographically greater than, equal to, or less than the OID
///            of `m2`.
/// @see       ldapschema_free, ldapschema_initialize, ldapschema_errno
_LDAPSCHEMA_I int
ldapschema_compar_models(
         const void *                  ap,
         const void *                  bp )
{
   const LDAPSchemaModel * a = *(const LDAPSchemaModel * const *)ap;
   const LDAPSchemaModel * b = *(const LDAPSchemaModel * const *)bp;

   if ( (!(a)) && (!(b)) )
      return(0);
   if (!(a))
      return(1);
   if (!(b))
      return(-1);

   if ( (!(a->oid)) && (!(b->oid)) )
      return(0);
   if (!(a->oid))
      return(1);
   if (!(b->oid))
      return(-1);

   return(strcasecmp(a->oid, b->oid));
}


/// compares the LDAP attributeType name and OIDs of `ap` and `bp`
/// @param[in]    ap          reference to LDAP syntax
/// @param[in]    bp          reference to LDAP syntax
///
/// @return    ldapschema_syntax_cmp() returns an integer greater than, equal
///            to, or less than 0, according as the description of `s1` is
///            lexicographically greater than, equal to, or less than the
///            description of `s2`.
/// @see       ldapschema_free, ldapschema_initialize, ldapschema_errno
_LDAPSCHEMA_I int
ldapschema_compar_objectclasses(
         const void *                  ap,
         const void *                  bp )
{
   const LDAPSchemaObjectclass * a = *(const LDAPSchemaObjectclass * const *)ap;
   const LDAPSchemaObjectclass * b = *(const LDAPSchemaObjectclass * const *)bp;
   const char *                  as;
   const char *                  bs;

   if ( (!(a)) && (!(b)) )
      return(0);
   if (!(a))
      return(1);
   if (!(b))
      return(-1);

   as = ((a->names)) ? a->names[0] : a->model.oid;
   bs = ((b->names)) ? b->names[0] : b->model.oid;


   if ( (!(as)) && (!(bs)) )
      return(0);
   if (!(as))
      return(1);
   if (!(bs))
      return(-1);

   return(strcasecmp(as, bs));
}


/// compares the LDAP syntax descriptions of `s1` and `s2`
/// @param[in]    ap          reference to LDAP syntax
/// @param[in]    bp          reference to LDAP syntax
///
/// @return    ldapschema_syntax_cmp() returns an integer greater than, equal
///            to, or less than 0, according as the description of `s1` is
///            lexicographically greater than, equal to, or less than the
///            description of `s2`.
/// @see       ldapschema_free, ldapschema_initialize, ldapschema_errno
_LDAPSCHEMA_I int
ldapschema_compar_spec(
         const void *                  ap,
         const void *                  bp )
{
   const LDAPSchemaSpec * a = *(const LDAPSchemaSpec * const *)ap;
   const LDAPSchemaSpec * b = *(const LDAPSchemaSpec * const *)bp;

   if ( (!(a)) && (!(b)) )
      return(0);
   if (!(a))
      return(1);
   if (!(b))
      return(-1);

   if ( (!(a->oid)) && (!(b->oid)) )
      return(0);
   if (!(a->oid))
      return(1);
   if (!(b->oid))
      return(-1);

   return(strcasecmp(a->oid, b->oid));
}


/// compares the LDAP syntax descriptions of `s1` and `s2`
/// @param[in]    ap          reference to LDAP syntax
/// @param[in]    bp          reference to LDAP syntax
///
/// @return    ldapschema_syntax_cmp() returns an integer greater than, equal
///            to, or less than 0, according as the description of `s1` is
///            lexicographically greater than, equal to, or less than the
///            description of `s2`.
/// @see       ldapschema_free, ldapschema_initialize, ldapschema_errno
_LDAPSCHEMA_I int
ldapschema_compar_syntaxes(
         const void *                  ap,
         const void *                  bp )
{
   const LDAPSchemaSyntax * a = *(const LDAPSchemaSyntax * const *)ap;
   const LDAPSchemaSyntax * b = *(const LDAPSchemaSyntax * const *)bp;

   if ( (!(a)) && (!(b)) )
      return(0);
   if (!(a))
      return(1);
   if (!(b))
      return(-1);

   if ( (!(a->model.desc)) && (!(b->model.desc)) )
      return(0);
   if (!(a->model.desc))
      return(1);
   if (!(b->model.desc))
      return(-1);

   return(strcasecmp(a->model.desc, b->model.desc));
}


/// compares two strings `ap` and `bp`
/// @param[in]    ap          reference to string
/// @param[in]    bp          reference to string
///
/// @return    ldapschema_alias_cmp() returns an integer greater than, equal
///            to, or less than 0, according as the alias of `ap` is
///            lexicographically greater than, equal to, or less than the alias
///            of `bp`.
/// @see       ldapschema_free, ldapschema_initialize, ldapschema_errno
_LDAPSCHEMA_I int
ldapschema_compar_values(
         const void *                  ap,
         const void *                  bp )
{
   const char * a = *(const char * const *)ap;
   const char * b = *(const char * const *)bp;

   if ( (!(a)) && (!(b)) )
      return(0);
   if (!(a))
      return(1);
   if (!(b))
      return(-1);

   return(strcasecmp(a, b));
}

#endif /* end of header file */
