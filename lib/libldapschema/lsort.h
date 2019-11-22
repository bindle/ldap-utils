
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
 *   @file src/ldapschema/llexer.h  contains error functions and variables
 */
#ifndef _LIB_LIBLDAPSCHEMA_LSORT_H
#define _LIB_LIBLDAPSCHEMA_LSORT_H 1


///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

#include "libldapschema.h"


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#pragma mark - Definitions


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes


////////////////////////
//                    //
//  Inline Functions  //
//                    //
////////////////////////
#pragma mark - Inline Functions

/// compares the OIDs of `m1` and `m2`
/// @param[in]    ap          reference to LDAP model
/// @param[in]    bp          reference to LDAP model
///
/// @return    ldapschema_model_cmp() returns an integer greater than, equal
///            to, or less than 0, according as the OID of `m1` is
///            lexicographically greater than, equal to, or less than the OID
///            of `m2`.
/// @see       ldapschema_free, ldapschema_initialize, ldapschema_errno
_LDAPSCHEMA_I int ldapschema_extension_cmp( const void * ap, const void * bp )
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
_LDAPSCHEMA_I int ldapschema_model_cmp( const void * ap, const void * bp )
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


/// compares the LDAP syntax descriptions of `s1` and `s2`
/// @param[in]    ap          reference to LDAP syntax
/// @param[in]    bp          reference to LDAP syntax
///
/// @return    ldapschema_syntax_cmp() returns an integer greater than, equal
///            to, or less than 0, according as the description of `s1` is
///            lexicographically greater than, equal to, or less than the
///            description of `s2`.
/// @see       ldapschema_free, ldapschema_initialize, ldapschema_errno
_LDAPSCHEMA_I int ldapschema_syntax_cmp( const void * ap, const void * bp )
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

#endif /* end of header file */
