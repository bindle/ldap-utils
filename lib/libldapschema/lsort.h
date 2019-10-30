
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
/// @param[in]    p1          reference to LDAP model
/// @param[in]    p2          reference to LDAP model
///
/// @return    ldapschema_model_cmp() returns an integer greater than, equal
///            to, or less than 0, according as the OID of `m1` is
///            lexicographically greater than, equal to, or less than the OID
///            of `m2`.
/// @see       ldapschema_free, ldapschema_initialize, ldapschema_errno
_LDAPSCHEMA_I int ldapschema_extension_cmp( const void * p1, const void * p2 )
{
   const LDAPSchemaExtension * e1 = p1;
   const LDAPSchemaExtension * e2 = p2;

   if ( (!(e1)) && (!(e2)) )
      return(0);
   if (!(e1))
      return(-1);
   if (!(e2))
      return(1);

   if ( (!(e1->extension)) && (!(e2->extension)) )
      return(0);
   if (!(e1->extension))
      return(-1);
   if (!(e2->extension))
      return(1);

   return(strcasecmp(e1->extension, e2->extension));
}


/// compares the OIDs of `m1` and `m2`
/// @param[in]    p1          reference to LDAP model
/// @param[in]    p2          reference to LDAP model
///
/// @return    ldapschema_model_cmp() returns an integer greater than, equal
///            to, or less than 0, according as the OID of `m1` is
///            lexicographically greater than, equal to, or less than the OID
///            of `m2`.
/// @see       ldapschema_free, ldapschema_initialize, ldapschema_errno
_LDAPSCHEMA_I int ldapschema_model_cmp( const void * p1, const void * p2 )
{
   const LDAPSchemaModel * m1 = p1;
   const LDAPSchemaModel * m2 = p2;

   if ( (!(m1)) && (!(m2)) )
      return(0);
   if (!(m1))
      return(-1);
   if (!(m2))
      return(1);

   if ( (!(m1->oid)) && (!(m2->oid)) )
      return(0);
   if (!(m1->oid))
      return(-1);
   if (!(m2->oid))
      return(1);

   return(strcasecmp(m1->oid, m2->oid));
}


/// compares the LDAP syntax descriptions of `s1` and `s2`
/// @param[in]    s1          Numeric error code
/// @param[in]    s2          Numeric error code
///
/// @return    ldapschema_syntax_cmp() returns an integer greater than, equal
///            to, or less than 0, according as the description of `s1` is
///            lexicographically greater than, equal to, or less than the
///            description of `s2`.
/// @see       ldapschema_free, ldapschema_initialize, ldapschema_errno
_LDAPSCHEMA_I int ldapschema_syntax_cmp( const LDAPSchemaSyntax * s1, const LDAPSchemaSyntax * s2 )
{

   if ( (!(s1)) && (!(s2)) )
      return(0);
   if (!(s1))
      return(-1);
   if (!(s2))
      return(1);

   if ( (!(s1->model.desc)) && (!(s2->model.desc)) )
      return(0);
   if (!(s1->model.desc))
      return(-1);
   if (!(s2->model.desc))
      return(1);

   return(strcasecmp(s1->model.desc, s2->model.desc));
}

#endif /* end of header file */
