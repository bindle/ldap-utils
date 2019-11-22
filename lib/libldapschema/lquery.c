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
#define _LIB_LIBLDAPSCHEMA_LQUERY_C 1
#include "lquery.h"


///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>

#include "lsort.h"
#include "lspec.h"


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

LDAPSchemaAlias * ldapschema_get_alias(LDAPSchema * lsd,
   const char * alias, LDAPSchemaAlias ** list, size_t list_len)
{
   size_t         low;
   size_t         mid;
   size_t         high;
   int            res;

   assert(lsd     != NULL);
   assert(alias   != NULL);
   assert(list    != NULL);

   low   = 0;
   high  = list_len - 1;

   // finds position in array
   while ((high - low) > 1)
   {
      mid = (low + high) / 2;
      res = strcasecmp(alias, list[mid]->alias);
      if (res < 0)
         high = mid;
      else if (res > 0)
         low = mid;
      else
         return(list[mid]);
   };

   // checks low value
   if ((res = strcasecmp(alias, list[low]->alias)) == 0)
      return(list[low]);

   // checks high value
   if ((res = strcasecmp(alias, list[high]->alias)) == 0)
      return(list[high]);

   return(NULL);
}


/// retrieves attributeType from schema
/// @param[in]  lsd    Reference to allocated ldap_schema struct
/// @param[in]  name   name or OID of attributeType to return
///
/// @return    If successful, returns a constant reference to the specified
///            attributetype.  NULL is returned if the attributeType does not
///            exist.
/// @see       ldapschema_errno, ldapschema_value_free
const LDAPSchemaAttributeType * ldapschema_get_attributetype(LDAPSchema * lsd,
   const char * name)
{
   const LDAPSchemaAlias   * alias;

   assert(lsd     != NULL);
   assert(name    != NULL);

   if ((alias = ldapschema_get_alias(lsd, name, lsd->attrs, lsd->attrs_len)) == NULL)
      return(NULL);

   return(alias->attributetype);
}


/// retrieves attributeType from schema
/// @param[in]  lsd    Reference to allocated ldap_schema struct
/// @param[in]  name   name or OID of attributeType to return
///
/// @return    If successful, returns a constant reference to the specified
///            attributetype.  NULL is returned if the attributeType does not
///            exist.
/// @see       ldapschema_errno, ldapschema_value_free
const LDAPSchemaSyntax * ldapschema_get_ldapsyntax(LDAPSchema * lsd,
   const char * name)
{
   const LDAPSchemaAlias   * alias;

   assert(lsd     != NULL);
   assert(name    != NULL);

   if ((alias = ldapschema_get_alias(lsd, name, lsd->syntaxes, lsd->syntaxes_len)) == NULL)
      return(NULL);

   return(alias->syntax);
}


/* end of source file */
