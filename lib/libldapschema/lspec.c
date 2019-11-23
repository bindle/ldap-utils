
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
 *   @file src/ldapschema/lerror.c  contains error functions and variables
 */
#define _LIB_LIBLDAPSCHEMA_LSPEC_C 1
#include "lspec.h"

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

#include "lspecdata.h"


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

int
ldapschema_spec_field_list(
         void                  * outvalue,
         const char           ** values );


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

/// retrieve field of OID specification
/// @param[in]    s           Reference to OID specification
/// @param[in]    field       field value to return
/// @param[out]   outvalue    returned pointer to requested field
///
/// @return    Upon successful completetion, this function returns 0,
///            otherwise an error code is returned.
/// @see       ldapschema_spec_search, ldapschema_spec_field_list
int ldapschema_spec_field(const LDAPSchemaSpec * s, int field, void * outvalue)
{
   int       * oi;   // output int
   char     ** os;   // output char * (string)

   assert(s        != NULL);
   assert(outvalue != NULL);

   oi = outvalue;
   os = outvalue;

   switch(field)
   {
      // int values (flags/types/etc)
      case LDAPSCHEMA_FLD_TYPE:           *oi = (int)s->type;             return(0);
      case LDAPSCHEMA_FLD_SUBTYPE:        *oi = (int)s->subtype;          return(0);
      case LDAPSCHEMA_FLD_SPEC_TYPE:      *oi = (int)s->spec_type;        return(0);
      case LDAPSCHEMA_FLD_FLAGS:          *oi = (int)s->flags;            return(0);

      // char * values (strings)
      case LDAPSCHEMA_FLD_OID:            *os = strdup(s->oid);           return(0);
      case LDAPSCHEMA_FLD_NAME:           *os = strdup(s->name);          return(0);
      case LDAPSCHEMA_FLD_DESC:           *os = strdup(s->desc);          return(0);
      case LDAPSCHEMA_FLD_DEF:            *os = strdup(s->def);           return(0);
      case LDAPSCHEMA_FLD_ABNF:           *os = strdup(s->abnf);          return(0);
      case LDAPSCHEMA_FLD_RE_POSIX:       *os = strdup(s->re_posix);      return(0);
      case LDAPSCHEMA_FLD_RE_PCRE:        *os = strdup(s->re_pcre);       return(0);
      case LDAPSCHEMA_FLD_SPEC:           *os = strdup(s->spec);          return(0);
      case LDAPSCHEMA_FLD_SPEC_NAME:      *os = strdup(s->spec_name);     return(0);
      case LDAPSCHEMA_FLD_SPEC_SECTION:   *os = strdup(s->spec_section);  return(0);
      case LDAPSCHEMA_FLD_SPEC_SOURCE:    *os = strdup(s->spec_source);   return(0);
      case LDAPSCHEMA_FLD_SPEC_VENDOR:    *os = strdup(s->spec_vendor);   return(0);
      case LDAPSCHEMA_FLD_SPEC_TEXT:      *os = strdup(s->spec_text);     return(0);
      case LDAPSCHEMA_FLD_NOTES:          *os = strdup(s->notes);         return(0);

      // char ** values (arrays of strings)
      case LDAPSCHEMA_FLD_EXAMPLES:       return(ldapschema_spec_field_list(outvalue, s->examples));

      default:
      break;
   };
   return(LDAPSCHEMA_UNKNOWN_FIELD);
}


/// duplicates values and returns results
/// @param[out]   outvalue    returned pointer to requested field
/// @param[in]    values      values to duplicate
///
/// @return    Upon successful completetion, this function returns 0,
///            otherwise an error code is returned.
/// @see       ldapschema_spec_field
int ldapschema_spec_field_list(void * outvalue, const char ** values)
{
   char    *** oa;   // output char ** (array of strings)
   size_t      len;
   size_t      pos;
   char     ** list;

   assert(outvalue   != NULL);

   oa    = outvalue;
   *oa   = NULL;

   if (!(values))
      return(0);

   for(len = 0; ((values[len])); len++);
   if ((list = malloc(sizeof(char *) * (len+1))) == NULL)
      return(LDAPSCHEMA_NO_MEMORY);

   for(pos = 0; (pos < len); pos++)
   {
      list[pos+1] = NULL;
      if ((list[pos] = strdup(values[pos])) == NULL)
      {
         ldapschema_value_free(list);
         return(LDAPSCHEMA_NO_MEMORY);
      };
   };

   *oa = list;

   return(0);
}


/// searches for specific oid
/// @param[out]   lenp        optional output for length of returned list
///
/// @return    Upon successful completetion, this function returns a reference
///            to an array of OID specifications otherwise NULL is returned.
/// @see       ldapschema_spec_search, ldapschema_spec_field
const LDAPSchemaSpec * const * ldapschema_spec_list(size_t * lenp)
{
   if ((lenp))
      *lenp = ldapschema_oidspecs_len;
   return(ldapschema_oidspecs);
}


/// searches for specific oid
/// @param[in]    oid         values to duplicate
///
/// @return    Upon successful completetion, this function returns a reference
///            to the specification of the requestd OID otherwise NULL is
///            returned.
/// @see       ldapschema_spec_list, ldapschema_spec_field
const LDAPSchemaSpec * ldapschema_spec_search(const char * oid)
{
   assert(oid != NULL);
   size_t               low;
   size_t               mid;
   size_t               high;
   int                  res;

   assert(oid  != NULL);

   low      = 0;
   high     = ldapschema_oidspecs_len - 1;

   // finds position in array
   while ((high - low) > 1)
   {
      mid = (low + high) / 2;
      res = strcasecmp(oid, ldapschema_oidspecs[mid]->oid);
      if (res < 0)
         high = mid;
      else if (res > 0)
         low = mid;
      else
         return(ldapschema_oidspecs[mid]);
   };

   // checks low value
   if ((res = strcasecmp(oid, ldapschema_oidspecs[low]->oid)) == 0)
      return(ldapschema_oidspecs[low]);
   if ((res = strcasecmp(oid, ldapschema_oidspecs[high]->oid)) == 0)
      return(ldapschema_oidspecs[high]);

   return(NULL);
}


/* end of source file */
