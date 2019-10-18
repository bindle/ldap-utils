
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
*   @file src/ldapschema/lmemory.c  contains memory functions and variables
*/
#define _LIB_LIBLDAPSCHEMA_LMEMORY_C 1
#include "lmemory.h"

///////////////
//           //
//  Headers  //
//           //
///////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Headers
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <ldap.h>
#include <stdlib.h>
#include <assert.h>


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Functions
#endif

/// counts number of values in list
/// @param[in]  vals   Reference to allocated ldap_schema struct
///
/// @return    returns number of values in array
/// @see       ldapschema_initialize
int ldap_count_values( char ** vals )
{
   int len;
   assert(vals != NULL);
   for(len = 0; ((vals[len])); len++);
   return(len);
}


/// counts number of values in list
/// @param[in]  vals   stores number of arguments parsed from definition
///
/// @return    returns number of values in array
/// @see       ldapschema_initialize
int ldap_count_values_len( struct berval ** vals )
{
   int len;
   assert(vals != NULL);
   for(len = 0; ((vals[len])); len++);
   return(len);
}


/// frees common config
/// @param[in]  lsd    Reference to allocated ldap_schema struct
///
/// @see       ldapschema_initialize
void ldapschema_free(LDAPSchema * lsd)
{
   int i;

   assert(lsd != NULL);

   // frees syntaxes
   if ((lsd->syntaxes))
   {
      for(i = 0; ((lsd->syntaxes[i])); i++)
         ldapschema_syntax_free(lsd->syntaxes[i]);
      free(lsd->syntaxes);
   };

   free(lsd);

   return;
}


/// initializes LDAP schema
/// @param[out]   lsdp        Reference to pointer used to store allocated ldap_schema struct.
///
/// @return    Upon successful completetion, this function returns 0,
///            otherwise an error code is returned.
/// @see       ldapschema_free
int ldapschema_initialize(LDAPSchema ** lsdp)
{
   LDAPSchema * lsd;

   assert(lsdp != NULL);

   // allocate initial memory
   if ((lsd = malloc(sizeof(LDAPSchema))) == NULL)
      return(LDAP_NO_MEMORY);
   bzero(lsd, sizeof(LDAPSchema));

   return(LDAP_SUCCESS);
}


void ldapschema_syntax_free(LDAPSchemaSyntax * syntax)
{
   assert(syntax != NULL);

   if ((syntax->model.definition))
      free(syntax->model.definition);
   if ((syntax->model.desc))
      free(syntax->model.desc);
   if ((syntax->model.oid))
      free(syntax->model.oid);

   return;
}


char ** ldapschema_value_add( char ** vals, const char * val, int * countp)
{
   int      count;
   size_t   len;
   void   * ptr;
   char   * str;

   if (!(vals))
      return(vals);
   if (!(val))
      return(vals);

   // determine number of values
   if ((countp))
      count = *countp;
   else
   count = ldap_count_values(vals);

   // saves value to array
   if ((str = strdup(val)) == NULL)
      return(NULL);

   // increase size of vals
   len = sizeof(char *) * ((size_t)count+1);
   if ((ptr = realloc(vals, len)) == NULL)
   {
      free(str);
      return(NULL);
   };
   vals          = ptr;
   vals[count+0] = str;
   vals[count+1] = NULL;

   // increments count
   if ((countp))
      *countp += 1;

   return(vals);
}


/// frees list of values
/// @param[in]    vals        array of values to be freed
///
/// @see       ldapschema_free
void ldapschema_value_free( char ** vals )
{
   int len;
   if (!(vals))
      return;
   for(len = 0; ((vals[len])); len++)
      free(vals[len]);
   free(vals);
   return;
}


/// frees list of values
/// @param[in]    vals        array of values to be freed
///
/// @see       ldapschema_free
void ldapschema_value_free_len( struct berval ** vals )
{
   int len;
   if (!(vals))
      return;
   for(len = 0; ((vals[len])); len++)
   {
      if ((vals[len]->bv_val))
         free(vals[len]->bv_val);
      free(vals[len]);
   };
   free(vals);
   return;
}

/* end of source file */
