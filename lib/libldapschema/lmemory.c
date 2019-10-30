
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
#pragma mark - Headers

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

void ldapschema_attributetype_free( LDAPSchemaAttributeType  * attr )
{
   assert(attr != NULL);

   ldapschema_object_free(&attr->model);

   return;
}


LDAPSchemaAttributeType * ldapschema_attributetype_initialize(LDAPSchema * lsd)
{
   LDAPSchemaAttributeType   * attr;

   assert(lsd  != NULL);

   if ((attr = malloc(sizeof(LDAPSchemaAttributeType))) == NULL)
   {
      lsd->errcode = LDAPSCHEMA_NO_MEMORY;
      return(NULL);
   };
   bzero(attr, sizeof(LDAPSchemaAttributeType));
   attr->model.size = sizeof(LDAPSchemaAttributeType);
   attr->model.type = LDAPSCHEMA_ATTRIBUTETYPE;

   return(attr);
}


/// counts number of values in list
/// @param[in]  vals   Reference to allocated ldap_schema struct
///
/// @return    returns number of values in array
/// @see       ldapschema_initialize
int ldapschema_count_values( char ** vals )
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
int ldapschema_count_values_len( struct berval ** vals )
{
   int len;
   assert(vals != NULL);
   for(len = 0; ((vals[len])); len++);
   return(len);
}


void ldapschema_ext_free(LDAPSchemaExtension * ext)
{
   if (!(ext))
      return;

   if ((ext->extension))
      free(ext->extension);

   if ((ext->values))
      ldapschema_value_free(ext->values);

   return;
}


LDAPSchemaExtension * ldapschema_ext_initialize(LDAPSchema * lsd, const char * name)
{
   LDAPSchemaExtension   * ext;

   assert(lsd  != NULL);
   assert(name != NULL);

   if ((ext = malloc(sizeof(LDAPSchemaExtension))) == NULL)
   {
      lsd->errcode = LDAPSCHEMA_NO_MEMORY;
      return(NULL);
   };
   bzero(ext, sizeof(LDAPSchemaExtension));

   if ((ext->extension = strdup(name)) == NULL)
   {
      lsd->errcode = LDAPSCHEMA_NO_MEMORY;
      ldapschema_ext_free(ext);
      return(NULL);
   };

   if ((ext->values = malloc(sizeof(void *))) == NULL)
   {
      lsd->errcode = LDAPSCHEMA_NO_MEMORY;
      ldapschema_ext_free(ext);
      return(NULL);
   };
   ext->values[0] = NULL;

   return(ext);
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
      free(lsd->syntaxes);
   lsd->syntaxes = NULL;

   // frees oids
   if ((lsd->oids))
   {
      for(i = 0; ((lsd->oids[i])); i++)
      {
         switch( ((LDAPSchemaModel *)lsd->oids[i])->type )
         {
            case LDAPSCHEMA_SYNTAX:
            ldapschema_syntax_free(lsd->oids[i]);
            break;

            default:
            free(lsd->oids[i]);
            break;
         };
      };
      free(lsd->oids);
      lsd->oids = NULL;
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
      return(LDAPSCHEMA_NO_MEMORY);
   bzero(lsd, sizeof(LDAPSchema));

   // allocate array for OIDs
   if ((lsd->oids = malloc(sizeof(void *))) == NULL)
   {
      ldapschema_free(lsd);
      return(LDAPSCHEMA_NO_MEMORY);
   };
   bzero(lsd->oids, sizeof(void *));

   // allocate array for OIDs
   if ((lsd->syntaxes = malloc(sizeof(void *))) == NULL)
   {
      ldapschema_free(lsd);
      return(LDAPSCHEMA_NO_MEMORY);
   };
   bzero(lsd->oids, sizeof(void *));

   // saves structure
   *lsdp = lsd;

   return(LDAP_SUCCESS);
}


int ldapschema_insert(LDAPSchema * lsd, void *** listp, size_t * lenp, void * obj, int (*compar)(const void *, const void *))
{
   void        ** list;
   //size_t         len;
   size_t         size;
   size_t         low;
   size_t         mid;
   size_t         high;
   size_t         idx;
   size_t         pos;
   int            res;

   assert(lsd    != NULL);
   assert(listp  != NULL);
   assert(lenp   != NULL);
   assert(obj    != NULL);
   assert(compar != NULL);

   // increase size of array
   size = sizeof(void *) * ((*lenp) + 2);
   if ((list = realloc(*listp, size)) == NULL)
   {
      lsd->errcode = LDAPSCHEMA_NO_MEMORY;
      return(-1);
   };
   *listp        = list;
   list[*lenp+0] = NULL;
   list[*lenp+1] = NULL;

   if ((*lenp) == 0)
   {
      list[*lenp] = obj;
      (*lenp)++;
      return(0);
   };

   low   = 0;
   high  = (*lenp) - 1;

   // finds position in array
   while ((high - low) > 1)
   {
      mid = (low + high) / 2;
      res = compar(obj, list[mid]);
      if (res < 0)
         high = mid;
      else if (res > 0)
         low = mid;
      else
      {
         lsd->errcode = LDAPSCHEMA_DUPLICATE;
         return(-1);
      };
   };

   // checks low value
   idx = *lenp;
   if ((res = compar(obj, list[low])) == 0)
   {
      lsd->errcode = LDAPSCHEMA_DUPLICATE;
      return(-1);
   }
   else if (res < 0)
      idx = low;
   // checks high value
   else if ((res = compar(obj, list[high])) == 0)
   {
      lsd->errcode = LDAPSCHEMA_DUPLICATE;
      return(-1);
   }
   else if (res < 0)
      idx = high;
   else
      idx = high+1;

   // shift array members
   for(pos = *lenp; pos > idx; pos--)
      list[pos] = list[pos-1];

   // stores object and increments length
   list[pos] = obj;
   (*lenp)++;

   return(0);
}


void ldapschema_model_free(LDAPSchemaModel * model)
{
   assert(model != NULL);
   ldapschema_object_free(model);
   free(model);
   return;
}


void ldapschema_object_free(LDAPSchemaModel * obj)
{
   size_t ext;

   assert(obj != NULL);

   if ((obj->definition))
      free(obj->definition);

   if ((obj->desc))
      free(obj->desc);

   if ((obj->oid))
      free(obj->oid);

   if ((obj->extensions))
   {
      for(ext = 0; ((obj->extensions[ext])); ext++)
      {
         if ((obj->extensions[ext]->extension))
            free(obj->extensions[ext]->extension);
         if ((obj->extensions[ext]->values))
            ldapschema_value_free(obj->extensions[ext]->values);
         free(obj->extensions[ext]);
      };
      free(obj->extensions);
   };

   return;
}


void * ldapschema_oid(LDAPSchema * lsd, const char * oid, size_t type)
{
   size_t               low;
   size_t               mid;
   size_t               high;
   int                  res;
   LDAPSchemaModel   ** models;

   assert(lsd  != NULL);
   assert(oid  != NULL);

   type     = LDAPSCHEMA_TYPE(type);
   models   = (LDAPSchemaModel **)lsd->oids;
   low      = 0;
   high     = lsd->oids_len;

   // finds position in array
   while ((high - low) > 1)
   {
      mid = (low + high) / 2;
      res = strcasecmp(oid, models[mid]->oid);
      if (res < 0)
         high = mid;
      else if (res > 0)
         low = mid;
      else
      {
         if ( (LDAPSCHEMA_TYPE(models[mid]->type) == type) || (!(type)) )
            return(models[mid]);
         return(NULL);
      };
   };

   // checks low value
   if ((res = strcasecmp(oid, models[low]->oid)) == 0)
      if ((models[low]->type == type) || (!(type)))
         return(models[low]);
   if ((res = strcasecmp(oid, models[high]->oid)) == 0)
      if ((models[high]->type == type) || (!(type)))
         return(models[high]);

   return(NULL);
}


void ldapschema_syntax_free(LDAPSchemaSyntax * syntax)
{
   assert(syntax != NULL);

   ldapschema_object_free(&syntax->model);

   free(syntax);

   return;
}


LDAPSchemaSyntax * ldapschema_syntax_initialize(LDAPSchema * lsd)
{
   LDAPSchemaSyntax * syntax;

   assert(lsd != NULL);

   // initialize syntax
   if ((syntax = malloc(sizeof(LDAPSchemaSyntax))) == NULL)
   {
      lsd->errcode = LDAPSCHEMA_NO_MEMORY;
      return(syntax);
   };
   bzero(syntax, sizeof(LDAPSchemaSyntax));
   syntax->model.size = sizeof(LDAPSchemaSyntax);
   syntax->model.type = LDAPSCHEMA_SYNTAX;

   return(syntax);
}


char ** ldapschema_value_add( char ** vals, const char * val, int * countp)
{
   int      count;
   size_t   len;
   void   * ptr;
   char   * str;

   assert(vals != NULL);
   assert(val  != NULL);
   //if (!(vals))
   //   return(NULL);
   //if (!(val))
   //   return(vals);

   // determine number of values
   if ((countp))
      count = *countp;
   else
      count = ldap_count_values(vals);

   // saves value to array
   if ((str = strdup(val)) == NULL)
      return(NULL);

   // increase size of vals
   len = sizeof(char *) * (((size_t)count)+2);
   if ((ptr = realloc(vals, len)) == NULL)
   {
      free(str);
      return(NULL);
   };
   vals        = ptr;
   vals[count] = str;
   count++;
   vals[count] = NULL;

   // increments count
   if ((countp))
      *countp = count;

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
