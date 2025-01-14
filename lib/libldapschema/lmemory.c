
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
*   @file lib/libldapschema/lmemory.c  contains memory functions and variables
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

#include "lspec.h"
#include "lsort.h"
#include "lerror.h"


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

int ldapschema_append(LDAPSchema * lsd, void *** listp, size_t * lenp, void * obj)
{
   void        ** list;
   size_t         size;

   assert(lsd    != NULL);
   assert(listp  != NULL);
   assert(lenp   != NULL);
   assert(obj    != NULL);

   // increase size of array
   size = sizeof(void *) * ((*lenp) + 2);
   if ((list = realloc(*listp, size)) == NULL)
      return(lsd->errcode = LDAPSCHEMA_NO_MEMORY);
   *listp        = list;
   list[*lenp+0] = obj;
   list[*lenp+1] = NULL;
   (*lenp)++;

   return(LDAPSCHEMA_SUCCESS);
}


void ldapschema_attributetype_free( LDAPSchemaAttributeType  * attr )
{
   assert(attr != NULL);

   ldapschema_object_free(&attr->model);

   return;
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


void ldapschema_curfree(LDAPSchemaCur cur)
{
   assert(cur != NULL);
   free(cur);
   return;
}


LDAPSchemaCur ldapschema_curalloc(LDAPSchema * lsd)
{
   LDAPSchemaCur cur;
   if ((cur = malloc(sizeof(struct ldapschema_cursor))) == NULL)
   {
      lsd->errcode = LDAPSCHEMA_NO_MEMORY;
      return(NULL);
   };
   memset(cur, 0, sizeof(struct ldapschema_cursor));
   return(cur);
}


void ldapschema_ext_free(LDAPSchemaExtension * ext)
{
   if (!(ext))
      return;

   if ((ext->extension))
      free(ext->extension);

   if ((ext->values))
      ldapschema_value_free(ext->values);

   free(ext);

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
   memset(ext, 0, sizeof(LDAPSchemaExtension));

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
   size_t   pos;

   assert(lsd != NULL);

   // frees list of errors
   if ((lsd->objerrs))
      free(lsd->objerrs);
   lsd->objerrs = NULL;

   // frees syntaxes list
   if ((lsd->syntaxes))
   {
      for(pos = 0; pos < lsd->syntaxes_len; pos++)
         free(lsd->syntaxes[pos]);
      free(lsd->syntaxes);
   };
   lsd->syntaxes = NULL;

   // frees attribute types list
   if ((lsd->attrs))
   {
      for(pos = 0; pos < lsd->attrs_len; pos++)
         free(lsd->attrs[pos]);
      free(lsd->attrs);
   };
   lsd->attrs = NULL;

   // frees matching rules list
   if ((lsd->mtchngrls))
   {
      for(pos = 0; pos < lsd->mtchngrls_len; pos++)
         free(lsd->mtchngrls[pos]);
      free(lsd->mtchngrls);
   };
   lsd->mtchngrls = NULL;

   // frees objectclass list
   if ((lsd->objclses))
   {
      for(pos = 0; pos < lsd->objclses_len; pos++)
         free(lsd->objclses[pos]);
      free(lsd->objclses);
   };
   lsd->objclses = NULL;

   if ((lsd->schema_errs))
      ldapschema_value_free(lsd->schema_errs);

   // frees oids
   if ((lsd->oids))
   {
      for(i = 0; ((lsd->oids[i].model)); i++)
      {
         switch( lsd->oids[i].model->type )
         {
            case LDAPSCHEMA_ATTRIBUTETYPE:
            ldapschema_attributetype_free(lsd->oids[i].attributetype);
            break;

            case LDAPSCHEMA_SYNTAX:
            ldapschema_syntax_free(lsd->oids[i].syntax);
            break;

            default:
            free(lsd->oids[i].model);
            break;
         };
      };
      free(lsd->oids);
      lsd->oids = NULL;
   };
   if ((lsd->dups))
   {
      for(i = 0; ((lsd->dups[i].model)); i++)
      {
         switch( lsd->dups[i].model->type )
         {
            case LDAPSCHEMA_ATTRIBUTETYPE:
            ldapschema_attributetype_free(lsd->dups[i].attributetype);
            break;

            case LDAPSCHEMA_SYNTAX:
            ldapschema_syntax_free(lsd->dups[i].syntax);
            break;

            default:
            free(lsd->dups[i].model);
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
   memset(lsd, 0, sizeof(LDAPSchema));

   // saves structure
   *lsdp = lsd;

   return(LDAP_SUCCESS);
}


/// adds error to list of schema errors
/// @param[in]  lsd        reference to allocated ldap_schema struct
/// @param[in]  listp      reference to sorted array to manipulate
/// @param[in]  lenp       reference to length of array
/// @param[in]  obj        reference to object to add to array
/// @param[in]  compar     reference to compare function used to determine
///                        object's position within the list.
///
/// @return    If successfull, returns 0.  If duplicate, returns -1. Otherwise
///            errcode is set and the value is return;
/// @see       ldapschema_append
int ldapschema_insert(LDAPSchema * lsd, void *** listp, size_t * lenp, void * obj, int (*compar)(const void *, const void *))
{
   void        ** list;
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
      return(lsd->errcode = LDAPSCHEMA_NO_MEMORY);
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
      res = compar(&obj, &list[mid]);
      if (res < 0)
         high = mid;
      else if (res > 0)
         low = mid;
      else
         return(-1);
   };

   // checks low value
   if ((res = compar(&obj, &list[low])) == 0)
      return(-1);
   else if (res < 0)
      idx = low;
   // checks high value
   else if ((res = compar(&obj, &list[high])) == 0)
      return(-1);
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

   return(LDAPSCHEMA_SUCCESS);
}


void ldapschema_matchingrule_free(LDAPSchemaMatchingRule * rule)
{
   assert(rule != NULL);

   if ((rule->used_by))
      free(rule->used_by);
   ldapschema_object_free(&rule->model);

   free(rule);

   return;
}


void ldapschema_memfree(void * p)
{
   if (!(p))
      return;
   free(p);
   return;
}


void ldapschema_memvfree(void ** v)
{
   size_t idx;
   if (!(v))
      return;
   for(idx = 0; ((v[idx])); idx++)
      free(v[idx]);
   free(v);
   return;
}


void ldapschema_model_free(LDAPSchemaModel * model)
{
   assert(model != NULL);
   ldapschema_object_free(model);
   free(model);
   return;
}


LDAPSchemaModel * ldapschema_model_initialize(LDAPSchema * lsd,
   const char * oid, uint32_t type, const struct berval * def)
{
   size_t               size;
   LDAPSchemaModel *    mod;

   assert(lsd != NULL);
   assert(oid != NULL);

   switch(type)
   {
      case LDAPSCHEMA_ATTRIBUTETYPE:   size = sizeof(LDAPSchemaAttributeType);   break;
      case LDAPSCHEMA_SYNTAX:          size = sizeof(LDAPSchemaSyntax);          break;
      case LDAPSCHEMA_MATCHINGRULE:    size = sizeof(LDAPSchemaMatchingRule);    break;
      case LDAPSCHEMA_OBJECTCLASS:     size = sizeof(LDAPSchemaObjectclass);     break;
      default: assert(0); return(NULL);
   };

   // initialize syntax
   if ((mod = malloc(size)) == NULL)
   {
      lsd->errcode = LDAPSCHEMA_NO_MEMORY;
      return(NULL);
   };
   memset(mod, 0, size);

   mod->size = size;
   mod->type = type;

   // copy OID into model
   if ((mod->oid = strdup(oid)) == NULL)
   {
      lsd->errcode = LDAPSCHEMA_NO_MEMORY;
      ldapschema_model_free(mod);
      return(NULL);
   };

   // copy definition into model
   if (((def)) && (def->bv_len > 0))
   {
      if ((mod->definition = malloc(def->bv_len+1)) == NULL)
      {
         lsd->errcode = LDAPSCHEMA_NO_MEMORY;
         ldapschema_model_free(mod);
         return(NULL);
      };
      memcpy(mod->definition, def->bv_val, def->bv_len);
      mod->definition[def->bv_len] = '\0';
   };

   // reference OID specification
   mod->spec = ldapschema_spec_search(oid);
   if ((mod->spec))
   {
      if (mod->spec->type != type)
      {
         mod->spec = NULL;
         return(mod);
      };
      mod->flags = mod->spec->flags;
   };

   return(mod);
}


int ldapschema_model_register(LDAPSchema * lsd, LDAPSchemaModel * mod)
{
   int                     err;
   size_t                  names_len;
   size_t                  idx;
   size_t *                list_lenp;
   char **                 names;
   const char *            desc;
   LDAPSchemaAlias *       alias;
   LDAPSchemaAlias ***     listp;
   LDAPSchemaPointer       objptr;

   assert(lsd != NULL);
   assert(mod != NULL);

   desc           = NULL;
   names          = NULL;
   names_len      = 0;
   objptr.model   = mod;

   // determines model specific list and search keys
   switch(mod->type)
   {
      case LDAPSCHEMA_ATTRIBUTETYPE:
      listp       = &lsd->attrs;
      list_lenp   = &lsd->attrs_len;
      names       = objptr.attributetype->names;
      names_len   = objptr.attributetype->names_len;
      break;

      case LDAPSCHEMA_SYNTAX:
      listp       = &lsd->syntaxes;
      list_lenp   = &lsd->syntaxes_len;
      desc        = mod->desc;
      break;

      case LDAPSCHEMA_MATCHINGRULE:
      listp       = &lsd->mtchngrls;
      list_lenp   = &lsd->mtchngrls_len;
      names       = objptr.matchingrule->names;
      names_len   = objptr.matchingrule->names_len;
      break;

      case LDAPSCHEMA_OBJECTCLASS:
      listp       = &lsd->objclses;
      list_lenp   = &lsd->objclses_len;
      names       = objptr.objectclass->names;
      names_len   = objptr.objectclass->names_len;
      break;

      default:
      assert(0);
      return(0);
   };

   // adds model to OID list
   if ((err = ldapschema_insert(lsd, (void ***)&lsd->oids, &lsd->oids_len, mod, ldapschema_compar_models)) > 0)
      return(err);
   if (err == -1)
   {
      ldapschema_schema_err(lsd, mod, "duplicates OID of existing object");
      if ((err = ldapschema_append(lsd,(void ***)&lsd->dups, &lsd->dups_len, mod)) != LDAP_SUCCESS)
         return(err);
   };

   // adds model into model specific list using OID
   if ((alias = malloc(sizeof(LDAPSchemaAlias))) == NULL)
      return(lsd->errcode = LDAPSCHEMA_NO_MEMORY);
   alias->alias   = mod->oid;
   alias->model   = mod;
   if ((err = ldapschema_insert(lsd, (void ***)listp, list_lenp, alias, ldapschema_compar_aliases)) > 0)
   {
      free(alias);
      return(err);
   };
   if (err == -1)
   {
      ldapschema_schema_err(lsd,  mod, "duplicates oid of existing object");
      free(alias);
   };

   // adds model into model specific list using desc
   if ((desc))
   {
      if ((alias = malloc(sizeof(LDAPSchemaAlias))) == NULL)
         return(lsd->errcode = LDAPSCHEMA_NO_MEMORY);
      alias->alias   = desc;
      alias->model   = mod;
      if ((err = ldapschema_insert(lsd, (void ***)listp, list_lenp, alias, ldapschema_compar_aliases)) > 0)
      {
         free(alias);
         return(err);
      };
      if (err == -1)
      {
         ldapschema_schema_err(lsd,  mod, "duplicates DESC of existing object");
         free(alias);
      };
   };

   // adds model into model specific list using names
   for(idx = 0; (idx < names_len); idx++)
   {
      if ((alias = malloc(sizeof(LDAPSchemaAlias))) == NULL)
         return(lsd->errcode = LDAPSCHEMA_NO_MEMORY);
      alias->alias   = names[idx];
      alias->model   = mod;
      if ((err = ldapschema_insert(lsd, (void ***)listp, list_lenp, alias, ldapschema_compar_aliases)) > 0)
      {
         free(alias);
         return(err);
      };
      if (err == -1)
      {
         ldapschema_schema_err(lsd,  mod, "duplicates NAME '%s' of existing object", names[idx]);
         free(alias);
      };
   };

   return(0);
}


void ldapschema_object_free(LDAPSchemaModel * obj)
{
   size_t idx;

   assert(obj != NULL);

   if ((obj->definition))
      free(obj->definition);

   if ((obj->desc))
      free(obj->desc);

   if ((obj->oid))
      free(obj->oid);

   if ((obj->extensions))
   {
      for(idx = 0; ((obj->extensions[idx])); idx++)
      {
         if ((obj->extensions[idx]->extension))
            free(obj->extensions[idx]->extension);
         if ((obj->extensions[idx]->values))
            ldapschema_value_free(obj->extensions[idx]->values);
         free(obj->extensions[idx]);
      };
      free(obj->extensions);
   };

   if ((obj->errors))
   {
      for(idx = 0; ((obj->errors[idx])); idx++)
         free(obj->errors[idx]);
      free(obj->errors);
   };

   return;
}


void ldapschema_objectclass_free(LDAPSchemaObjectclass * objectclass)
{
   assert(objectclass != NULL);

   ldapschema_object_free(&objectclass->model);

   if ((objectclass->sup_name))
      free(objectclass->sup_name);

   if ((objectclass->names))
      ldapschema_value_free(objectclass->names);

   if ((objectclass->must))
      free(objectclass->must);
   if ((objectclass->may))
      free(objectclass->may);

   if ((objectclass->inherit_must))
      free(objectclass->inherit_must);
   if ((objectclass->inherit_may))
      free(objectclass->inherit_may);

   free(objectclass);

   return;
}


void * ldapschema_oid(LDAPSchema * lsd, const char * oid, uint32_t type)
{
   size_t                  low;
   size_t                  mid;
   size_t                  high;
   int                     res;
   LDAPSchemaModel **      models;
   const LDAPSchemaSpec *  spec;
   LDAPSchemaModel *       mod;
   int                     err;

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

   // look for matching spec and build requested OID from spec
   if ((spec = ldapschema_spec_search(oid)) == NULL)
      return(NULL);
   if ( (spec->type != type) && ((type)) )
      return(NULL);
   if ((mod = ldapschema_model_initialize(lsd, oid, spec->type, NULL)) == NULL)
      return(NULL);
   if ((err = ldapschema_model_register(lsd, mod)) != LDAP_SUCCESS)
   {
      ldapschema_model_free(mod);
      return(NULL);
   };
   ldapschema_schema_err(lsd, mod, "not defined by server");

   return(mod);
}


char * ldapschema_stradd(char ** s1p, const char * s2)
{
   char *   s1;
   size_t   l1;
   size_t   l2;
   void *   ptr;

   assert(s1p  != NULL);
   assert(*s1p != NULL);
   assert(s2   != NULL);

   s1 = *s1p;
   l1 = strlen(s1);
   l2 = strlen(s2);

   if ((ptr = realloc(s1, (l1+l2+1))) == NULL)
      return(NULL);
   s1    = ptr;
   *s1p  = s1;

   return(strncat(s1, s2, (l1+l2+1)));
}


void ldapschema_syntax_free(LDAPSchemaSyntax * syntax)
{
   assert(syntax != NULL);

   regfree(&syntax->re);
   ldapschema_object_free(&syntax->model);

   if ((syntax->attrs))
      free(syntax->attrs);

   if ((syntax->mtchngrls))
      free(syntax->mtchngrls);

   free(syntax);

   return;
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
      count = ldaputils_count_values(vals);

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

char ** ldapschema_value_dup(char ** vals)
{
   size_t      len;
   size_t      idx;
   char     ** dups;

   assert(vals != NULL);

   for(len = 0; ((vals[len])); len++);

   if ((dups = malloc(sizeof(char *)*(len+1))) == NULL)
      return(NULL);

   for(idx = 0; (idx < len); idx++)
   {
      if ((dups[idx] = strdup(vals[idx])) == NULL)
      {
         ldapschema_value_free(dups);
         return(NULL);
      };
   };
   dups[idx] = NULL;

   return(dups);
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
