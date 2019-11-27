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
#include "lmemory.h"


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

int
ldapschema_get_info_model_str(
         char **                       os,
         const char *                  src );


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

//-----------------------//
// ldapschema_count_XXXX //
//-----------------------//
#pragma mark ldapschema_count_XXXX functions

size_t ldapschema_count_attributetypes(LDAPSchema * lsd)
{
   size_t idx;
   size_t cnt;
   assert(lsd != NULL);
   cnt = 0;
   for(idx = 0; (idx < lsd->oids_len); idx++)
      if (lsd->oids[idx].model->type == LDAPSCHEMA_ATTRIBUTETYPE)
         cnt++;
   return(cnt);
}


size_t ldapschema_count_ldapsyntaxes(LDAPSchema * lsd)
{
   size_t idx;
   size_t cnt;
   assert(lsd != NULL);
   cnt = 0;
   for(idx = 0; (idx < lsd->oids_len); idx++)
      if (lsd->oids[idx].model->type == LDAPSCHEMA_SYNTAX)
         cnt++;
   return(cnt);
}


size_t ldapschema_count_matchingrules(LDAPSchema * lsd)
{
   size_t idx;
   size_t cnt;
   assert(lsd != NULL);
   cnt = 0;
   for(idx = 0; (idx < lsd->oids_len); idx++)
      if (lsd->oids[idx].model->type == LDAPSCHEMA_MATCHINGRULE)
         cnt++;
   return(cnt);
}


size_t ldapschema_count_objectclasses(LDAPSchema * lsd)
{
   size_t idx;
   size_t cnt;
   assert(lsd != NULL);
   cnt = 0;
   for(idx = 0; (idx < lsd->oids_len); idx++)
      if (lsd->oids[idx].model->type == LDAPSCHEMA_OBJECTCLASS)
         cnt++;
   return(cnt);
}


//----------------------//
// ldapschema_find_XXXX //
//----------------------//
#pragma mark ldapschema_find_XXXX functions

LDAPSchemaAlias * ldapschema_find_alias(LDAPSchema * lsd,
   const char * alias, LDAPSchemaAlias ** list, size_t list_len)
{
   size_t         low;
   size_t         mid;
   size_t         high;
   int            res;

   assert(lsd     != NULL);
   assert(alias   != NULL);
   assert(list    != NULL);

   // verify there is data in the list
   if (list_len == 0)
      return(NULL);

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
LDAPSchemaAttributeType * ldapschema_find_attributetype(LDAPSchema * lsd,
   const char * name)
{
   const LDAPSchemaAlias   * alias;

   assert(lsd     != NULL);
   assert(name    != NULL);

   if ((alias = ldapschema_find_alias(lsd, name, lsd->attrs, lsd->attrs_len)) == NULL)
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
LDAPSchemaSyntax * ldapschema_find_ldapsyntax(LDAPSchema * lsd,
   const char * name)
{
   const LDAPSchemaAlias   * alias;

   assert(lsd     != NULL);
   assert(name    != NULL);

   if ((alias = ldapschema_find_alias(lsd, name, lsd->syntaxes, lsd->syntaxes_len)) == NULL)
      return(NULL);

   return(alias->syntax);
}


LDAPSchemaMatchingRule * ldapschema_find_matchingrule(LDAPSchema * lsd,
   const char * name)
{
   const LDAPSchemaAlias   * alias;

   assert(lsd     != NULL);
   assert(name    != NULL);

   if ((alias = ldapschema_find_alias(lsd, name, lsd->mtchngrls, lsd->mtchngrls_len)) == NULL)
      return(NULL);

   return(alias->matchingrule);
}


LDAPSchemaObjectclass * ldapschema_find_objectclass(LDAPSchema * lsd,
   const char * name)
{
   const LDAPSchemaAlias   * alias;

   assert(lsd     != NULL);
   assert(name    != NULL);

   if ((alias = ldapschema_find_alias(lsd, name, lsd->objclses, lsd->objclses_len)) == NULL)
      return(NULL);

   return(alias->objectclass);
}


//-----------------------//
// ldapschema_first_XXXX //
//-----------------------//
#pragma mark ldapschema_first_XXXX functions

const LDAPSchemaAttributeType * ldapschema_first_attributetype(LDAPSchema * lsd,
   LDAPSchemaCur * curp)
{
   LDAPSchemaCur cur;

   assert(lsd  != NULL);
   assert(curp != NULL);

   if ((cur = ldapschema_curalloc(lsd)) == NULL)
      return(NULL);
   *curp = cur;

   for(cur->cursor = 0; (cur->cursor < lsd->oids_len); cur->cursor++)
      if (lsd->oids[cur->cursor].model->type == LDAPSCHEMA_ATTRIBUTETYPE)
         return(lsd->oids[cur->cursor].attributetype);

   return(NULL);
}


const LDAPSchemaSyntax * ldapschema_first_ldapsyntax(LDAPSchema * lsd,
   LDAPSchemaCur * curp)
{
   LDAPSchemaCur cur;

   assert(lsd  != NULL);
   assert(curp != NULL);

   if ((cur = ldapschema_curalloc(lsd)) == NULL)
      return(NULL);
   *curp = cur;

   for(cur->cursor = 0; (cur->cursor < lsd->oids_len); cur->cursor++)
      if (lsd->oids[cur->cursor].model->type == LDAPSCHEMA_SYNTAX)
         return(lsd->oids[cur->cursor].syntax);

   return(NULL);
}


const LDAPSchemaMatchingRule * ldapschema_first_matchingrule(LDAPSchema * lsd,
   LDAPSchemaCur * curp)
{
   LDAPSchemaCur cur;

   assert(lsd  != NULL);
   assert(curp != NULL);

   if ((cur = ldapschema_curalloc(lsd)) == NULL)
      return(NULL);
   *curp = cur;

   for(cur->cursor = 0; (cur->cursor < lsd->oids_len); cur->cursor++)
      if (lsd->oids[cur->cursor].model->type == LDAPSCHEMA_MATCHINGRULE)
         return(lsd->oids[cur->cursor].matchingrule);

   return(NULL);
}


const LDAPSchemaObjectclass * ldapschema_first_objectclass(LDAPSchema * lsd,
   LDAPSchemaCur * curp)
{
   LDAPSchemaCur cur;

   assert(lsd  != NULL);
   assert(curp != NULL);

   if ((cur = ldapschema_curalloc(lsd)) == NULL)
      return(NULL);
   *curp = cur;

   for(cur->cursor = 0; (cur->cursor < lsd->oids_len); cur->cursor++)
      if (lsd->oids[cur->cursor].model->type == LDAPSCHEMA_OBJECTCLASS)
         return(lsd->oids[cur->cursor].objectclass);

   return(NULL);
}


//--------------------------//
// ldapschema_get_info_XXXX //
//--------------------------//
#pragma mark ldapschema_get_info_XXXX functions

int ldapschema_get_info_attributetype(LDAPSchema * lsd,
   const LDAPSchemaAttributeType * attr, int field, void * outvalue)
{
   int       * oi;   // output int (flags/types/etc)
   char    *** oa;   // output char ** (array of strings)

   assert(lsd        != NULL);
   assert(attr       != NULL);
   assert(field      != 0);
   assert(outvalue   != 0);

   oi = outvalue;
   oa = outvalue;

   switch(field)
   {
      // int values (flags/types/etc)
      case LDAPSCHEMA_FLD_USAGE: *oi = (int)attr->usage;   return(0);

      // char * values (strings)

      // char ** values (arrays of strings)
      case LDAPSCHEMA_FLD_NAME:  if ((*oa = ldapschema_value_dup(attr->names)) == NULL) return(LDAPSCHEMA_NO_MEMORY); return(0);

      // misc
      case LDAPSCHEMA_FLD_SUPERIOR: *(LDAPSchemaAttributeType **)outvalue = attr->sup;    return(0);
      case LDAPSCHEMA_FLD_SYNTAX:   *(LDAPSchemaSyntax **)outvalue        = attr->syntax; return(0);

      default:
      break;
   };

   return(ldapschema_get_info_model(lsd, &attr->model, field, outvalue));
}


int ldapschema_get_info_ldapsyntax(LDAPSchema * lsd,
   const LDAPSchemaSyntax * syntax, int field, void * outvalue )
{
   assert(lsd        != NULL);
   assert(syntax     != NULL);
   assert(field      != 0);
   assert(outvalue   != 0);
   return(ldapschema_get_info_model(lsd, &syntax->model, field, outvalue));
}


int ldapschema_get_info_matchingrule(LDAPSchema * lsd,
   const LDAPSchemaMatchingRule * mtchngrl, int field, void * outvalue )
{
   char    *** oa;   // output char ** (array of strings)

   assert(lsd        != NULL);
   assert(mtchngrl   != NULL);
   assert(field      != 0);
   assert(outvalue   != 0);

   oa = outvalue;

   switch(field)
   {
      // char ** values (arrays of strings)
      case LDAPSCHEMA_FLD_NAME:  if ((*oa = ldapschema_value_dup(mtchngrl->names)) == NULL) return(LDAPSCHEMA_NO_MEMORY); return(0);

      // misc
      case LDAPSCHEMA_FLD_SYNTAX: *(LDAPSchemaSyntax **)outvalue = mtchngrl->syntax; return(0);

      default:
      break;
   };

   return(ldapschema_get_info_model(lsd, &mtchngrl->model, field, outvalue));
}


int ldapschema_get_info_model(LDAPSchema * lsd,
   const LDAPSchemaModel * mod, int field, void * outvalue )
{
   int       * oi;   // output int
   char     ** os;   // output char * (string)

   assert(lsd        != NULL);
   assert(mod        != NULL);
   assert(field      != 0);
   assert(outvalue   != 0);

   oi = outvalue;
   os = outvalue;

   switch(field)
   {
      // int values (flags/types/etc)
      case LDAPSCHEMA_FLD_TYPE:  *oi = (int)mod->type;     return(0);
      case LDAPSCHEMA_FLD_FLAGS: *oi = (int)mod->flags;    return(0);

      // char * values (strings)
      case LDAPSCHEMA_FLD_OID:  return(ldapschema_get_info_model_str(os, mod->oid));
      case LDAPSCHEMA_FLD_DESC: return(ldapschema_get_info_model_str(os, mod->desc));
      case LDAPSCHEMA_FLD_DEF:  return(ldapschema_get_info_model_str(os, mod->definition));

      // char ** values (arrays of strings)

      default:
      break;
   };

   return(LDAPSCHEMA_UNKNOWN_FIELD);
}


int ldapschema_get_info_model_str(char ** os, const char * src)
{
   assert(os != NULL);
   if (!(src))
   {
      *os = NULL;
      return(0);
   };
   if ((*os = strdup(src)) == NULL)
      return(LDAPSCHEMA_NO_MEMORY);
   return(0);
}


int ldapschema_get_info_objectclass(LDAPSchema * lsd,
   const LDAPSchemaObjectclass * objcls, int field, void * outvalue )
{
   int       * oi;   // output int (flags/types/etc)
   char    *** oa;   // output char ** (array of strings)

   assert(lsd        != NULL);
   assert(objcls     != NULL);
   assert(field      != 0);
   assert(outvalue   != 0);

   oi = outvalue;
   oa = outvalue;

   switch(field)
   {
      // int values (flags/types/etc)
      case LDAPSCHEMA_FLD_KIND: *oi = (int)objcls->kind;   return(0);

      // char * values (strings)

      // char ** values (arrays of strings)
      case LDAPSCHEMA_FLD_NAME:  if ((*oa = ldapschema_value_dup(objcls->names)) == NULL) return(LDAPSCHEMA_NO_MEMORY); return(0);

      // misc
      case LDAPSCHEMA_FLD_SUPERIOR: *(LDAPSchemaObjectclass **)outvalue = objcls->sup; return(0);

      default:
      break;
   };

   return(ldapschema_get_info_model(lsd, &objcls->model, field, outvalue));
}


//----------------------//
// ldapschema_model_XXXX //
//----------------------//
#pragma mark ldapschema_model_XXXX functions

const LDAPSchemaModel * ldapschema_model_attributetype(
   const LDAPSchemaAttributeType * attr )
{
   assert(attr != NULL);
   return(&attr->model);
}

const LDAPSchemaModel * ldapschema_model_ldapsyntax(
   const LDAPSchemaSyntax * syntax )
{
   assert(syntax != NULL);
   return(&syntax->model);
}

const LDAPSchemaModel * ldapschema_model_matchingrule(
   const LDAPSchemaMatchingRule * matchingrule )
{
   assert(matchingrule != NULL);
   return(&matchingrule->model);
}

const LDAPSchemaModel * ldapschema_model_objectclass(
   const LDAPSchemaObjectclass * objcls )
{
   assert(objcls != NULL);
   return(&objcls->model);
}


//----------------------//
// ldapschema_next_XXXX //
//----------------------//
#pragma mark ldapschema_next_XXXX functions

const LDAPSchemaAttributeType * ldapschema_next_attributetype(LDAPSchema * lsd,
   LDAPSchemaCur cur)
{
   assert(lsd != NULL);
   assert(cur != NULL);

   for(cur->cursor++; (cur->cursor < lsd->oids_len); cur->cursor++)
      if (lsd->oids[cur->cursor].model->type == LDAPSCHEMA_ATTRIBUTETYPE)
         return(lsd->oids[cur->cursor].attributetype);

   return(NULL);
}


const LDAPSchemaSyntax * ldapschema_next_ldapsyntax(LDAPSchema * lsd,
   LDAPSchemaCur cur)
{
   assert(lsd != NULL);
   assert(cur != NULL);

   for(cur->cursor++; (cur->cursor < lsd->oids_len); cur->cursor++)
      if (lsd->oids[cur->cursor].model->type == LDAPSCHEMA_SYNTAX)
         return(lsd->oids[cur->cursor].syntax);

   return(NULL);
}


const LDAPSchemaMatchingRule * ldapschema_next_matchingrule(LDAPSchema * lsd,
   LDAPSchemaCur cur)
{
   assert(lsd != NULL);
   assert(cur != NULL);

   for(cur->cursor++; (cur->cursor < lsd->oids_len); cur->cursor++)
      if (lsd->oids[cur->cursor].model->type == LDAPSCHEMA_MATCHINGRULE)
         return(lsd->oids[cur->cursor].matchingrule);

   return(NULL);
}


const LDAPSchemaObjectclass * ldapschema_next_objectclass(LDAPSchema * lsd,
   LDAPSchemaCur cur)
{
   assert(lsd != NULL);
   assert(cur != NULL);

   for(cur->cursor++; (cur->cursor < lsd->oids_len); cur->cursor++)
      if (lsd->oids[cur->cursor].model->type == LDAPSCHEMA_OBJECTCLASS)
         return(lsd->oids[cur->cursor].objectclass);

   return(NULL);
}

/* end of source file */
