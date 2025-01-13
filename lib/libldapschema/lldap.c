
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
 *   @file lib/libldapschema/lldap.c  contains LDAP functions
 */
#define _LIB_LIBLDAPSCHEMA_LLDAP_C 1
#include "lldap.h"

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

#include "llexer.h"
#include "lquery.h"
#include "lerror.h"
#include "lmemory.h"
#include "lsort.h"


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

int ldapschema_fetch(LDAPSchema * lsd, LDAP * ld)
{
   int                  err;
   int                  x;
   struct timeval       timeout;
   LDAPMessage        * res;
   LDAPMessage        * msg;
   char              ** dns;
   char              ** attrs;
   struct berval     ** vals;
   void               * ptr;
   size_t               idx;
   size_t               subidx;
   LDAPSchemaAlias    * alias;
   LDAPSchemaAttributeType     * attr;
   LDAPSchemaAttributeType     * attrsup;
   LDAPSchemaObjectclass       * objcls;
   LDAPSchemaObjectclass       * objclssup;
   LDAPSchemaMatchingRule *      mtchngrl;

   assert(lsd != NULL);
   assert(ld  != NULL);

   // reset errors
   if ((lsd->schema_errs))
      ldapschema_value_free(lsd->schema_errs);
   lsd->schema_errs     = NULL;

   attrs = NULL;
   if ((err = ldapschema_definition_split(lsd, NULL, "( + * )", 7, &attrs)) == -1)
      return(lsd->errcode);

   // searches for schema DN
   timeout.tv_sec    = 5;
   timeout.tv_usec   = 0;
   res               = NULL;
   if ((err = ldap_search_ext_s(ld, "", LDAP_SCOPE_BASE, "(objectclass=*)", attrs, 0, NULL, NULL, &timeout, 0, &res)) != LDAP_SUCCESS)
   {
      ldapschema_value_free(attrs);
      return(err);
   };
   if ((msg = ldap_first_entry(ld, res)) == NULL)
   {
      ldap_msgfree(res);
      return(-1);
   };
   if ((dns = ldap_get_values(ld, msg, "subschemaSubentry")) == NULL)
   {
      ldap_msgfree(res);
      ldap_value_free(dns);
      return(-1);
   };
   ldap_msgfree(res);

   // searches for schema entry
   timeout.tv_sec    = 5;
   timeout.tv_usec   = 0;
   res               = NULL;
   if ((err = ldap_search_ext_s(ld, dns[0], LDAP_SCOPE_BASE, "(objectclass=*)", attrs, 0, NULL, NULL, &timeout, 0, &res)) != LDAP_SUCCESS)
   {
      ldap_value_free(dns);
      ldapschema_value_free(attrs);
      return(-1);
   };
   ldap_value_free(dns);
   ldapschema_value_free(attrs);
   dns   = NULL;
   attrs = NULL;
   if ((msg = ldap_first_entry(ld, res)) == NULL)
   {
      ldap_msgfree(res);
      return(-1);
   };

   // process ldapSyntaxes
   if ((vals = ldap_get_values_len(ld, msg, "ldapSyntaxes")) != NULL)
   {
      for(x = 0; ((vals[x])); x++)
      {
         if ( ((ptr = ldapschema_parse_syntax(lsd, vals[x])) == NULL) &&
              (lsd->errcode != LDAPSCHEMA_SCHEMA_ERROR) )
         {
            ldaputils_value_free_len(vals);
            ldap_msgfree(res);
            return(-1);
         };
      };
      ldaputils_value_free_len(vals);
   };

   // process matchingRule
   if ((vals = ldap_get_values_len(ld, msg, "matchingRules")) != NULL)
   {
      for(x = 0; ((vals[x])); x++)
      {
         if ( ((ptr = ldapschema_parse_matchingrule(lsd, vals[x])) == NULL) &&
              (lsd->errcode != LDAPSCHEMA_SCHEMA_ERROR) )
         {
            ldaputils_value_free_len(vals);
            ldap_msgfree(res);
            return(-1);
         };
      };
      ldaputils_value_free_len(vals);

      // checks attribute
       for(idx = 0; (idx < lsd->oids_len); idx++)
       {
          mtchngrl = lsd->oids[idx].matchingrule;
          if (mtchngrl->model.type != LDAPSCHEMA_MATCHINGRULE)
             continue;

          if (!(mtchngrl->names))
             ldapschema_schema_err(lsd, (LDAPSchemaModel *)mtchngrl, "missing NAME");

          if (!(mtchngrl->syntax))
             ldapschema_schema_err(lsd, (LDAPSchemaModel *)mtchngrl, "missing or unknown SYNTAX");
       };
   };

   // process attributeTypes
   if ((vals = ldap_get_values_len(ld, msg, "attributeTypes")) != NULL)
   {
      // initial parsing of definition
      for(x = 0; ((vals[x])); x++)
      {
         if ( ((ptr = ldapschema_parse_attributetype(lsd, vals[x])) == NULL) &&
              (lsd->errcode != LDAPSCHEMA_SCHEMA_ERROR) )
         {
            ldaputils_value_free_len(vals);
            ldap_msgfree(res);
            return(-1);
         };
      };
      ldaputils_value_free_len(vals);

      // maps superior
      for(idx = 0; (idx < lsd->oids_len); idx++)
      {
         // checks for superior
         attr = lsd->oids[idx].attributetype;
         if (attr->model.type != LDAPSCHEMA_ATTRIBUTETYPE)
            continue;
         if (!(attr->sup_name))
            continue;
         if ((alias = ldapschema_find_alias(lsd, attr->sup_name, lsd->attrs, lsd->attrs_len)) == NULL)
         {
            ldapschema_schema_err(lsd, &attr->model, "specifies invalid superior '%s'", attr->sup_name);
            continue;
         };

         // saves superior
         attr->sup = alias->attributetype;

         // inherent specs from superior
         attrsup   = attr;
         while((attrsup = attrsup->sup) != NULL)
         {
            attr->model.flags |= attrsup->model.flags;
            if (!(attr->syntax))
               if ((attr->syntax = attrsup->syntax) != NULL)
                  ldapschema_insert(lsd, (void ***)&attr->syntax->attrs, &attr->syntax->attrs_len, attr, ldapschema_compar_models);
            if (!(attr->min_upper))
               attr->min_upper = attrsup->min_upper;
            if (!(attr->usage))
               attr->usage = attrsup->usage;
            if (!(attr->equality))
               if ((attr->equality = attrsup->equality) != NULL)
                  ldapschema_insert(lsd, (void ***)&attr->equality->used_by, &attr->equality->used_by_len, attr, ldapschema_compar_models);
            if (!(attr->ordering))
               if ((attr->ordering = attrsup->ordering) != NULL)
                  ldapschema_insert(lsd, (void ***)&attr->ordering->used_by, &attr->ordering->used_by_len, attr, ldapschema_compar_models);
            if (!(attr->substr))
               if ((attr->substr = attrsup->substr) != NULL)
                  ldapschema_insert(lsd, (void ***)&attr->substr->used_by, &attr->substr->used_by_len, attr, ldapschema_compar_models);
         };
      };

      // checks attribute
      for(idx = 0; (idx < lsd->oids_len); idx++)
      {
         attr = lsd->oids[idx].attributetype;
         if (attr->model.type != LDAPSCHEMA_ATTRIBUTETYPE)
            continue;

         if (!(attr->syntax))
            ldapschema_schema_err(lsd, (LDAPSchemaModel *)attr, "missing or unknown SYNTAX");
      };
   };

   // process objectClasses
   if ((vals = ldap_get_values_len(ld, msg, "objectClasses")) != NULL)
   {
      // initial parsing of definition
      for(x = 0; ((vals[x])); x++)
      {
         if ( ((ptr = ldapschema_parse_objectclass(lsd, vals[x])) == NULL) &&
              (lsd->errcode != LDAPSCHEMA_SCHEMA_ERROR) )
         {
            ldaputils_value_free_len(vals);
            ldap_msgfree(res);
            return(-1);
         };
      };
      ldaputils_value_free_len(vals);

      // maps superior
      for(idx = 0; (idx < lsd->oids_len); idx++)
      {
         // checks for superior
         objcls = lsd->oids[idx].objectclass;
         if (objcls->model.type != LDAPSCHEMA_OBJECTCLASS)
            continue;
         if (!(objcls->sup_name))
            continue;
         if ((alias = ldapschema_find_alias(lsd, objcls->sup_name, lsd->objclses, lsd->objclses_len)) == NULL)
         {
            ldapschema_schema_err(lsd, &objcls->model, "specifies invalid superior '%s'", objcls->sup_name);
            continue;
         };

         // saves superior
         objcls->sup = alias->objectclass;

         // inherent specs from superior
         objclssup   = objcls;
         while((objclssup = objclssup->sup) != NULL)
         {
            objcls->model.flags |= objclssup->model.flags;
            if (!(objcls->kind))
               objcls->kind = objclssup->kind;
            for(subidx = 0; (subidx < objclssup->may_len); subidx++)
            {
               if ((err = ldapschema_objectclass_attribute(lsd, objcls, objclssup->may[subidx], 0, 1)) > 0)
               {
                  ldaputils_value_free_len(vals);
                  ldap_msgfree(res);
                  return(lsd->errcode);
               };
            };
            for(subidx = 0; (subidx < objclssup->must_len); subidx++)
            {
               if ((err = ldapschema_objectclass_attribute(lsd, objcls, objclssup->must[subidx], 1, 1)) > 0)
               {
                  ldaputils_value_free_len(vals);
                  ldap_msgfree(res);
                  return(lsd->errcode);
               };
            };
         };
      };
   };

   ldap_msgfree(res);

   if ((lsd->schema_errs))
      return(lsd->errcode = LDAPSCHEMA_SCHEMA_ERROR);
   return(LDAP_SUCCESS);
}

/* end of source file */
