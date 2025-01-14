
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
*   @file lib/libldapschema/loutput.c  contains output functions
*/
#define _LIB_LIBLDAPSCHEMA_LOUTPUT_C 1
#include "loutput.h"

///////////////
//           //
//  Headers  //
//           //
///////////////
// MARK: - Headers

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>

#include "lspec.h"


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
// MARK: - Definitions

#define LDAPSCHEMA_WIDTH_HEADER    19
#define LDAPSCHEMA_WIDTH_INDENT    3
#define LDAPSCHEMA_WIDTH_FIELD     (LDAPSCHEMA_WIDTH_HEADER-LDAPSCHEMA_WIDTH_INDENT)
#define LDAPSCHEMA_WIDTH_VALUE      59


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
// MARK: - Prototypes

static void
ldapschema_print_data_class(
         LDAPSchema *                  lsd,
         size_t                        classid );


static void
ldapschema_print_definition(
         LDAPSchema *                  lsd,
         LDAPSchemaModel *             model );


static void
ldapschema_print_extensions(
         LDAPSchema *                  lsd,
         LDAPSchemaModel *             model );


static void
ldapschema_print_flags(
         LDAPSchema *                  lsd,
         LDAPSchemaModel *             model );


static void
ldapschema_print_issues(
         LDAPSchema *                  lsd,
         LDAPSchemaModel *             model );


static void
ldapschema_print_line(
         const char *                  field,
         const char *                  input );


static void
ldapschema_print_list(
         const char *                  field,
         char **                       vals );


static void
ldapschema_print_list_models(
         LDAPSchema *                  lsd,
         const char *                  name,
         LDAPSchemaModel   **          list,
         size_t                        list_len );


static void
ldapschema_print_unsigned(
         const char *                  field,
         uintmax_t                     u );


static void
ldapschema_print_obj_attributetype(
         LDAPSchema *                  lsd,
         LDAPSchemaAttributeType *     attr );


static void
ldapschema_print_obj_matchingrule(
         LDAPSchema *                  lsd,
         LDAPSchemaMatchingRule *      mtchngrl );


static void
ldapschema_print_obj_model(
         LDAPSchema *                  lsd,
         LDAPSchemaModel *             model );


static void
ldapschema_print_obj_objectclass(
         LDAPSchema *                  lsd,
         LDAPSchemaObjectclass *       objcls );


static void
ldapschema_print_obj_syntax(
         LDAPSchema *                  lsd,
         LDAPSchemaSyntax *            syntax );


static void
ldapschema_print_spec(
         LDAPSchema *                  lsd,
         const LDAPSchemaSpec *        spec );


static void
ldapschema_print_type(
         LDAPSchema *                  lsd,
         LDAPSchemaModel *             model );


/////////////////
//             //
//  Functions  //
//             //
/////////////////
// MARK: - Functions

void
ldapschema_print(
         LDAPSchema *                  lsd,
         LDAPSchemaModel *             mod )
{
   assert(lsd != NULL);
   assert(mod != NULL);
   switch(mod->type)
   {
      case LDAPSCHEMA_ATTRIBUTETYPE:
      if (mod->size != sizeof(LDAPSchemaAttributeType))
         return;
      ldapschema_print_obj_attributetype(lsd, (LDAPSchemaAttributeType *)mod);
      return;

      case LDAPSCHEMA_MATCHINGRULE:
      if (mod->size != sizeof(LDAPSchemaMatchingRule))
         return;
      ldapschema_print_obj_matchingrule(lsd, (LDAPSchemaMatchingRule *)mod);
      return;

      case LDAPSCHEMA_OBJECTCLASS:
      if (mod->size != sizeof(LDAPSchemaObjectclass))
         return;
      ldapschema_print_obj_objectclass(lsd, (LDAPSchemaObjectclass *)mod);
      return;

      case LDAPSCHEMA_SYNTAX:
      if (mod->size != sizeof(LDAPSchemaSyntax))
         return;
      ldapschema_print_obj_syntax(lsd, (LDAPSchemaSyntax *)mod);
      return;

      default:
      break;
   };
   ldapschema_print_obj_model(lsd, mod);
   return;
}


void
ldapschema_printall(
         LDAPSchema *                  lsd,
         int                           type )
{
   size_t x;

   assert(lsd != NULL);

   for(x = 0; x < lsd->oids_len; x++)
   {
      if ((type))
         if (lsd->oids[x].model->type != (size_t)type)
            continue;
      ldapschema_print(lsd, lsd->oids[x].model);
      printf("\n");
   };

   return;
}


void
ldapschema_print_data_class(
         LDAPSchema *                  lsd,
         size_t                        classid )
{
   const char * data_class;

   assert(lsd != NULL);

   switch(classid)
   {
      case LDAPSCHEMA_CLASS_ASCII:           data_class = "ASCII";         break;
      case LDAPSCHEMA_CLASS_UTF8:            data_class = "UTF8";          break;
      case LDAPSCHEMA_CLASS_INTEGER:         data_class = "integer";       break;
      case LDAPSCHEMA_CLASS_UNSIGNED:        data_class = "unsigned";      break;
      case LDAPSCHEMA_CLASS_BOOLEAN:         data_class = "boolean";       break;
      case LDAPSCHEMA_CLASS_DATA:            data_class = "binary data";   break;
      case LDAPSCHEMA_CLASS_IMAGE:           data_class = "image";         break;
      case LDAPSCHEMA_CLASS_AUDIO:           data_class = "audio";         break;
      case LDAPSCHEMA_CLASS_UTF8_MULTILINE:  data_class = "audio";         break;
      default:
      return;
   };

   printf("%*s%-*s %s\n", LDAPSCHEMA_WIDTH_INDENT, "", LDAPSCHEMA_WIDTH_FIELD, "data class:", data_class);

   return;
}


void
ldapschema_print_definition(
         LDAPSchema *                  lsd,
         LDAPSchemaModel *             model )
{
   char           buff[4096];
   const char *   def;
   const char *   name;

   assert(lsd   != NULL);
   assert(model != NULL);

   name = "definition:";
   if ((def = model->definition) == NULL)
   {
      name = "spec definition:";
      ldapschema_print_line("definition:", "<not defined by server>");
      if ((def = model->spec->def) == NULL)
      return;
   };

   ldapschema_fmt_definition(buff, sizeof(buff), def, LDAPSCHEMA_WIDTH_VALUE);
   ldapschema_print_line(name, buff);

   return;
}


void
ldapschema_print_extensions(
         LDAPSchema *                  lsd,
         LDAPSchemaModel *             model )
{
   size_t                  x;
   size_t                  y;
   int                     len;
   int                     max;
   LDAPSchemaExtension *   ext;

   assert(lsd   != NULL);
   assert(model != NULL);

   if (model->extensions_len < 1)
      return;

   printf("%*s%-*s ", LDAPSCHEMA_WIDTH_INDENT, "", LDAPSCHEMA_WIDTH_FIELD, "extensions:");
   max = 0;
   for(x = 0; x < model->extensions_len; x++)
      if ((len = (int)strlen(model->extensions[x]->extension)) > max)
         max = len;
   for(x = 0; x < model->extensions_len; x++)
   {
      if (x > 0)
         printf("%*s ", LDAPSCHEMA_WIDTH_HEADER, "");
      ext = model->extensions[x];
      printf("%-*s (", max, ext->extension);
      for(y = 0; y < ext->values_len; y++)
         printf(" '%s'", ext->values[y]);
      printf(" )\n");
   };

   return;
}


void
ldapschema_print_flags(
         LDAPSchema *                  lsd,
         LDAPSchemaModel *             model )
{
   assert(lsd   != NULL);
   assert(model != NULL);

   if ((model->flags & LDAPSCHEMA_O_OBSOLETE))
      printf("%*s%-*s %s\n", LDAPSCHEMA_WIDTH_INDENT, "", LDAPSCHEMA_WIDTH_FIELD, "obsolete:", "yes");

   if ((model->flags & LDAPSCHEMA_O_SINGLEVALUE))
      printf("%*s%-*s %s\n", LDAPSCHEMA_WIDTH_INDENT, "", LDAPSCHEMA_WIDTH_FIELD, "single value:", "yes");

   if ((model->flags & LDAPSCHEMA_O_READABLE))
      printf("%*s%-*s %s\n", LDAPSCHEMA_WIDTH_INDENT, "", LDAPSCHEMA_WIDTH_FIELD, "readable:", "yes");

   if ((model->flags & LDAPSCHEMA_O_COLLECTIVE))
      printf("%*s%-*s %s\n", LDAPSCHEMA_WIDTH_INDENT, "", LDAPSCHEMA_WIDTH_FIELD, "collective:", "yes");

   if ((model->flags & LDAPSCHEMA_O_NO_USER_MOD))
      printf("%*s%-*s %s\n", LDAPSCHEMA_WIDTH_INDENT, "", LDAPSCHEMA_WIDTH_FIELD, "no user mod:", "yes");

   return;
}


void
ldapschema_print_issues(
         LDAPSchema *                  lsd,
         LDAPSchemaModel *             model )
{
   size_t idx;
   assert(lsd   != NULL);
   assert(model != NULL);
   if (!(model->errors))
      return;
   for(idx = 0; ((model->errors[idx])); idx++)
      ldapschema_print_line( ((!(idx))?"issues:":NULL), model->errors[idx]);
   return;
}


void
ldapschema_print_line(
         const char *                  field,
         const char *                  str )
{
   const char *   bol;
   const char *   eol;

   if (!(field))
      field = "";

   if (!(str))
      return;

   bol = str;
   while((eol = strchr(bol, '\n')) != NULL)
   {
      if (bol == str)
         printf("%*s%-*s %.*s\n", LDAPSCHEMA_WIDTH_INDENT, "", LDAPSCHEMA_WIDTH_FIELD, field, (int)(eol-bol), str);
      else
         printf("%*s %.*s\n", LDAPSCHEMA_WIDTH_HEADER, "", (int)(eol-bol), bol);
      bol = &eol[1];
   };
   if (bol == str)
      printf("%*s%-*s %.*s\n", LDAPSCHEMA_WIDTH_INDENT, "", LDAPSCHEMA_WIDTH_FIELD, field, (int)(eol-bol), str);
   else if ((strlen(bol)))
      printf("%*s %.*s\n", LDAPSCHEMA_WIDTH_HEADER, "", (int)(eol-bol), bol);

   return;
}


void
ldapschema_print_list(
         const char *                  field,
         char **                       vals )
{
   size_t idx;

   if (!(vals))
      return;

   for(idx = 0; ((vals[idx])); idx++)
      ldapschema_print_line( ((!(idx))?field:""), vals[idx]);

   return;
}


void
ldapschema_print_list_models(
         LDAPSchema *                  lsd,
         const char *                  name,
         LDAPSchemaModel **            list,
         size_t                        list_len )
{
   size_t            pos;
   const char *      key;
   size_t            key_len;
   size_t            buff_len;
   char              buff[256];
   size_t            lineno;

   assert(lsd != NULL);
   assert(name != NULL);
   if ( (!(list)) || (!(list_len)) )
      return;

   lineno   = 0;
   buff_len = 0;
   buff[0]  = '\0';

   for(pos = 0; (pos < list_len); pos++)
   {
      key = NULL;
      switch(list[pos]->type)
      {
         case LDAPSCHEMA_ATTRIBUTETYPE:
         if ((((LDAPSchemaAttributeType *)list[pos])->names))
            key = ((LDAPSchemaAttributeType *)list[pos])->names[0];
         break;

         case LDAPSCHEMA_MATCHINGRULE:
         if ((((LDAPSchemaMatchingRule *)list[pos])->names))
            key = ((LDAPSchemaMatchingRule *)list[pos])->names[0];
         break;

         case LDAPSCHEMA_OBJECTCLASS:
         if ((((LDAPSchemaObjectclass *)list[pos])->names))
            key = ((LDAPSchemaObjectclass *)list[pos])->names[0];
         break;

         case LDAPSCHEMA_SYNTAX:
         if ((((LDAPSchemaSyntax *)list[pos])->model.desc))
            key = ((LDAPSchemaSyntax *)list[pos])->model.desc;
         break;

         default:
         key = list[pos]->desc;
         break;
      };
      if (!(key))
         key = list[pos]->oid;
      if (!(key))
         continue;

      key_len = strlen(key) + 1;
      if ( ((buff_len)) && ((buff_len+key_len) > LDAPSCHEMA_WIDTH_VALUE) )
      {
         if (buff[buff_len-1] == ' ')
            buff[buff_len-1] = '\0';
         ldapschema_print_line( ((!(lineno)) ? name : NULL), buff);
         buff_len = 0;
         buff[0]  = '\0';
         lineno++;
      };

      if ((pos + 1) < list_len)
         buff_len += (size_t)snprintf(&buff[buff_len], sizeof(buff)-buff_len, "%s, ", key );
      else
         buff_len += (size_t)snprintf(&buff[buff_len], sizeof(buff)-buff_len, "%s", key );
   };
   if ((buff_len))
      ldapschema_print_line( ((!(lineno))?name:NULL), buff);

   return;
}


void
ldapschema_print_obj_attributetype(
         LDAPSchema *                  lsd,
         LDAPSchemaAttributeType *     attr )
{
   const char *               str;
   LDAPSchemaAttributeType *  sup;
   size_t                     flags;
   char                       buff[256];
   LDAPSchemaSyntax *         syntax;
   LDAPSchemaMatchingRule *   mtchngrl;

   assert(lsd  != NULL);
   assert(attr != NULL);

   ldapschema_print_type(lsd, &attr->model);
   ldapschema_print_list("name(s):",     attr->names);
   ldapschema_print_line("description:", attr->model.desc);
   ldapschema_print_flags(lsd, &attr->model);

   switch(attr->usage)
   {
      case 0: // assume LDAPSCHEMA_USER_APP if value is not set
      case LDAPSCHEMA_USER_APP:        str = "userApplications";     break;
      case LDAPSCHEMA_DIRECTORY_OP:    str = "directoryOperation";   break;
      case LDAPSCHEMA_DISTRIBUTED_OP:  str = "distributedOperation"; break;
      case LDAPSCHEMA_DSA_OP:          str = "dSAOperation";         break;
      default:                         str = "unknown:";             break;
   };
   ldapschema_print_line("usage:", str);

   if ((sup = attr->sup) != NULL)
   {
      ldapschema_print_line("superior(s):", (((sup->names))?sup->names[0]:sup->model.oid)  );
      while ((sup = sup->sup) != NULL)
         ldapschema_print_line(NULL, (((sup->names))?sup->names[0]:sup->model.oid)  );
   };

   ldapschema_print_spec(lsd, attr->model.spec);

   if ((mtchngrl = attr->equality) != NULL)
      ldapschema_print_line("equality:", ((mtchngrl->names)) ? mtchngrl->names[0] : mtchngrl->model.oid);
   if ((mtchngrl = attr->ordering) != NULL)
      ldapschema_print_line("ordering:", ((mtchngrl->names)) ? mtchngrl->names[0] : mtchngrl->model.oid);
   if ((mtchngrl = attr->substr) != NULL)
      ldapschema_print_line("substr:", ((mtchngrl->names)) ? mtchngrl->names[0] : mtchngrl->model.oid);

   // print syntax information
   ldapschema_print_unsigned("min upper bound:", attr->min_upper);
   if ((syntax = attr->syntax)  != NULL)
   {
      // syntax OID/desc
      if ((syntax->model.desc))
         snprintf(buff, sizeof(buff), "%s ( %s )", syntax->model.oid, syntax->model.desc);
      else
         snprintf(buff, sizeof(buff), "%s", syntax->model.oid);
      ldapschema_print_line("syntax:", buff);

      ldapschema_print_data_class(lsd, syntax->data_class);

      flags = (size_t)syntax->model.flags;
      ldapschema_print_line("common abnf:", ((flags & LDAPSCHEMA_O_COMMON_ABNF) != 0) ? "yes" : "no");
      ldapschema_print_line("schema abnf:", ((flags & LDAPSCHEMA_O_SCHEMA_ABNF) != 0) ? "yes" : "no");
      ldapschema_print_line("abnf:",        ((!(syntax->model.spec)) ? NULL : syntax->model.spec->abnf));
   };

   ldapschema_print_extensions(lsd, &attr->model);
   ldapschema_print_list_models(lsd, "required by:", (LDAPSchemaModel **)attr->required_by, attr->required_by_len);
   ldapschema_print_list_models(lsd, "allowed by:",  (LDAPSchemaModel **)attr->allowed_by, attr->allowed_by_len);
   ldapschema_print_definition(lsd, &attr->model);
   ldapschema_print_issues(lsd, &attr->model);

   return;
}


void
ldapschema_print_obj_matchingrule(
         LDAPSchema *                  lsd,
         LDAPSchemaMatchingRule *      mtchngrl )
{
   char buff[256];

   assert(lsd        != NULL);
   assert(mtchngrl   != NULL);

   ldapschema_print_type(lsd, &mtchngrl->model);
   ldapschema_print_list("name(s):",     mtchngrl->names);
   ldapschema_print_line("description:", mtchngrl->model.desc);
   ldapschema_print_flags(lsd, &mtchngrl->model);

   if ((mtchngrl->syntax))
   {
      if ((mtchngrl->syntax->model.desc))
         snprintf(buff, sizeof(buff), "%s ( %s )", mtchngrl->syntax->model.oid, mtchngrl->syntax->model.desc);
   else
         snprintf(buff, sizeof(buff), "%s", mtchngrl->syntax->model.oid);
      ldapschema_print_line("syntax:", buff);
   };

   ldapschema_print_list_models(lsd, "used by:",  (LDAPSchemaModel **)mtchngrl->used_by, mtchngrl->used_by_len);
   ldapschema_print_extensions(lsd, &mtchngrl->model);
   ldapschema_print_definition(lsd, &mtchngrl->model);
   ldapschema_print_issues(lsd, &mtchngrl->model);

   return;
}


void
ldapschema_print_obj_model(
         LDAPSchema *                  lsd,
         LDAPSchemaModel *             model )
{
   assert(lsd   != NULL);
   assert(model != NULL);

   ldapschema_print_type(lsd, model);
   ldapschema_print_line("description:", model->desc);
   ldapschema_print_flags(lsd, model);
   ldapschema_print_extensions(lsd, model);
   ldapschema_print_definition(lsd, model);
   ldapschema_print_spec(lsd, model->spec);

   return;
}


void
ldapschema_print_obj_objectclass(
         LDAPSchema *                  lsd,
         LDAPSchemaObjectclass *       objcls )
{
   const char *               str;
   LDAPSchemaObjectclass *    sup;

   assert(lsd    != NULL);
   assert(objcls != NULL);

   ldapschema_print_type(lsd, &objcls->model);
   ldapschema_print_list("name(s):",     objcls->names);
   ldapschema_print_line("description:", objcls->model.desc);
   ldapschema_print_flags(lsd, &objcls->model);

   switch(objcls->kind)
   {
      case LDAPSCHEMA_STRUCTURAL:      str = "structural";  break;
      case LDAPSCHEMA_AUXILIARY:       str = "auxiliary";   break;
      case LDAPSCHEMA_ABSTRACT:        str = "abstract";    break;
      default:                         str = "unknown:";    break;
   };
   ldapschema_print_line("usage:", str);

   if ((sup = objcls->sup) != NULL)
   {
      ldapschema_print_line("superior(s):", (((sup->names))?sup->names[0]:sup->model.oid)  );
      while ((sup = sup->sup) != NULL)
         ldapschema_print_line(NULL, (((sup->names))?sup->names[0]:sup->model.oid)  );
   };

   ldapschema_print_list_models(lsd, "may:",             (LDAPSchemaModel **)objcls->may,          objcls->may_len);
   ldapschema_print_list_models(lsd, "must:",            (LDAPSchemaModel **)objcls->must,         objcls->must_len);
   ldapschema_print_list_models(lsd, "inherited may:",   (LDAPSchemaModel **)objcls->inherit_may,  objcls->inherit_may_len);
   ldapschema_print_list_models(lsd, "inherited must:",  (LDAPSchemaModel **)objcls->inherit_must, objcls->inherit_must_len);
   ldapschema_print_extensions(lsd, &objcls->model);
   ldapschema_print_definition(lsd, &objcls->model);
   ldapschema_print_issues(lsd, &objcls->model);

   return;
}


void
ldapschema_print_obj_syntax(
         LDAPSchema *                  lsd,
         LDAPSchemaSyntax *            syntax )
{
   assert(lsd    != NULL);
   assert(syntax != NULL);

   ldapschema_print_type(lsd, &syntax->model);
   ldapschema_print_line("description:", syntax->model.desc);
   ldapschema_print_data_class(lsd, syntax->data_class);
   ldapschema_print_flags(lsd, &syntax->model);
   ldapschema_print_extensions(lsd, &syntax->model);
   ldapschema_print_list_models(lsd, "matchingRules:",   (LDAPSchemaModel **)syntax->mtchngrls, syntax->mtchngrls_len);
   ldapschema_print_list_models(lsd, "used by:",  (LDAPSchemaModel **)syntax->attrs,     syntax->attrs_len);
   ldapschema_print_spec(lsd, syntax->model.spec);
   ldapschema_print_definition(lsd, &syntax->model);
   ldapschema_print_issues(lsd, &syntax->model);

   return;
}


void
ldapschema_print_spec(
         LDAPSchema *                  lsd,
         const LDAPSchemaSpec *        spec )
{
   assert(lsd != NULL);
   if (!(spec))
      return;
   ldapschema_print_line("spec name:",     spec->spec);
   ldapschema_print_line("spec chapter:",  spec->spec_section);
   ldapschema_print_line("spec vendor:",   spec->spec_vendor);
   ldapschema_print_line("spec source:",   spec->spec_source);
   ldapschema_print_line("spec text:",     spec->spec_text);
   ldapschema_print_line("spec notes:",    spec->notes);
   ldapschema_print_line("common abnf:",   ((spec->flags & LDAPSCHEMA_O_COMMON_ABNF) != 0) ? "yes" : "no");
   ldapschema_print_line("schema abnf:",   ((spec->flags & LDAPSCHEMA_O_SCHEMA_ABNF) != 0) ? "yes" : "no");
   ldapschema_print_line("abnf:",          spec->abnf);
   return;
}


void
ldapschema_print_type(
         LDAPSchema *                  lsd,
         LDAPSchemaModel *             model )
{
   const char * str;
   assert(lsd   != NULL);
   assert(model != NULL);
   switch(model->type)
   {
      case LDAPSCHEMA_ATTRIBUTETYPE: str = "attributeType:"; break;
      case LDAPSCHEMA_MATCHINGRULE:  str = "matchingRule:"; break;
      case LDAPSCHEMA_OBJECTCLASS:   str = "objectClass:"; break;
      case LDAPSCHEMA_SYNTAX:        str = "ldapSyntax:"; break;
      default:                       str = "unknown:"; break;
   };
   printf("%-*s %s\n", LDAPSCHEMA_WIDTH_HEADER, str, model->oid);
   return;
}


void
ldapschema_print_unsigned(
         const char *                  field,
         uintmax_t                     u )
{
   if (!(u))
      return;
   if ((field))   printf("%*s%-*s %ju\n", LDAPSCHEMA_WIDTH_INDENT, "", LDAPSCHEMA_WIDTH_FIELD, field, u);
   else           printf("%*s %ju\n", LDAPSCHEMA_WIDTH_HEADER, "", u);
   return;
}

/* end of source file */
