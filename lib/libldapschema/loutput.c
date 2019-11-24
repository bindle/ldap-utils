
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
*   @file src/ldapschema/loutput.c  contains output functions
*/
#define _LIB_LIBLDAPSCHEMA_LOUTPUT_C 1
#include "loutput.h"

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


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#pragma mark - Definitions

#define LDAPSCHEMA_WIDTH_HEADER    19
#define LDAPSCHEMA_WIDTH_INDENT    3
#define LDAPSCHEMA_WIDTH_FIELD     (LDAPSCHEMA_WIDTH_HEADER-LDAPSCHEMA_WIDTH_INDENT)


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

void
ldapschema_print_attributetype_objcls(
         LDAPSchema               * lsd,
         const char               * name,
         LDAPSchemaObjectclass   ** list,
         size_t                     len );

void
ldapschema_print_model_def(
         LDAPSchema            * lsd,
         LDAPSchemaModel       * model );

void
ldapschema_print_model_ext(
         LDAPSchema            * lsd,
         LDAPSchemaModel       * model );

void
ldapschema_print_model_flags(
         LDAPSchema            * lsd,
         LDAPSchemaModel       * model );

void
ldapschema_print_model_type(
         LDAPSchema            * lsd,
         LDAPSchemaModel       * model );

void
ldapschema_print_multiline(
         const char            * field,
         const char            * input );

void
ldapschema_print_ldapsyntax_class(
         LDAPSchema            * lsd,
         size_t                  classid );

void
ldapschema_print_spec(
         LDAPSchema            * lsd,
         const LDAPSchemaSpec  * spec );


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

void ldapschema_print_attributetype( LDAPSchema * lsd, LDAPSchemaAttributeType * attr )
{
   size_t                     x;
   const char               * str;
   LDAPSchemaAttributeType  * sup;
   size_t                     flags;

   assert(lsd  != NULL);
   assert(attr != NULL);

   ldapschema_print_model_type(lsd, &attr->model);

   for(x = 0; x < attr->names_len; x++)
   {
      if (x == 0)
         printf("%*s%-*s %s\n", LDAPSCHEMA_WIDTH_INDENT, "", LDAPSCHEMA_WIDTH_FIELD, "name(s):", attr->names[x]);
      else
         printf("%*s %s\n", LDAPSCHEMA_WIDTH_HEADER, "", attr->names[x]);
   };

   ldapschema_print_multiline("description:", attr->model.desc);
   ldapschema_print_model_flags(lsd, &attr->model);

   switch(attr->usage)
   {
      case LDAPSCHEMA_USER_APP:        str = "userApplications";     break;
      case LDAPSCHEMA_DIRECTORY_OP:    str = "directoryOperation";   break;
      case LDAPSCHEMA_DISTRIBUTED_OP:  str = "distributedOperation"; break;
      case LDAPSCHEMA_DSA_OP:          str = "dSAOperation";         break;
      default:                         str = "unknown:";             break;
   };
   printf("%*s%-*s %s\n", LDAPSCHEMA_WIDTH_INDENT, "", LDAPSCHEMA_WIDTH_FIELD, "usage:", str);

   if ((sup = attr->sup) != NULL)
   {
      printf("%*s%-*s %s\n", LDAPSCHEMA_WIDTH_INDENT, "", LDAPSCHEMA_WIDTH_FIELD, "superior(s):", (((sup->names))?sup->names[0]:sup->model.oid) );
      while ((sup = sup->sup) != NULL)
         printf("%*s %s\n", LDAPSCHEMA_WIDTH_HEADER, "", (((sup->names))?sup->names[0]:sup->model.oid));
   };

   ldapschema_print_spec(lsd, attr->model.spec);

   if ((attr->syntax))
   {
      if ((attr->syntax->model.desc))
         printf("%*s%-*s %s  ( %s )\n", LDAPSCHEMA_WIDTH_INDENT, "", LDAPSCHEMA_WIDTH_FIELD, "syntax:", attr->syntax->model.oid, attr->syntax->model.desc);
      else
         printf("%*s%-*s %s\n", LDAPSCHEMA_WIDTH_INDENT, "", LDAPSCHEMA_WIDTH_FIELD, "syntax:", attr->syntax->model.oid);
      if ((attr->min_upper))
         printf("%*s%-*s %zu\n", LDAPSCHEMA_WIDTH_INDENT, "", LDAPSCHEMA_WIDTH_FIELD, "min upper bound:", attr->min_upper);
      ldapschema_print_ldapsyntax_class(lsd, attr->syntax->data_class);
      if ( ((attr->syntax->model.spec)) && ((attr->syntax->model.spec->abnf)) )
      {
         flags = (size_t)attr->syntax->model.spec->flags;
         printf("%*s%-*s %s\n", LDAPSCHEMA_WIDTH_INDENT, "", LDAPSCHEMA_WIDTH_FIELD, "common abnf:",  ((flags & LDAPSCHEMA_O_COMMON_ABNF) != 0) ? "yes" : "no");
         printf("%*s%-*s %s\n", LDAPSCHEMA_WIDTH_INDENT, "", LDAPSCHEMA_WIDTH_FIELD, "schema abnf:",  ((flags & LDAPSCHEMA_O_SCHEMA_ABNF) != 0) ? "yes" : "no");
         ldapschema_print_multiline("abnf:", attr->syntax->model.spec->abnf);
      };
   } else if ((attr->min_upper))
   {
      printf("%*s%-*s %zu\n", LDAPSCHEMA_WIDTH_INDENT, "", LDAPSCHEMA_WIDTH_FIELD, "min upper bound:", attr->min_upper);
   };
   ldapschema_print_model_ext(lsd, &attr->model);
   ldapschema_print_attributetype_objcls(lsd, "required by:", attr->required_by, attr->required_by_len);
   ldapschema_print_attributetype_objcls(lsd, "allowed by:",  attr->allowed_by,  attr->allowed_by_len);
   ldapschema_print_model_def(lsd, &attr->model);

   return;
}


void ldapschema_print_attributetype_objcls(LDAPSchema * lsd,
   const char * name, LDAPSchemaObjectclass ** list, size_t len)
{
   size_t pos;

   assert(lsd != NULL);

   if ( (!(list)) || (!(len)) )
      return;

   if ((list[0]->names))
      printf("%*s%-*s %s\n", LDAPSCHEMA_WIDTH_INDENT, "", LDAPSCHEMA_WIDTH_FIELD, name, list[0]->names[0]);
   else
      printf("%*s%-*s %s\n", LDAPSCHEMA_WIDTH_INDENT, "", LDAPSCHEMA_WIDTH_FIELD, name, list[0]->model.oid);

   for(pos = 1; (pos < len); pos++)
   {
      if ((list[pos]->names))
         printf("%*s %s\n", LDAPSCHEMA_WIDTH_HEADER, "", list[pos]->names[0]);
      else
         printf("%*s %s\n", LDAPSCHEMA_WIDTH_HEADER, "", list[pos]->model.oid);
   };

   return;
}



void ldapschema_print_attributetypes( LDAPSchema * lsd )
{
   size_t x;
   assert(lsd != NULL);
   for(x = 0; x < lsd->oids_len; x++)
   {
      if (lsd->oids[x].model->type == LDAPSCHEMA_ATTRIBUTETYPE)
      {
         ldapschema_print_attributetype(lsd, lsd->oids[x].attributetype);
         printf("\n");
      };
   };
   return;
}


void ldapschema_print_model(LDAPSchema * lsd, LDAPSchemaModel * model)
{

   assert(lsd   != NULL);
   assert(model != NULL);

   ldapschema_print_model_type(lsd, model);
   ldapschema_print_multiline("description:", model->desc);
   ldapschema_print_model_flags(lsd, model);
   ldapschema_print_model_ext(lsd, model);
   ldapschema_print_model_def(lsd, model);
   if ((model->spec))
   {
      ldapschema_print_multiline("spec name:",     model->spec->spec);
      ldapschema_print_multiline("spec chapter:",  model->spec->spec_section);
      ldapschema_print_multiline("spec vendor:",   model->spec->spec_vendor);
      ldapschema_print_multiline("spec source:",   model->spec->spec_source);
      ldapschema_print_multiline("spec text:",     model->spec->spec_text);
      ldapschema_print_multiline("spec notes:",    model->spec->notes);
      ldapschema_print_multiline("abnf:",          model->spec->abnf);
   };

   return;
}


void ldapschema_print_model_def(LDAPSchema * lsd, LDAPSchemaModel * model)
{
   char buff[4096];

   assert(lsd   != NULL);
   assert(model != NULL);

   ldapschema_fmt_definition(buff, sizeof(buff), model->definition, 30);
   ldapschema_print_multiline("definition:", buff);

   return;
}


void ldapschema_print_model_ext(LDAPSchema * lsd, LDAPSchemaModel * model)
{
   size_t                  x;
   size_t                  y;
   int                     len;
   int                     max;
   LDAPSchemaExtension   * ext;

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


void ldapschema_print_model_flags(LDAPSchema * lsd, LDAPSchemaModel * model)
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


void ldapschema_print_model_type(LDAPSchema * lsd, LDAPSchemaModel * model)
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


void ldapschema_print_models( LDAPSchema * lsd )
{
   size_t x;
   assert(lsd != NULL);
   
   for(x = 0; x < lsd->oids_len; x++)
      ldapschema_print_model(lsd, lsd->oids[x].model);

   return;
}


void ldapschema_print_multiline(const char * field, const char * str)
{
   const char         * bol;
   const char         * eol;

   assert(field != NULL);

   if (!(str))
      return;

   bol = str;
   while((eol = index(bol, '\n')) != NULL)
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


void ldapschema_print_objectclass(LDAPSchema * lsd, LDAPSchemaObjectclass * objcls)
{
   size_t                     x;
   const char               * str;
   char                     * attrname;
   LDAPSchemaObjectclass    * sup;

   assert(lsd    != NULL);
   assert(objcls != NULL);

   ldapschema_print_model_type(lsd, &objcls->model);

   for(x = 0; x < objcls->names_len; x++)
   {
      if (x == 0)
         printf("%*s%-*s %s\n", LDAPSCHEMA_WIDTH_INDENT, "", LDAPSCHEMA_WIDTH_FIELD, "name(s):", objcls->names[x]);
      else
         printf("%*s %s\n", LDAPSCHEMA_WIDTH_HEADER, "", objcls->names[x]);
   };

   ldapschema_print_multiline("description:", objcls->model.desc);
   ldapschema_print_model_flags(lsd, &objcls->model);

   switch(objcls->kind)
   {
      case LDAPSCHEMA_STRUCTURAL:      str = "structural";  break;
      case LDAPSCHEMA_AUXILIARY:       str = "auxiliary";   break;
      case LDAPSCHEMA_ABSTRACT:        str = "abstract";    break;
      default:                         str = "unknown:";    break;
   };
   printf("%*s%-*s %s\n", LDAPSCHEMA_WIDTH_INDENT, "", LDAPSCHEMA_WIDTH_FIELD, "usage:", str);

   if ((sup = objcls->sup) != NULL)
   {
      printf("%*s%-*s %s\n", LDAPSCHEMA_WIDTH_INDENT, "", LDAPSCHEMA_WIDTH_FIELD, "superior(s):", (((sup->names))?sup->names[0]:sup->model.oid) );
      while ((sup = sup->sup) != NULL)
         printf("%*s %s\n", LDAPSCHEMA_WIDTH_HEADER, "", (((sup->names))?sup->names[0]:sup->model.oid));
   };

   for(x = 0; x < objcls->may_len; x++)
   {
      if ((objcls->may[x]->names))
         attrname = objcls->may[x]->names[0];
      else
         attrname = objcls->may[x]->model.oid;
      if (x == 0)
         printf("%*s%-*s %s\n", LDAPSCHEMA_WIDTH_INDENT, "", LDAPSCHEMA_WIDTH_FIELD, "may:", attrname);
      else
         printf("%*s %s\n", LDAPSCHEMA_WIDTH_HEADER, "", attrname);
   };

   for(x = 0; x < objcls->must_len; x++)
   {
      if ((objcls->must[x]->names))
         attrname = objcls->must[x]->names[0];
      else
         attrname = objcls->must[x]->model.oid;
      if (x == 0)
         printf("%*s%-*s %s\n", LDAPSCHEMA_WIDTH_INDENT, "", LDAPSCHEMA_WIDTH_FIELD, "must:", attrname);
      else
         printf("%*s %s\n", LDAPSCHEMA_WIDTH_HEADER, "", attrname);
   };

   for(x = 0; x < objcls->inherit_may_len; x++)
   {
      if ((objcls->inherit_may[x]->names))
         attrname = objcls->inherit_may[x]->names[0];
      else
         attrname = objcls->inherit_may[x]->model.oid;
      if (x == 0)
         printf("%*s%-*s %s\n", LDAPSCHEMA_WIDTH_INDENT, "", LDAPSCHEMA_WIDTH_FIELD, "inherited may:", attrname);
      else
         printf("%*s %s\n", LDAPSCHEMA_WIDTH_HEADER, "", attrname);
   };

   for(x = 0; x < objcls->inherit_must_len; x++)
   {
      if ((objcls->inherit_must[x]->names))
         attrname = objcls->inherit_must[x]->names[0];
      else
         attrname = objcls->inherit_must[x]->model.oid;
      if (x == 0)
         printf("%*s%-*s %s\n", LDAPSCHEMA_WIDTH_INDENT, "", LDAPSCHEMA_WIDTH_FIELD, "inherited must:", attrname);
      else
         printf("%*s %s\n", LDAPSCHEMA_WIDTH_HEADER, "", attrname);
   };

   ldapschema_print_model_ext(lsd, &objcls->model);
   ldapschema_print_model_def(lsd, &objcls->model);

   return;
}


void ldapschema_print_objectclasses( LDAPSchema * lsd )
{
   size_t x;
   assert(lsd != NULL);
   for(x = 0; x < lsd->oids_len; x++)
   {
      if (lsd->oids[x].model->type == LDAPSCHEMA_OBJECTCLASS)
      {
         ldapschema_print_objectclass(lsd, lsd->oids[x].objectclass);
         printf("\n");
      };
   };
   return;
}


void ldapschema_print_ldapsyntax(LDAPSchema * lsd, LDAPSchemaSyntax * syntax)
{
   assert(lsd    != NULL);
   assert(syntax != NULL);

   ldapschema_print_model_type(lsd, &syntax->model);
   ldapschema_print_multiline("description:", syntax->model.desc);
   ldapschema_print_ldapsyntax_class(lsd, syntax->data_class);
   ldapschema_print_model_flags(lsd, &syntax->model);
   ldapschema_print_model_ext(lsd, &syntax->model);
   ldapschema_print_spec(lsd, syntax->model.spec);
   ldapschema_print_model_def(lsd, &syntax->model);

   return;
}


void ldapschema_print_ldapsyntax_class(LDAPSchema * lsd, size_t classid )
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


void ldapschema_print_ldapsyntaxes( LDAPSchema * lsd )
{
   size_t x;
   assert(lsd != NULL);
   for(x = 0; x < lsd->oids_len; x++)
   {
      if (lsd->oids[x].model->type == LDAPSCHEMA_SYNTAX)
      {
         ldapschema_print_ldapsyntax(lsd, lsd->oids[x].syntax);
         printf("\n");
      };
   };
   return;
}


void ldapschema_print_spec( LDAPSchema * lsd, const LDAPSchemaSpec * spec)
{
   assert(lsd != NULL);
   if (!(spec))
      return;
   ldapschema_print_multiline("spec name:",     spec->spec);
   ldapschema_print_multiline("spec chapter:",  spec->spec_section);
   ldapschema_print_multiline("spec vendor:",   spec->spec_vendor);
   ldapschema_print_multiline("spec source:",   spec->spec_source);
   ldapschema_print_multiline("spec text:",     spec->spec_text);
   ldapschema_print_multiline("spec notes:",    spec->notes);
   ldapschema_print_multiline("abnf:",          spec->abnf);
   return;
}

/* end of source file */
