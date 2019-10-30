
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


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#pragma mark - Definitions

#define LDAPSCHEMA_WIDTH_HEADER    16
#define LDAPSCHEMA_WIDTH_INDENT    3
#define LDAPSCHEMA_WIDTH_FIELD     (LDAPSCHEMA_WIDTH_HEADER-LDAPSCHEMA_WIDTH_INDENT)


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

void
ldapschema_print_model_def(
         LDAPSchema            * lsd,
         LDAPSchemaModel       * model );

void
ldapschema_print_model_desc(
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


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

void ldapschema_print_attributetype( LDAPSchema * lsd, LDAPSchemaAttributeType * attr )
{
   size_t         x;
   const char   * str;

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

   ldapschema_print_model_desc(lsd, &attr->model);
   ldapschema_print_model_flags(lsd, &attr->model);

   switch(attr->usage)
   {
      case LDAPSCHEMA_USER_APP:        str = "userApplications:"; break;
      case LDAPSCHEMA_DIRECTORY_OP:    str = "directoryOperation:"; break;
      case LDAPSCHEMA_DISTRIBUTED_OP:  str = "distributedOperation:"; break;
      case LDAPSCHEMA_DSA_OP:          str = "dSAOperation:"; break;
      default:                         str = "unknown:"; break;
   };
   printf("%*s%-*s %s\n", LDAPSCHEMA_WIDTH_INDENT, "", LDAPSCHEMA_WIDTH_FIELD, "usage:", str);

   if ((attr->sup_name))
      printf("%*s%-*s %s\n", LDAPSCHEMA_WIDTH_INDENT, "", LDAPSCHEMA_WIDTH_FIELD, "superior:", attr->sup_name);

   if ((attr->syntax))
   {
      printf("%*s%-*s %s (%s)\n", LDAPSCHEMA_WIDTH_INDENT, "", LDAPSCHEMA_WIDTH_FIELD, "syntax:", attr->syntax->model.oid, attr->syntax->model.desc);
   };

   ldapschema_print_model_ext(lsd, &attr->model);
   ldapschema_print_model_def(lsd, &attr->model);

   return;
}


void ldapschema_print_attributetypes( LDAPSchema * lsd )
{
   size_t x;
   assert(lsd != NULL);
   for(x = 0; x < lsd->attrs_len; x++)
   {
      ldapschema_print_attributetype(lsd, lsd->attrs[x]);
      printf("\n");
   };
   return;
}


void ldapschema_print_model(LDAPSchema * lsd, LDAPSchemaModel * model)
{

   assert(lsd   != NULL);
   assert(model != NULL);

   ldapschema_print_model_type(lsd, model);
   ldapschema_print_model_desc(lsd, model);
   ldapschema_print_model_flags(lsd, model);
   ldapschema_print_model_ext(lsd, model);
   ldapschema_print_model_def(lsd, model);

   return;
}


void ldapschema_print_model_def(LDAPSchema * lsd, LDAPSchemaModel * model)
{
   //size_t x;
   char      * str;
   size_t      space;
   size_t      len;
   size_t      pos;
   size_t      bol;

   assert(lsd   != NULL);
   assert(model != NULL);

   // initialize values
   space    = 0;
   len      = strlen(model->definition) - 2;
   if ((str = strdup(&model->definition[1])) == NULL)
      return;

   for (pos = 0; ((pos < len) && ((str[pos] == ' ') || (str[pos] == '\t'))); pos++);
   bol = pos;

   // print formatted definition
   printf("%*s%-*s (\n", LDAPSCHEMA_WIDTH_INDENT, "", LDAPSCHEMA_WIDTH_FIELD, "defintion:");
   while(pos < len)
   {
      // process quoted strings
      if (str[pos] == '\'')
      {
         for(pos += 1; ((pos < len) && (str[pos] != '\'')); pos++); // fast forward to closing quotation
         pos++;
      }

      // processed grouped values
      else if (str[pos] == '(')
      {
         for(pos += 1; ((pos < len) && (str[pos] != ')')); pos++); // fast forward to closing parentheses
         pos++;
      }

      // process white space
      else if ((str[pos] == ' ') || (str[pos] == '\t'))
      {
         for(pos += 1; ((pos < len) && ((str[pos] == ' ') || (str[pos] == '\t'))); pos++); // fast forward to end of white space
      }

      // process key words
      else if ((str[pos] >= 'A') && (str[pos] <= 'Z'))
      {
         str[pos-1] = '\0';
         printf("%*s    %s\n", LDAPSCHEMA_WIDTH_HEADER, "", &str[bol]);
         bol = pos;
         for(pos += 1; ((pos < len) && (str[pos] != ' ') && (str[pos] != '\t')); pos++); // fast forward to white space
         pos++;
      }

      // process unquoted values
      else
      {
         for(pos += 1; ((pos < len) && (str[pos] != ' ') && (str[pos] != '\t')); pos++); // fast forward to white space
         pos++;
      };
   };
   printf("%*s )\n", LDAPSCHEMA_WIDTH_HEADER, "");

   free(str);

   return;
}


void ldapschema_print_model_desc(LDAPSchema * lsd, LDAPSchemaModel * model)
{
   assert(lsd   != NULL);
   assert(model != NULL);
   if ((model->desc))
      printf("%*s%-*s %s\n", LDAPSCHEMA_WIDTH_INDENT, "", LDAPSCHEMA_WIDTH_FIELD, "description:", model->desc);
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
      ldapschema_print_model(lsd, lsd->oids[x]);

   return;
}


void ldapschema_print_syntax(LDAPSchema * lsd, LDAPSchemaSyntax * syntax)
{
   assert(lsd    != NULL);
   assert(syntax != NULL);

   ldapschema_print_model(lsd, &syntax->model);

   return;
}


void ldapschema_print_syntaxes( LDAPSchema * lsd )
{
   size_t x;
   assert(lsd != NULL);
   for(x = 0; x < lsd->syntaxes_len; x++)
   {
      ldapschema_print_syntax(lsd, lsd->syntaxes[x]);
      printf("\n");
   };
   return;
}

/* end of source file */
