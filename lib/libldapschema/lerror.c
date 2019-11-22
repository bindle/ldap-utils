
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
#define _LIB_LIBLDAPSCHEMA_LERROR_C 1
#include "lerror.h"

///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

/// initializes LDAP schema
/// @param[in]    err         Numeric error code
///
/// @return    Returns a string representation of the error code.
/// @see       ldapschema_free, ldapschema_initialize, ldapschema_errno
const char * ldapschema_err2string( int err )
{
   switch(err)
   {
      case LDAPSCHEMA_SUCCESS:                  return("success");
      case LDAPSCHEMA_NO_MEMORY:                return("out of virtual memory");
      case LDAPSCHEMA_SCHEMA_ERROR:             return("schema error");
      case LDAPSCHEMA_DUPLICATE:                return("duplicate definition");
      default:                                  return("unknown error");
   };

   return(LDAP_SUCCESS);
}


/// initializes LDAP schema
/// @param[in]  lsd    Reference to allocated ldap_schema struct
///
/// @return    Returns a numeric code of last error
/// @see       ldapschema_free, ldapschema_initialize, ldapschema_err2string
int ldapschema_errno( LDAPSchema * lsd )
{
   assert(lsd != NULL);
   return(lsd->errcode);
}


/// adds error to list of schema errors
/// @param[in]  lsd     reference to allocated ldap_schema struct
/// @param[in]  fmt     error format string
/// @param[in]  ...     error format arguments
///
/// @return    Returns a numeric code of last error
/// @see       ldapschema_free, ldapschema_initialize, ldapschema_err2string
int ldapschema_schema_err(LDAPSchema * lsd, LDAPSchemaModel * mod, const char * fmt, ... )
{
   char        buff[512];
   va_list     args;
   char      * str;
   const char  * type;
   const char  * def;
   size_t        len;

   assert(lsd != NULL);
   assert(fmt != NULL);


   // initialize errors if first error
   if (!(lsd->schema_errs))
   {
      if ((lsd->schema_errs = malloc(sizeof(char *)*2)) == NULL)
         return(lsd->errcode = LDAPSCHEMA_NO_MEMORY);
      lsd->schema_errs[0] = NULL;
   };

   // determine object type
   def = NULL;
   if ((mod))
   {
      switch(mod->type)
      {
         case LDAPSCHEMA_ATTRIBUTETYPE:   type = "attributeType";    break;
         case LDAPSCHEMA_OBJECTCLASS:     type = "objectClass";      break;
         case LDAPSCHEMA_SYNTAX:          type = "ldapSyntax";       break;
         case LDAPSCHEMA_MATCHINGRULE:    type = "matchingRules";    break;
         default:                         type = "unknown";          break;
      };
      def = mod->definition;
   } else
   {
      type = "";
   };

   // save definition if first error for object
   if (lsd->schema_errs_cur != mod)
   {
      lsd->schema_errs_cnt++;
      snprintf(buff, sizeof(buff), "%s %zu: ", type, lsd->schema_errs_cnt);
      len = strlen(buff);
      snprintf(&buff[len], sizeof(buff)-len, "definition: %s", mod->definition);
      if ((str = strdup(buff)) == NULL)
         return(lsd->errcode = LDAPSCHEMA_NO_MEMORY);
      if ((lsd->schema_errs = ldapschema_value_add(lsd->schema_errs, str, NULL)) == NULL)
      {
         free(str);
         return(lsd->errcode = LDAPSCHEMA_NO_MEMORY);
      };
   };

   // create error header
   snprintf(buff, sizeof(buff), "%s %zu: ", type, lsd->schema_errs_cnt);
   len = strlen(buff);

   // process error message
   va_start(args, fmt);
   vsnprintf(&buff[len], sizeof(buff)-len, fmt, args);
   va_end(args);

   // save error
   if ((str = strdup(buff)) == NULL)
      return(lsd->errcode = LDAPSCHEMA_NO_MEMORY);
   if ((lsd->schema_errs = ldapschema_value_add(lsd->schema_errs, str, NULL)) == NULL)
   {
      free(str);
      return(lsd->errcode = LDAPSCHEMA_NO_MEMORY);
   };

   // set error code
   lsd->errcode = LDAPSCHEMA_SCHEMA_ERROR;

   return(0);
}


char ** ldapschema_schema_errors(LDAPSchema * lsd )
{
   char     ** errs;
   size_t      len;
   size_t      pos;

   assert(lsd != NULL);

   if (!(lsd->schema_errs))
      return(NULL);

   for(len = 0; ((lsd->schema_errs[len])); len++);
   if ((errs = malloc(sizeof(char *)*(len+1))) == NULL)
      return(NULL);

   for(pos = 0; pos < len; pos++)
   {
      if ((errs[pos] = strdup(lsd->schema_errs[pos])) == NULL)
      {
         ldapschema_value_free(errs);
         return(NULL);
      };
   };
   errs[pos] = NULL;

   return(errs);
}

/* end of source file */
