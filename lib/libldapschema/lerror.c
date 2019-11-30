
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

#include "lmemory.h"
#include "lsort.h"


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
      case LDAPSCHEMA_UNKNOWN_FIELD:            return("unknown field");
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
   char           buff[512];
   va_list        args;
   char *         str;
   char **        tmplist;
   char ***       listp;
   int            err;

   assert(lsd != NULL);
   assert(fmt != NULL);

   // determines which list
   listp = &lsd->schema_errs;
   if ((mod))
      listp = &mod->errors;

   // initialize errors if first error
   if (!(*listp))
   {
      if ((*listp = malloc(sizeof(char *)*2)) == NULL)
         return(lsd->errcode = LDAPSCHEMA_NO_MEMORY);
      bzero(*listp, sizeof(char *)*2);
   };

   // process error message
   va_start(args, fmt);
   vsnprintf(buff, sizeof(buff), fmt, args);
   va_end(args);

   // save error
   if ((str = strdup(buff)) == NULL)
      return(lsd->errcode = LDAPSCHEMA_NO_MEMORY);
   if ((tmplist = ldapschema_value_add(*listp, str, NULL)) == NULL)
   {
      free(str);
      return(lsd->errcode = LDAPSCHEMA_NO_MEMORY);
   };
   *listp = tmplist;

   // adds object to error list
   if ((err = ldapschema_insert(lsd, (void ***)&lsd->objerrs, &lsd->objerrs_len, mod, ldapschema_compar_models)) > 0)
      return(lsd->errcode);

   // set error code
   lsd->errcode = LDAPSCHEMA_SCHEMA_ERROR;

   return(0);
}


int ldapschema_schema_err_kw_dup(LDAPSchema * lsd, LDAPSchemaModel * mod,
   const char * keyword )
{
   assert(lsd != NULL);
   return(ldapschema_schema_err(lsd, mod, "definition contains duplicate keyword '%s'", keyword));
}


int ldapschema_schema_err_kw_unknown(LDAPSchema * lsd, LDAPSchemaModel * mod,
   const char * keyword )
{
   assert(lsd != NULL);
   return(ldapschema_schema_err(lsd, mod, "definition contains unknown keyword '%s'", keyword));
}


char ** ldapschema_schema_errors(LDAPSchema * lsd )
{
   int                  len;
   size_t               x;
   size_t               y;
   char                 buff[256];
   char *               str;
   char **              errs;
   char **              tmperrs;
   LDAPSchemaModel *    mod;

   assert(lsd != NULL);

   // if not errors, exit
   if ( (!(lsd->schema_errs)) && (!(lsd->objerrs)) )
      return(NULL);

   // initialize list
   if ((errs = malloc(sizeof(char *)*2)) == NULL)
      return(NULL);
   errs[0]  = NULL;
   len      = 0;

   // copy server errors
   for(x = 0; (((lsd->schema_errs)) && ((lsd->schema_errs[x]))); x++)
   {
      snprintf(buff, sizeof(buff), "server: %s", lsd->schema_errs[x]);
      if ((str = strdup(buff)) == NULL)
      {
         ldapschema_value_free(errs);
         return(NULL);
      };
      if ((tmperrs = ldapschema_value_add(errs, str, &len)) == NULL)
      {
         free(str);
         ldapschema_value_free(errs);
         return(NULL);
      };
      free(str);
      errs = tmperrs;
   };

   // loop through objects and copy errors
   for(x = 0; x < lsd->objerrs_len; x++)
   {
      mod = lsd->objerrs[x].model;
      for(y = 0; ((mod->errors[y])); y++)
      {
         snprintf(buff, sizeof(buff), "%s: %s: %s", ldapschema_type_name(mod->type), mod->oid, mod->errors[y]);
         if ((str = strdup(buff)) == NULL)
         {
            ldapschema_value_free(errs);
            return(NULL);
         };
         if ((tmperrs = ldapschema_value_add(errs, str, &len)) == NULL)
         {
            free(str);
            ldapschema_value_free(errs);
            return(NULL);
         };
         free(str);
         errs = tmperrs;
      };
   };

   return(errs);
}

/* end of source file */
