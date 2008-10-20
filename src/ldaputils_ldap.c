/*
 *  LDAP Utilities
 *  Copyright (c) 2008 David M. Syzdek <david@syzdek.net>.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
/**
 *  @file src/ldaputils_misc.c contains shared functions and variables
 */
#define _LDAP_UTILS_SRC_LDAPUTILS_LDAP_C 1
#include "ldaputils_ldap.h"

///////////////
//           //
//  Headers  //
//           //
///////////////

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <ldap.h>
#include <stdlib.h>

#include "ldaputils_config.h"


/////////////////
//             //
//  Functions  //
//             //
/////////////////

/// retrieves values of an LDAP attribute
/// @param[in] ld      refernce to LDAP socket data
/// @param[in] entry   pointer to LDAP entry
/// @param[in] attr    attribute to retrieve
char * ldaputils_get_vals(LDAP * ld, LDAPMessage * entry, const char * attr)
{
   int              x;
   char           * dn;
   char           * ptr;
   char           * val;
   size_t           val_len;
   size_t           att_len;
   size_t           new_len;
   struct berval ** vals;
   
   val     = NULL;
   val_len = 256;
   
   if (!(val = (char *) malloc(sizeof(char) * val_len)))
   {
      fprintf(stderr, _("%s: out of virtual memory\n"), PROGRAM_NAME);
      return(NULL);
   };
   memset(val, 0, val_len);

   if (!(strcasecmp("dn", attr)))
   {
      dn = ldap_get_dn(ld, entry);
      if (val_len < strlen(dn))
      {
         if (!(ptr = realloc(val, sizeof(char)*(strlen(dn)+1))))
         {
            fprintf(stderr, _("%s: out of virtual memory\n"), PROGRAM_NAME);
            free(val);
            ldap_memfree(dn);
            return(NULL);
         };
         val = ptr;
      };
      strcpy(val, dn);
      ldap_memfree(dn);
      return(val);
   };

   if ((vals = ldap_get_values_len(ld, entry, attr)))
   {
      for(x = 0; vals[x]; x++)
      {
         att_len = vals[x]->bv_len;
         if (val_len < att_len)
         {
            new_len = val_len + att_len + 256;
            if (!(ptr = (char * ) realloc(val, (sizeof(char) * new_len))))
            {
               fprintf(stderr, _("%s: out of virtual memory\n"), PROGRAM_NAME);
               free(val);
               ldap_value_free_len(vals);
               return(NULL);
            };
            val = ptr;
            memset(&val[val_len], 0, new_len-val_len);
            val_len = new_len;
         };
         if ((x))
            strcat(val, ",");
         memcpy(&val[strlen(val)], vals[x]->bv_val, vals[x]->bv_len);
      };
      ldap_value_free_len(vals);
   };
         
   return(val);
}


/// connects and binds to LDAP server
/// @param[in] cnf   reference to common configuration struct
LDAP * ldaputils_initialize(LdapUtilsConfig * cnf)
{
   int          err;
   LDAP       * ld;
   char         uribuff[256];
   BerValue     cred;
   BerValue   * servercredp;
   const char * mechanism;
   const char * uri;

   if (cnf->debug)
      if ((LDAP_OPT_SUCCESS != ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, (void *)&cnf->debug)))
         fprintf(stderr, _("%s: could not set LDAP_OPT_DEBUG_LEVEL\n"), PROGRAM_NAME);
   
   uri = cnf->uri;
   if ( (!(uri)) && ((cnf->host)) )
   {
      if (cnf->port)
         snprintf(uribuff, 256, "ldap://%s:%i", cnf->host, cnf->port);
      else
         snprintf(uribuff, 256, "ldap://%s", cnf->host);
      uri = uribuff;
   };
   
   ld = NULL;
   if (ldap_initialize(&ld, uri))
   {
      fprintf(stderr, "%s: ldaputils_initialize(): %s\n", PROGRAM_NAME, strerror(errno));
      return(NULL);
   };

   cnf->version = 3;
   if (cnf->version)
      if ((LDAP_OPT_SUCCESS != ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &cnf->version)))
         fprintf(stderr, _("%s: could not set LDAP_OPT_PROTOCOL_VERSION\n"), PROGRAM_NAME);
   if (cnf->referrals)
      if ((LDAP_OPT_SUCCESS != ldap_set_option(ld, LDAP_OPT_REFERRALS, &cnf->sizelimit)))
         fprintf(stderr, _("%s: could not set LDAP_OPT_REFERRALS\n"), PROGRAM_NAME);
   if (cnf->sizelimit)
      if ((LDAP_OPT_SUCCESS != ldap_set_option(ld, LDAP_OPT_SIZELIMIT, &cnf->sizelimit)))
         fprintf(stderr, _("%s: could not set LDAP_OPT_SIZELIMIT\n"), PROGRAM_NAME);
   if (cnf->timelimit)
      if ((LDAP_OPT_SUCCESS != ldap_set_option(ld, LDAP_OPT_TIMELIMIT, &cnf->timelimit)))
         fprintf(stderr, _("%s: could not set LDAP_OPT_TIMELIMIT\n"), PROGRAM_NAME);
   
   //mechanism   = (const char *)LDAP_AUTH_SIMPLE;
   mechanism   = (const char *)LDAP_SASL_SIMPLE;
   cred.bv_val = cnf->bindpw;
   cred.bv_len = (size_t) strlen(cnf->bindpw);
   
   servercredp = NULL;
   if ((err = ldap_sasl_bind_s(ld, cnf->binddn, mechanism, &cred, NULL, NULL,  &servercredp)) != LDAP_SUCCESS)
   {
      fprintf(stderr, "%s: ldap_sasl_bind_s(): %s\n", PROGRAM_NAME, ldap_err2string(err));
      ldap_unbind_ext_s(ld, NULL, NULL);
      return(NULL);
   };

   return(ld);
}


/// connects and binds to LDAP server
/// @param[in] ld    refernce to LDAP socket data
/// @param[in] cnf   reference to common configuration struct
int ldaputils_search(LDAP * ld, LdapUtilsConfig * cnf, LDAPMessage ** resp)
{
   int rc;
   int err;
   int msgid;

   if ((err = ldap_search_ext(ld, cnf->basedn, cnf->scope, cnf->filter, cnf->attrs, 0, NULL, NULL, NULL, -1, &msgid)))
   {
      fprintf(stderr, "%s: ldap_search_ext_s(): %s\n", PROGRAM_NAME, ldap_err2string(err));
      ldap_unbind_ext_s(ld, NULL, NULL);
      return(-1);
   };

   switch((err = ldap_result(ld, msgid, LDAP_MSG_ALL, NULL, resp)))
   {
      case 0:
         break;
      case -1:
         fprintf(stderr, "%s: ldap_result(): %s\n", PROGRAM_NAME, ldap_err2string(err));
         ldap_unbind_ext_s(ld, NULL, NULL);
         return(-1);
      default:
         break;
   };

   rc = ldap_parse_result(ld, *resp, &err, NULL, NULL, NULL, NULL, 0);
   if (rc != LDAP_SUCCESS)
   {
      fprintf(stderr, "%s: ldap_parse_result(): %s\n", PROGRAM_NAME, ldap_err2string(rc));
      ldap_unbind_ext_s(ld, NULL, NULL);
      return(-1);
   };
   if (err != LDAP_SUCCESS)
   {
      fprintf(stderr, "%s: ldap_parse_result(): %s\n", PROGRAM_NAME, ldap_err2string(err));
      ldap_unbind_ext_s(ld, NULL, NULL);
      return(-1);
   };
   
   return(0);
}

/* end of source file */
