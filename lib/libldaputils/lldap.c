/*
 *  LDAP Utilities
 *  Copyright (C) 2012 Bindle Binaries <syzdek@bindlebinaries.com>.
 *
 *  @BINDLE_BINARIES_BSD_LICENSE_START@
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
 *
 *  @BINDLE_BINARIES_BSD_LICENSE_END@
 */
/**
 *  @file src/ldaputils_misc.c contains shared functions and variables
 */
#define _LIB_LIBLDAPUTILS_LLDAP_C 1
#include "lldap.h"

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

#include "lconfig.h"


/////////////////
//             //
//  Functions  //
//             //
/////////////////

/// compares two LDAP values for sorting
/// @param[in] ptr1   pointer to first data item to compare
/// @param[in] ptr2   pointer to second data item to compare
int ldaputils_cmp_berval(const struct berval ** ptr1, const struct berval ** ptr2)
{
   int rc;
   
   // quick check of the arguments
   if ( (!(ptr1)) && (!(ptr2)) )
      return(0);
   if (!(ptr1))
      return(-1);
   if (!(ptr2))
      return(1);
   
   // quick check of the pointers
   if ( (!(*ptr1)) && (!(*ptr2)) )
      return(0);
   if (!(*ptr1))
      return(-1);
   if (!(*ptr2))
      return(1);
   
   // case insensitive compare
   if ((rc = strcasecmp((*ptr1)->bv_val, (*ptr2)->bv_val)))
      return(rc);
   
   // case sensitive compare
   if ((rc = strcmp((*ptr1)->bv_val, (*ptr2)->bv_val)))
      return(rc);
   
   // fall back to comparing memory location
   if ( *ptr1 < *ptr2 )
      return(-1);
   if ( *ptr1 > *ptr2 )
      return(1);
   
   // pointers must point to the same object
   return(0);
}


/// compares two LDAP values for sorting
/// @param[in] ptr1   pointer to first data item to compare
/// @param[in] ptr2   pointer to second data item to compare
int ldaputils_cmp_entry(const LDAPUtilsEntry ** ptr1, const LDAPUtilsEntry ** ptr2)
{
   int rc;
   
   // quick check of the arguments
   if ( (!(ptr1)) && (!(ptr2)) )
      return(0);
   if (!(ptr1))
      return(-1);
   if (!(ptr2))
      return(1);
   
   // quick check of the pointers
   if ( (!(*ptr1)) && (!(*ptr2)) )
      return(0);
   if (!(*ptr1))
      return(-1);
   if (!(*ptr2))
      return(1);

   // quick check of the pointers
   if ( (!(*ptr1)->sortval) && (!(*ptr2)->sortval) )
   {
      // compare of DN
      if ((rc = strcasecmp((*ptr1)->dn, (*ptr2)->dn)))
         return(rc);
      if ((rc = strcmp((*ptr1)->dn, (*ptr2)->dn)))
         return(rc);
      return(0);
   };
   if (!(*ptr1)->sortval)
      return(-1);
   if (!(*ptr2)->sortval)
      return(1);
   
   // compare of sort value
   if ((rc = strcasecmp((*ptr1)->sortval, (*ptr2)->sortval)))
      return(rc);
   if ((rc = strcmp((*ptr1)->sortval, (*ptr2)->sortval)))
      return(rc);

   // compare of DN
   if ((rc = strcasecmp((*ptr1)->dn, (*ptr2)->dn)))
      return(rc);
   if ((rc = strcmp((*ptr1)->dn, (*ptr2)->dn)))
      return(rc);
   
   // fall back to comparing memory location
   if ( *ptr1 < *ptr2 )
      return(-1);
   if ( *ptr1 > *ptr2 )
      return(1);
   
   // pointers must point to the same object
   return(0);
}


/// frees list of entries
/// @param[in] entries   list of entries to free
void ldaputils_free_entries(LDAPUtilsEntry ** entries)
{
   int  x;
   int  y;
   
   if (!(entries))
      return;
   
   for(x = 0; entries[x]; x++)
   {
      if (entries[x]->dn)
         ldap_memfree(entries[x]->dn);
      if (entries[x]->sortval)
         free(entries[x]->sortval);
      if (entries[x]->attributes)
      {
         for(y = 0; entries[x]->attributes[y]; y++)
         {
            if (entries[x]->attributes[y]->name)
               ldap_memfree(entries[x]->attributes[y]->name);
            if (entries[x]->attributes[y]->vals)
               ldap_value_free_len(entries[x]->attributes[y]->vals);
            free(entries[x]->attributes[y]);
         };
         free(entries[x]->attributes);
      };
      free(entries[x]);
   };
   free(entries);
   
   return;
}


/// retrieves LDAP entries from result
/// @param[in] ld      refernce to LDAP socket data
/// @param[in] res     refernce to LDAP result message
LDAPUtilsEntry ** ldaputils_get_entries(LDAPUtils * cnf, LDAP * ld,
   LDAPMessage * res, const char * sortattr)
{
   char                * attr;
   void                * ptr;
   size_t                entry_count;
   BerElement          * ber;
   LDAPMessage         * entry;
   LDAPUtilsEntry      * e;
   LDAPUtilsEntry     ** entries;
   LDAPUtilsAttribute  * a;
   
   entries     = NULL;
   entry_count = 0;
   
   entry = ldap_first_entry(ld, res);
   while(entry)
   {
      if (!(e = malloc(sizeof(LDAPUtilsEntry))))
      {
         fprintf(stderr, "%s: out of virtual memory\n", cnf->prog_name);
         return(NULL);
      };
      memset(e, 0, sizeof(LDAPUtilsEntry));
      
      entry_count++;
      if (!(ptr = realloc(entries, sizeof(LDAPUtilsEntry *) * (entry_count+1))))
      {
         fprintf(stderr, "%s: out of virtual memory\n", cnf->prog_name);
         free(e);
         return(NULL);
      };
      entries = ptr;
      entries[entry_count-1] = e;
      entries[entry_count-0] = NULL;
      
      e->dn = ldap_get_dn(ld, entry);

      attr = ldap_first_attribute(ld, entry, &ber);
      while(attr)
      {
         if (!(a = malloc(sizeof(LDAPUtilsAttribute))))
         {
            fprintf(stderr, "%s: out of virtual memory\n", cnf->prog_name);
            return(NULL);
         };
         memset(a, 0, sizeof(LDAPUtilsAttribute));
         
         e->count++;
         if (!(ptr = realloc(e->attributes, sizeof(LDAPUtilsAttribute *) * (e->count+1))))
         {
            fprintf(stderr, "%s: out of virtual memory\n", cnf->prog_name);
            free(a);
            return(NULL);
         };
         e->attributes = ptr;
         e->attributes[e->count-1] = a;
         e->attributes[e->count-0] = NULL;
                  
         a->name = attr;
         a->vals = ldap_get_values_len(ld, entry, attr);
         ldaputils_sort_values(a->vals);
         
         if (sortattr)
            if (!(strcasecmp(attr, sortattr)))
               if (a->vals)
                  if (a->vals[0])
                     e->sortval = strdup(a->vals[0]->bv_val);
                  
         attr = ldap_next_attribute(ld, entry, ber);
      };
      ber_free(ber, 0);
      
      entry = ldap_next_entry(ld, entry);
   };
   
   return(entries);
}


/// retrieves values of an LDAP attribute
/// @param[in] ld      refernce to LDAP socket data
/// @param[in] entry   pointer to LDAP entry
/// @param[in] attr    attribute to retrieve
char * ldaputils_get_vals(LDAPUtils * cnf, LDAPUtilsEntry * entry,
   const char * attr)
{
   int              x;
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
      fprintf(stderr, "%s: out of virtual memory\n", cnf->prog_name);
      return(NULL);
   };
   memset(val, 0, val_len);

   if (!(strcasecmp("dn", attr)))
   {
      if (!(ptr = realloc(val, sizeof(char)*(strlen(entry->dn)+1))))
      {
         fprintf(stderr, "%s: out of virtual memory\n", cnf->prog_name);
         free(val);
         return(NULL);
      };
      val = ptr;
      strcpy(val, entry->dn);
      return(val);
   };
   
   vals = NULL;
   for(x = 0; entry->attributes[x]; x++)
      if (!(strcasecmp(entry->attributes[x]->name, attr)))
         vals = entry->attributes[x]->vals;
   
   if (!(vals))
      return(val);

   for(x = 0; vals[x]; x++)
   {
      att_len = vals[x]->bv_len;
      if (val_len < att_len)
      {
         new_len = val_len + att_len + 256;
         if (!(ptr = (char * ) realloc(val, (sizeof(char) * new_len))))
         {
            fprintf(stderr, "%s: out of virtual memory\n", cnf->prog_name);
            free(val);
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
         
   return(val);
}


/// connects and binds to LDAP server
/// @param[in] cnf   reference to common configuration struct
LDAP * ldaputils_initialize_conn(LDAPUtils * cnf)
{
   int          err;
   LDAP       * ld;
   BerValue     cred;
   BerValue   * servercredp;
   const char * mechanism;

   ld = NULL;
   if (ldap_initialize(&ld, NULL))
   {
      fprintf(stderr, "%s: ldaputils_initialize(): %s\n", cnf->prog_name, strerror(errno));
      return(NULL);
   };

   cnf->version = 3;
   if (cnf->version)
      if ((LDAP_OPT_SUCCESS != ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &cnf->version)))
         fprintf(stderr, "%s: could not set LDAP_OPT_PROTOCOL_VERSION\n", cnf->prog_name);
   if (cnf->sizelimit)
      if ((LDAP_OPT_SUCCESS != ldap_set_option(ld, LDAP_OPT_SIZELIMIT, &cnf->sizelimit)))
         fprintf(stderr, "%s: could not set LDAP_OPT_SIZELIMIT\n", cnf->prog_name);
   if (cnf->timelimit)
      if ((LDAP_OPT_SUCCESS != ldap_set_option(ld, LDAP_OPT_TIMELIMIT, &cnf->timelimit)))
         fprintf(stderr, "%s: could not set LDAP_OPT_TIMELIMIT\n", cnf->prog_name);
   
   //mechanism   = (const char *)LDAP_AUTH_SIMPLE;
   mechanism   = (const char *)LDAP_SASL_SIMPLE;
   cred.bv_val = cnf->bindpw;
   cred.bv_len = (size_t) strlen(cnf->bindpw);
   
   servercredp = NULL;
   if ((err = ldap_sasl_bind_s(ld, cnf->binddn, mechanism, &cred, NULL, NULL,  &servercredp)) != LDAP_SUCCESS)
   {
      fprintf(stderr, "%s: ldap_sasl_bind_s(): %s\n", cnf->prog_name, ldap_err2string(err));
      ldap_unbind_ext_s(ld, NULL, NULL);
      return(NULL);
   };

   return(ld);
}


/// connects and binds to LDAP server
/// @param[in] ld    refernce to LDAP socket data
/// @param[in] cnf   reference to common configuration struct
int ldaputils_search(LDAP * ld, LDAPUtils * cnf, LDAPMessage ** resp)
{
   int rc;
   int err;
   int msgid;

   if ((err = ldap_search_ext(ld, cnf->basedn, cnf->scope, cnf->filter, cnf->attrs, 0, NULL, NULL, NULL, -1, &msgid)))
   {
      fprintf(stderr, "%s: ldap_search_ext_s(): %s\n", cnf->prog_name, ldap_err2string(err));
      ldap_unbind_ext_s(ld, NULL, NULL);
      return(-1);
   };

   switch((err = ldap_result(ld, msgid, LDAP_MSG_ALL, NULL, resp)))
   {
      case 0:
         break;
      case -1:
         fprintf(stderr, "%s: ldap_result(): %s\n", cnf->prog_name, ldap_err2string(err));
         ldap_unbind_ext_s(ld, NULL, NULL);
         return(-1);
      default:
         break;
   };

   rc = ldap_parse_result(ld, *resp, &err, NULL, NULL, NULL, NULL, 0);
   if (rc != LDAP_SUCCESS)
   {
      fprintf(stderr, "%s: ldap_parse_result(): %s\n", cnf->prog_name, ldap_err2string(rc));
      ldap_unbind_ext_s(ld, NULL, NULL);
      return(-1);
   };
   if (err != LDAP_SUCCESS)
   {
      fprintf(stderr, "%s: ldap_parse_result(): %s\n", cnf->prog_name, ldap_err2string(err));
      ldap_unbind_ext_s(ld, NULL, NULL);
      return(-1);
   };
   
   return(0);
}


/// sorts values
/// @param[in] entries   list of attribute values to sort
int ldaputils_sort_entries(LDAPUtilsEntry ** entries)
{
   size_t  len;
   if (!(entries))
      return(1);
   for(len = 0; entries[len]; len++);
   qsort(entries, len, sizeof(LDAPUtilsEntry *), (int (*)(const void *, const void *))ldaputils_cmp_entry);
   return(0);
}


/// sorts values
/// @param[in] vals   list of attribute values to sort
int ldaputils_sort_values(struct berval ** vals)
{
   size_t  len;
   if (!(vals))
      return(1);
   for(len = 0; vals[len]; len++);
   qsort(vals, len, sizeof(char *), (int (*)(const void *, const void *))ldaputils_cmp_berval);
   return(0);
}

/* end of source file */
