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
   
   if (entries == NULL)
      return;
   
   for(x = 0; (entries[x] != NULL); x++)
   {
      // frees DN
      if (entries[x]->dn != NULL)
         ldap_memfree(entries[x]->dn);
      entries[x]->dn = NULL;

      // frees sort value
      if (entries[x]->sortval != NULL)
         free(entries[x]->sortval);

      // frees attributes
      if (entries[x]->attributes != NULL)
      {
         for(y = 0; (entries[x]->attributes[y] != NULL); y++)
         {
            // frees attribute name
            if (entries[x]->attributes[y]->name != NULL)
               ldap_memfree(entries[x]->attributes[y]->name);

            // frees attribute values
            if (entries[x]->attributes[y]->vals != NULL)
               ldap_value_free_len(entries[x]->attributes[y]->vals);

            // frees attribute
            free(entries[x]->attributes[y]);
         };
         free(entries[x]->attributes);
         entries[x]->attributes = NULL;
      };
      free(entries[x]);
   };
   free(entries);
   
   return;
}


/// retrieves LDAP entries from result
/// @param[in] ld      refernce to LDAP socket data
/// @param[in] res     refernce to LDAP result message
LDAPUtilsEntry ** ldaputils_get_entries(LDAPUtils * lud, LDAP * ld,
   LDAPMessage * res, const char * sortattr)
{
   char                * name;
   void                * ptr;
   size_t                entry_count;
   BerElement          * ber;
   LDAPMessage         * msg;
   LDAPUtilsEntry      * entry;
   LDAPUtilsEntry     ** entries;
   LDAPUtilsAttribute  * attr;

   entries     = NULL;
   entry_count = 0;

   msg = ldap_first_entry(ld, res);
   while(msg)
   {
      // allocates entry
      if ( (entry = malloc(sizeof(LDAPUtilsEntry))) == NULL )
      {
         fprintf(stderr, "%s: out of virtual memory\n", lud->prog_name);
         ldaputils_free_entries(entries);
         return(NULL);
      };
      memset(entry, 0, sizeof(LDAPUtilsEntry));

      // increases size of entry list
      entry_count++;
      if ((ptr = realloc(entries, sizeof(LDAPUtilsEntry *) * (entry_count+1))) == NULL)
      {
         fprintf(stderr, "%s: out of virtual memory\n", lud->prog_name);
         free(entry);
         ldaputils_free_entries(entries);
         return(NULL);
      };
      entries                = ptr;
      entries[entry_count-1] = entry;
      entries[entry_count-0] = NULL;

      // retrieves entry DN
      if ((entry->dn = ldap_get_dn(ld, msg)) == NULL)
      {
         fprintf(stderr, "%s: out of virtual memory\n", lud->prog_name);
         ldaputils_free_entries(entries);
         return(NULL);
      };

      // retrieves attributes
      name = ldap_first_attribute(ld, msg, &ber);
      while(name != NULL)
      {
         // allocates attribute
         if (!(attr = malloc(sizeof(LDAPUtilsAttribute))))
         {
            fprintf(stderr, "%s: out of virtual memory\n", lud->prog_name);
            ldaputils_free_entries(entries);
            return(NULL);
         };
         memset(attr, 0, sizeof(LDAPUtilsAttribute));

         // increases size of attribute list
         entry->count++;
         if (!(ptr = realloc(entry->attributes, sizeof(LDAPUtilsAttribute *) * (entry->count+1))))
         {
            fprintf(stderr, "%s: out of virtual memory\n", lud->prog_name);
            free(attr);
            ldaputils_free_entries(entries);
            return(NULL);
         };
         entry->attributes                 = ptr;
         entry->attributes[entry->count-1] = attr;
         entry->attributes[entry->count-0] = NULL;

         // populates attribute name and values
         attr->name = name;
         attr->vals = ldap_get_values_len(ld, msg, name);
         ldaputils_sort_values(attr->vals);

         // saves entry's sort value
         if (sortattr != NULL)
            if (!(strcasecmp(name, sortattr)))
               if (attr->vals != NULL)
                  if (attr->vals[0] != NULL)
                     entry->sortval = strdup(attr->vals[0]->bv_val);
                  
         name = ldap_next_attribute(ld, msg, ber);
      };
      ber_free(ber, 0);
      
      msg = ldap_next_entry(ld, msg);
   };
   
   return(entries);
}


/// retrieves values of an LDAP attribute
/// @param[in] ld      refernce to LDAP socket data
/// @param[in] entry   pointer to LDAP entry
/// @param[in] attr    attribute to retrieve
char * ldaputils_get_vals(LDAPUtils * lud, LDAPUtilsEntry * entry,
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
      fprintf(stderr, "%s: out of virtual memory\n", lud->prog_name);
      return(NULL);
   };
   memset(val, 0, val_len);

   if (!(strcasecmp("dn", attr)))
   {
      if (!(ptr = realloc(val, sizeof(char)*(strlen(entry->dn)+1))))
      {
         fprintf(stderr, "%s: out of virtual memory\n", lud->prog_name);
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
            fprintf(stderr, "%s: out of virtual memory\n", lud->prog_name);
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
/// @param[in] lud   reference to LDAP utilities struct
int ldaputils_bind_s(LDAPUtils * lud)
{
   int          err;
   LDAP       * ld;
   BerValue     cred;
   BerValue   * servercredp;

   ld          = lud->ld;
   servercredp = NULL;

   bzero(&cred, sizeof(cred));
   if ((lud->bindpw[0]))
   {
      cred.bv_val = lud->bindpw;
      cred.bv_len = (size_t) strlen(lud->bindpw);
   };

   // binds to LDAP
   if ((err = ldap_sasl_bind_s(ld, lud->binddn, lud->sasl_mech, &cred, NULL, NULL, &servercredp)) != LDAP_SUCCESS)
   {
      return(err);
   };

   return(LDAP_SUCCESS);
}


/// connects and binds to LDAP server
/// @param[in] ld    refernce to LDAP socket data
/// @param[in] lud   reference to LDAP utilities struct
int ldaputils_search(LDAPUtils * lud, LDAPMessage ** resp)
{
   int    rc;
   int    err;
   int    msgid;
   LDAP * ld;

   ld  = lud->ld;

   if ((err = ldap_search_ext(ld, lud->basedn, lud->scope, lud->filter, lud->attrs, 0, NULL, NULL, NULL, -1, &msgid)) != LDAP_SUCCESS)
   {
      ldap_unbind_ext_s(ld, NULL, NULL);
      return(err);
   };

   switch((err = ldap_result(ld, msgid, LDAP_MSG_ALL, NULL, resp)))
   {
      case 0:
      break;

      case -1:
      ldap_unbind_ext_s(ld, NULL, NULL);
      return(err);

      default:
      break;
   };

   rc = ldap_parse_result(ld, *resp, &err, NULL, NULL, NULL, NULL, 0);
   if (rc != LDAP_SUCCESS)
   {
      ldap_unbind_ext_s(ld, NULL, NULL);
      return(rc);
   };
   if (err != LDAP_SUCCESS)
   {
      ldap_unbind_ext_s(ld, NULL, NULL);
      return(err);
   };

   return(LDAP_SUCCESS);
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
