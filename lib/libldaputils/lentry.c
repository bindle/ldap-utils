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
 *  @file lib/libldaputils/lentry.c  contains shared functions and variables
 */
#define _LIB_LIBLDAPUTILS_LENTRY_C 1
#include "lentry.h"

///////////////
//           //
//  Headers  //
//           //
///////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Headers
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <ldap.h>
#include <stdlib.h>
#include <assert.h>

#include "lconfig.h"


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Functions
#endif

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
int ldaputils_cmp_entry(const void * ptr1, const void * ptr2)
{
   int rc;
   const LDAPUtilsEntry   * e1;
   const LDAPUtilsEntry   * e2;

   assert(ptr1 != NULL);
   assert(ptr2 != NULL);

   e1 = *((const LDAPUtilsEntry * const *)ptr1);
   e2 = *((const LDAPUtilsEntry * const *)ptr2);

   // quick check of the pointers
   if ( (!(e1)) && (!(e2)) )
      return(0);
   if (!(e1))
      return(-1);
   if (!(e2))
      return(1);

   // quick check of the pointers
   if ( (!(e1->sortval)) && (!(e2->sortval)) )
      return(ldaputils_cmp_entrydn(ptr1, ptr2));
   if (!(e1->sortval))
      return(-1);
   if (!(e2->sortval))
      return(1);
   
   // compare of sort value
   if ((rc = strcasecmp(e1->sortval, e2->sortval)))
      return(rc);
   if ((rc = strcmp(e1->sortval, e2->sortval)))
      return(rc);

   // compare of DN
   return(ldaputils_cmp_entrydn(ptr1, ptr2));
}


/// compares two LDAP values for sorting
/// @param[in] ptr1   pointer to first data item to compare
/// @param[in] ptr2   pointer to second data item to compare
int ldaputils_cmp_entrydn(const void * ptr1, const void * ptr2)
{
   int                      rc;
   size_t                   u;
   size_t                   complen;
   const LDAPUtilsEntry   * e1;
   const LDAPUtilsEntry   * e2;

   assert(ptr1 != NULL);
   assert(ptr2 != NULL);

   e1 = *((const LDAPUtilsEntry * const *)ptr1);
   e2 = *((const LDAPUtilsEntry * const *)ptr2);

   // quick check of the pointers
   if ( (!(e1)) && (!(e2)) )
      return(0);
   if (!(e1))
      return(-1);
   if (!(e2))
      return(1);

   if ( (!(e1->components)) || (!(e2->components)) )
   {
      if ((rc = strcasecmp(e1->dn, e2->dn)))
         return(rc);
      return(strcmp(e1->dn, e2->dn));
   };

   // determine minimum number of DN components
   complen = (e1->components_len < e2->components_len) ? e1->components_len : e2->components_len;

   // case insensitive compare of DN components
   for(u = 0; u < complen; u++)
      if ((rc = strcasecmp(e1->components[u], e2->components[u])))
         return(rc);

   // compare DN compnent counts
   if (e1->components_len < e2->components_len)
      return(-1);
   if (e1->components_len > e2->components_len)
      return(1);

   // case sensitive compare of DN components
   for(u = 0; u < complen; u++)
       if ((rc = strcmp(e1->components[u], e2->components[u])))
         return(rc);

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

      // frees DN components
      if (entries[x]->components != NULL)
         free(entries[x]->components);

      // frees attributes
      if (entries[x]->attrs != NULL)
      {
         for(y = 0; (entries[x]->attrs[y] != NULL); y++)
         {
            // frees attribute name
            if (entries[x]->attrs[y]->name != NULL)
               ldap_memfree(entries[x]->attrs[y]->name);

            // frees attribute values
            if (entries[x]->attrs[y]->vals != NULL)
               ldap_value_free_len(entries[x]->attrs[y]->vals);

            // frees attribute
            free(entries[x]->attrs[y]);
         };
         free(entries[x]->attrs);
         entries[x]->attrs = NULL;
      };
      free(entries[x]);
   };
   free(entries);
   
   return;
}


/// retrieves LDAP entries from result
/// @param[in] ld      refernce to LDAP socket data
/// @param[in] res     refernce to LDAP result message
LDAPUtilsEntry ** ldaputils_get_entries(LDAP * ld, LDAPMessage * res,
   const char * sortattr)
{
   char                * name;
   char                * str;
   void                * ptr;
   size_t                u;
   size_t                len;
   size_t                entry_count;
   BerElement          * ber;
   LDAPMessage         * msg;
   LDAPUtilsEntry      * entry;
   LDAPUtilsEntry     ** entries;
   LDAPUtilsAttribute  * attr;

   assert(ld  != NULL);
   assert(res != NULL);

   entries     = NULL;
   entry_count = 0;

   msg = ldap_first_entry(ld, res);
   while(msg)
   {
      // allocates entry
      if ( (entry = malloc(sizeof(LDAPUtilsEntry))) == NULL )
      {
         ldaputils_free_entries(entries);
         return(NULL);
      };
      memset(entry, 0, sizeof(LDAPUtilsEntry));

      // increases size of entry list
      entry_count++;
      if ((ptr = realloc(entries, sizeof(LDAPUtilsEntry *) * (entry_count+1))) == NULL)
      {
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
         ldaputils_free_entries(entries);
         return(NULL);
      };

      // breaks DN into components
      if ((entry->components = ldap_explode_dn(entry->dn, 0)) == NULL)
      {
         ldaputils_free_entries(entries);
         return(NULL);
      };
      entry->rdn = entry->components[0];
      for(len = 0; (entry->components[len] != NULL); len++);
      entry->components_len = len;
      for(u = 0; (u < (len/2)); u++)
      {
         str                        = entry->components[u];
         entry->components[u]       = entry->components[len-u-1];
         entry->components[len-u-1] = str;
      };

      // retrieves attributes
      name = ldap_first_attribute(ld, msg, &ber);
      while(name != NULL)
      {
         // allocates attribute
         if (!(attr = malloc(sizeof(LDAPUtilsAttribute))))
         {
            ldaputils_free_entries(entries);
            return(NULL);
         };
         memset(attr, 0, sizeof(LDAPUtilsAttribute));

         // increases size of attribute list
         entry->attrs_count++;
         if (!(ptr = realloc(entry->attrs, sizeof(LDAPUtilsAttribute *) * (entry->attrs_count+1))))
         {
            free(attr);
            ldaputils_free_entries(entries);
            return(NULL);
         };
         entry->attrs                 = ptr;
         entry->attrs[entry->attrs_count-1] = attr;
         entry->attrs[entry->attrs_count-0] = NULL;

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
   for(x = 0; entry->attrs[x]; x++)
      if (!(strcasecmp(entry->attrs[x]->name, attr)))
         vals = entry->attrs[x]->vals;
   
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


/// sorts values
/// @param[in] entries   list of attribute values to sort
int ldaputils_sort_entries(LDAPUtilsEntry ** entries, int (*compar)(const void *, const void *))
{
   size_t  len;
   if (!(entries))
      return(1);
   for(len = 0; entries[len]; len++);
   qsort(entries, len, sizeof(LDAPUtilsEntry *), compar);
//   qsort(entries, len, sizeof(LDAPUtilsEntry *), (int (*)(const void *, const void *))ldaputils_cmp_entry);
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
