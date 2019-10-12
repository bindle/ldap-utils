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


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Prototypes
#endif

int ldaputils_attribute_add_values(LDAPUtilsAttribute * attr, struct berval ** vals);
LDAPUtilsAttribute * ldaputils_attribute_copy(LDAPUtilsAttribute * attr);
void ldaputils_attribute_free(LDAPUtilsAttribute * attr);
LDAPUtilsAttribute * ldaputils_attribute_initialize(const char * name, struct berval **vals);

int ldaputils_entry_add_attribute(LDAPUtilsEntry * entry, const char * name, struct berval ** vals);
LDAPUtilsEntry * ldaputils_entry_initialize(const char * dn);

int ldaputils_entries_add_entry(LDAPUtilsEntries * entries, LDAPUtilsEntry * entry);

// initializes list of entries
LDAPUtilsEntries * ldaputils_entries_initialize(void);

struct berval ** ldaputils_values_len_copy(struct berval ** vals);

/////////////////
//             //
//  Functions  //
//             //
/////////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Functions
#endif

int ldaputils_attribute_add_values(LDAPUtilsAttribute * attr, struct berval ** vals)
{
   size_t          len;
   size_t          u;
   struct berval * val;
   void          * ptr;

   assert(attr != NULL);
   assert(vals != NULL);

   // count values
   for(len = 0; ((vals[len])); len++);

   // increase size of array
   if ((ptr = realloc(attr->vals, (sizeof(struct berval *)*(len+attr->len+1)))) == NULL)
      return(LDAP_SUCCESS);
   attr->vals = ptr;

   // add bervals
   for (u = 0; u < len; u++)
   {
      // allocate berval
      if ((val = malloc(sizeof(struct berval))) == NULL)
         return(LDAP_NO_MEMORY);
      bzero(val, sizeof(struct berval));

      // populate berval
      val->bv_len = vals[u]->bv_len;
      if ((val->bv_val = malloc(val->bv_len)) == NULL)
      {
         free(val);
         return(LDAP_NO_MEMORY);
      };
      memcpy(val->bv_val, vals[u]->bv_val, vals[u]->bv_len);

      // add berval to list
      attr->vals[attr->len+0] = val;
      attr->vals[attr->len+1] = NULL;
      attr->len++;
   };

   // sort values
   ldaputils_values_sort(attr->vals);

   return(LDAP_SUCCESS);
}


LDAPUtilsAttribute * ldaputils_attribute_copy(LDAPUtilsAttribute * attr)
{
   LDAPUtilsAttribute * new;

   assert(attr != NULL);

   if ((new = malloc(sizeof(LDAPUtilsAttribute))) == NULL)
      return(NULL);
   bzero(new, sizeof(LDAPUtilsAttribute));

   if ((new->vals = ldaputils_values_len_copy(attr->vals)) == NULL)
   {
      ldaputils_attribute_free(new);
      return(NULL);
   };
   new->len = attr->len;

   if ((new->name = strdup(attr->name)) == NULL)
   {
      ldaputils_attribute_free(new);
      return(NULL);
   };

   return(new);
}


void ldaputils_attribute_free(LDAPUtilsAttribute * attr)
{
   assert(attr != NULL);

   if ((attr->vals))
      ldap_value_free_len(attr->vals);

   if ((attr->name))
      free(attr->name);

   free(attr);

   return;
}


LDAPUtilsAttribute * ldaputils_attribute_initialize(const char * name, struct berval **vals)
{
   int                  err;
   LDAPUtilsAttribute * attr;

   assert(name != NULL);

   if ((attr = malloc(sizeof(LDAPUtilsAttribute))) == NULL)
      return(NULL);
   bzero(attr, sizeof(LDAPUtilsAttribute));

   if ((attr->name = strdup(name)) == NULL)
   {
      ldaputils_attribute_free(attr);
      return(NULL);
   };

   if (!(vals))
      return(attr);

   // count entries
   if ((err = ldaputils_attribute_add_values(attr, vals)) != LDAP_SUCCESS)
   {
      ldaputils_attribute_free(attr);
      return(NULL);
   };

   return(attr);
}


/// compares two LDAP values for sorting
/// @param[in] ptr1   pointer to first data item to compare
/// @param[in] ptr2   pointer to second data item to compare
int ldaputils_berval_cmp(const struct berval ** ptr1, const struct berval ** ptr2)
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


// initializes list of entries
int ldaputils_entries_add_entry(LDAPUtilsEntries * entries, LDAPUtilsEntry * entry)
{
   size_t            len;
   LDAPUtilsEntry ** list;

   assert(entries != NULL);
   assert(entry   != NULL);

   // increase size of entry array
   len = sizeof(LDAPUtilsEntry *) * (entries->count + 2);
   if ((list = realloc(entries->list, len)) == NULL)
      return(LDAP_NO_MEMORY);
   entries->list = list;

   // save entry reference to list
   entries->list[entries->count++] = entry;
   entries->list[entries->count]   = NULL;

   return(LDAP_SUCCESS);
}


/// frees list of entries
/// @param[in] entries   list of entries to free
void ldaputils_entries_free(LDAPUtilsEntries * entries)
{
   size_t  x;

   assert(entries != NULL);

   if ((entries->list))
   {
      for(x = 0; x < entries->count; x++)
         ldaputils_entry_free(entries->list[x]);
      free(entries->list);
   };

   free(entries);
   
   return;
}


// initializes list of entries
LDAPUtilsEntries * ldaputils_entries_initialize(void)
{
   LDAPUtilsEntries * entries;

   // initialize memory
   if ((entries = malloc(sizeof(LDAPUtilsEntries))) == NULL)
      return(NULL);
   bzero(entries, sizeof(LDAPUtilsEntries));

   // initialize list
   if ((entries->list = malloc(sizeof(LDAPUtilsEntry *))) == NULL)
   {
      ldaputils_entries_free(entries);
      return(NULL);
   };
   bzero(entries->list, sizeof(LDAPUtilsEntry *));

   return(entries);
}


/// sorts values
/// @param[in] entries   list of attribute values to sort
int ldaputils_entries_sort(LDAPUtilsEntries * entries, int (*compar)(const void *, const void *))
{
   assert(entries != NULL);

   if (compar == NULL)
      compar = ldaputils_entry_cmp;
   qsort(entries->list, entries->count, sizeof(LDAPUtilsEntry *), compar);
   return(0);
}


int ldaputils_entry_add_attribute(LDAPUtilsEntry * entry, const char * name, struct berval ** vals)
{
   size_t               u;
   size_t               size;
   int                  err;
   void               * ptr;
   LDAPUtilsAttribute * attr;

   assert(entry != NULL);
   assert(name  != NULL);

   // find existing attribute
   attr = NULL;
   for(u = 0; u < entry->attrs_count; u++)
   {
      if (!(strcmp(entry->attrs[u]->name, name)))
      {
         attr = entry->attrs[u];
         u = entry->attrs_count;
      };
   };

   // adds values
   if ((attr))
   {
      if ((err = ldaputils_attribute_add_values(attr, vals)) != LDAP_SUCCESS)
         return(err);
      return(LDAP_SUCCESS);
   };

   // resize attribute array
   size = sizeof(LDAPUtilsAttribute *) * (entry->attrs_count + 2);
   if ((ptr = realloc(entry->attrs, size)) == NULL)
      return(LDAP_NO_MEMORY);
   entry->attrs                       = ptr;
   entry->attrs[entry->attrs_count+0] = NULL;
   entry->attrs[entry->attrs_count+1] = NULL;

   // allocate and assign attributes
   if ((entry->attrs[entry->attrs_count] = ldaputils_attribute_initialize(name, vals)) == NULL)
      return(LDAP_NO_MEMORY);
   entry->attrs_count++;

   return(LDAP_SUCCESS);
}


/// compares two LDAP values for sorting
/// @param[in] ptr1   pointer to first data item to compare
/// @param[in] ptr2   pointer to second data item to compare
int ldaputils_entry_cmp(const void * ptr1, const void * ptr2)
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
      return(ldaputils_entry_cmp_dn(ptr1, ptr2));
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
   return(ldaputils_entry_cmp_dn(ptr1, ptr2));
}


/// compares two LDAP values for sorting
/// @param[in] ptr1   pointer to first data item to compare
/// @param[in] ptr2   pointer to second data item to compare
int ldaputils_entry_cmp_dn(const void * ptr1, const void * ptr2)
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


LDAPUtilsEntry * ldaputils_entry_copy(LDAPUtilsEntry * entry)
{
   size_t           x;
   size_t           size;
   LDAPUtilsEntry * new;

   assert(entry != NULL);

   // initialize
   if ((new = ldaputils_entry_initialize(entry->dn)))
      return(NULL);

   // initialize  attributes list
   size = sizeof(LDAPUtilsEntry *) * (entry->attrs_count+1);
   if ((new->attrs = malloc(size)) == NULL)
   {
      ldaputils_entry_free(new);
      return(NULL);
   };
   bzero(new->attrs, size);

   // copy attributes
   for(x = 0; x < entry->attrs_count; x++)
   {
      if ((new->attrs[x] = ldaputils_attribute_copy(entry->attrs[x])) == NULL)
      {
         ldaputils_entry_free(new);
         return(NULL);
      };
   };

   return(new);
}


// initializes list of entries
void ldaputils_entry_free(LDAPUtilsEntry * entry)
{
   int  y;

   assert(entry != NULL);

   if (entry->dn != NULL)
      ldap_memfree(entry->dn);
   entry->dn = NULL;

   // frees sort value
   if (entry->sortval != NULL)
      free(entry->sortval);

   // frees DN components
   if (entry->components != NULL)
      free(entry->components);

   // frees attributes
   if (entry->attrs != NULL)
   {
      for(y = 0; (entry->attrs[y] != NULL); y++)
      {
         // frees attribute name
         if (entry->attrs[y]->name != NULL)
            ldap_memfree(entry->attrs[y]->name);

         // frees attribute values
         if (entry->attrs[y]->vals != NULL)
            ldap_value_free_len(entry->attrs[y]->vals);

         // frees attribute
         free(entry->attrs[y]);
      };
      free(entry->attrs);
      entry->attrs = NULL;
   };

   free(entry);

   return;
}


// initializes list of entries
LDAPUtilsEntry * ldaputils_entry_initialize(const char * dn)
{
   size_t           len;
   size_t           u;
   char           * str;
   LDAPUtilsEntry * entry;

   // initialize memory
   if ((entry = malloc(sizeof(LDAPUtilsEntry))) == NULL)
      return(NULL);
   bzero(entry, sizeof(LDAPUtilsEntry));

   // copy dn
   if ((entry->dn = strdup(dn)) == NULL)
   {
      free(entry);
      return(NULL);
   };

   // breaks DN into components
   if ((entry->components = ldap_explode_dn(entry->dn, 0)) == NULL)
   {
      ldaputils_entry_free(entry);
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

   return(entry);
}


LDAPUtilsEntry * ldaputils_first_entry(LDAPUtilsEntries * entries)
{
   assert(entries != NULL);
   entries->cursor = 0;
   return(ldaputils_next_entry(entries));
}


LDAPUtilsEntry * ldaputils_next_entry(LDAPUtilsEntries * entries)
{
   assert(entries != NULL);
   if (entries->cursor < entries->count)
      return(entries->list[entries->cursor++]);
   return(NULL);
}


/// retrieves LDAP entries from result
/// @param[in] ld      refernce to LDAP socket data
/// @param[in] res     refernce to LDAP result message
LDAPUtilsEntries * ldaputils_get_entries(LDAP * ld, LDAPMessage * res,
   const char * sortattr)
{
   int                   err;
   char                * name;
   char                * str;
   BerElement          * ber;
   LDAPMessage         * msg;
   struct berval      ** vals;
   LDAPUtilsEntry      * entry;
   LDAPUtilsEntries    * entries;

   assert(ld  != NULL);
   assert(res != NULL);

   if ((entries = ldaputils_entries_initialize()) == NULL)
      return(NULL);

   msg = ldap_first_entry(ld, res);
   while(msg)
   {
      // initial entry
      if ((str = ldap_get_dn(ld, msg)) == NULL)
      {
         ldaputils_entries_free(entries);
         return(NULL);
      };
      if ((entry = ldaputils_entry_initialize(str)) == NULL)
      {
         free(str);
         ldaputils_entries_free(entries);
         return(NULL);
      };
      free(str);

      // retrieves attributes
      name = ldap_first_attribute(ld, msg, &ber);
      while(name != NULL)
      {
         // retrieve values
         if ((vals = ldap_get_values_len(ld, msg, name)) != NULL)
         {
            ldaputils_entry_add_attribute(entry, name, vals);
            if ( ((sortattr)) && (!(strcasecmp(sortattr, name))) )
            {
               ldaputils_values_sort(vals);
               entry->sortval = strdup(vals[0]->bv_val);
            };
            ldap_value_free_len(vals);
         };

         name = ldap_next_attribute(ld, msg, ber);
      };
      ber_free(ber, 0);

      if ((err = ldaputils_entries_add_entry(entries, entry)) != LDAP_SUCCESS)
         ldaputils_entry_free(entry);
      
      msg = ldap_next_entry(ld, msg);
   };
   
   return(entries);
}

int ldaputils_count_entries(LDAPUtilsEntries * entries)
{
   assert(entries != NULL);
   return((int)entries->count);
}


const char * ldaputils_get_dn(LDAPUtilsEntry * entry)
{
   assert(entry != NULL);
   return(entry->dn);
}


const char * const * ldaputils_get_dn_components(LDAPUtilsEntry * entry, size_t * lenp)
{
   assert(entry != NULL);
   if ((lenp))
      *lenp = entry->components_len;
   return((const char * const *)entry->components);
}


const char * ldaputils_get_rdn(LDAPUtilsEntry * entry)
{
   assert(entry != NULL);
   return(entry->rdn);
}


struct berval ** ldaputils_values_len_copy(struct berval ** vals)
{
   size_t           x;
   size_t           len;
   size_t           size;
   struct berval ** newvals;

   assert(vals != NULL);

   // count values
   for(len = 0; ((vals[len])); len++);

   // create array
   size = sizeof(struct berval *) * (len + 1);
   if ((newvals = malloc(size)) == NULL)
      return(NULL);
   bzero(newvals, size);

   // copy values into array
   for(x = 0; ((vals[x])); x++)
   {
      // allocate new berval
      if ((newvals[x] = malloc(sizeof(struct berval))) == NULL)
      {
         ldap_value_free_len(newvals);
         return(NULL);
      };

      // copy value
      if ((newvals[x]->bv_val = malloc(vals[x]->bv_len)) == NULL)
      {
         ldap_value_free_len(newvals);
         return(NULL);
      };
      memcpy(newvals[x]->bv_val, vals[x]->bv_val, vals[x]->bv_len);
      newvals[x]->bv_len = vals[x]->bv_len;
   };

   return(newvals);
}


/// sorts values
/// @param[in] vals   list of attribute values to sort
int ldaputils_values_sort(struct berval ** vals)
{
   size_t  len;
   if (!(vals))
      return(1);
   for(len = 0; ((vals[len])); len++);
   qsort(vals, len, sizeof(char *), (int (*)(const void *, const void *))ldaputils_berval_cmp);
   return(0);
}

/* end of source file */
