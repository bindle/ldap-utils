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
#define _LIB_LIBLDAPUTILS_LTREE_C 1
#include "ltree.h"

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
#include "lentry.h"


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Datatypes
#endif

struct ldap_utils_tree
{
   char              * rdn;
   LDAPUtilsEntry    * entry;
   LDAPUtilsTree     * parent;
   size_t              children_len;
   LDAPUtilsTree    ** children;
};


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Prototypes
#endif

LDAPUtilsTree * ldaputils_tree_child_init(LDAPUtilsTree * tree, const char * rdn);

int ldaputils_tree_cmp(const void * ptr1, const void * ptr2);

void ldaputils_tree_level_count_recursive(LDAPUtilsTree * tree, size_t level, size_t * depthp);

void ldaputils_tree_print_bullets_recursive(LDAPUtilsTree * tree, size_t level);

void ldaputils_tree_print_hierarchy_recursive(LDAPUtilsTree * tree, size_t level, char * map);


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Functions
#endif

int ldaputils_tree_add_dn(LDAPUtilsTree * tree, const char * dn)
{
   char           ** components;
   size_t            components_len;
   LDAPUtilsTree   * child;
   size_t            cur_chld;
   size_t            cur_comp;

   assert(tree  != NULL);
   assert(dn    != NULL);

   // explode DN into components
   if ((components = ldap_explode_rdn(dn, 0)) == NULL)
      return(LDAP_NO_MEMORY);
   for(components_len = 0; ((components[components_len])); components_len++);

   // loop through DN components
   for (cur_comp = 0; cur_comp < components_len; cur_comp++)
   {
      child = NULL;

      // search for matching child
      for(cur_chld = 0; ((cur_chld < tree->children_len) && (child == NULL)); cur_chld++)
         if (!(strcasecmp(tree->children[cur_chld]->rdn, components[cur_comp])))
            child = tree->children[cur_chld];

      // initialize child if it does not exist
      if (!(child))
      {
         if ((child = ldaputils_tree_child_init(tree, components[cur_comp])))
         {
            ldap_value_free(components);
            return(LDAP_NO_MEMORY);
         };
      };

      // step up to child
      tree = child;
   };

   ldap_value_free(components);

   return(LDAP_SUCCESS);
}


int ldaputils_tree_add_entry(LDAPUtilsTree * tree, LDAPUtilsEntry * entry, int copy)
{
   LDAPUtilsTree * child;
   size_t          cur_chld;
   size_t          cur_comp;

   assert(tree  != NULL);
   assert(entry != NULL);
   assert(copy  != 1);

   // loop through DN components
   for (cur_comp = 0; cur_comp < entry->components_len; cur_comp++)
   {
      child = NULL;

      // search for matching child
      for(cur_chld = 0; ((cur_chld < tree->children_len) && (child == NULL)); cur_chld++)
         if (!(strcasecmp(tree->children[cur_chld]->rdn, entry->components[cur_comp])))
            child = tree->children[cur_chld];

      // initialize child if it does not exist
      if (!(child))
         if ((child = ldaputils_tree_child_init(tree, entry->components[cur_comp])) == NULL)
            return(LDAP_NO_MEMORY);

      // step up to child
      tree = child;
   };

   // copy entry into tree
   if ((copy))
      if ((tree->entry = ldaputils_entry_copy(entry)) == NULL)
         return(LDAP_NO_MEMORY);

   return(LDAP_SUCCESS);
}


int ldaputils_tree_cmp(const void * ptr1, const void * ptr2)
{
   int                     rc;
   const LDAPUtilsTree   * a;
   const LDAPUtilsTree   * b;

   assert(ptr1 != NULL);
   assert(ptr2 != NULL);

   a = *((const LDAPUtilsTree * const *)ptr1);
   b = *((const LDAPUtilsTree * const *)ptr2);

   // quick check of the pointers
   if ( (!(a)) && (!(b)) )
      return(0);
   if (!(a))
      return(-1);
   if (!(b))
      return(1);

   // quick check of the pointers
   if ( (!(a->rdn)) && (!(b->rdn)) )
      return(ldaputils_entry_cmp_dn(ptr1, ptr2));
   if (!(a->rdn))
      return(-1);
   if (!(b->rdn))
      return(1);

   // compare of sort value
   if ((rc = strcasecmp(a->rdn, b->rdn)))
      return(rc);
   return(strcmp(a->rdn, b->rdn));
}


LDAPUtilsTree * ldaputils_tree_child_init(LDAPUtilsTree * tree, const char * rdn)
{
   LDAPUtilsTree * child;
   size_t          size;
   void          * ptr;

   assert(tree  != NULL);
   assert(rdn   != NULL);

   // initialize child
   if ((child = malloc(sizeof(LDAPUtilsTree))) == NULL)
      return(NULL);
   bzero(child, sizeof(LDAPUtilsTree));

   // copy RDN
   if ((child->rdn = strdup(rdn)) == NULL)
   {
      ldaputils_tree_free(child);
      return(NULL);
   };

   // increase size of children list
   size = sizeof(LDAPUtilsTree *) * (tree->children_len + 2);
   if ((ptr = realloc(tree->children, size)) == NULL)
   {
      ldaputils_tree_free(child);
      return(NULL);
   };
   tree->children = ptr;

   // save child to children list
   child->parent                        = tree;
   tree->children[tree->children_len++] = child;
   tree->children[tree->children_len]   = NULL;

   // sort children list
   qsort(tree->children, tree->children_len, sizeof(LDAPUtilsTree *), (int (*)(const void *, const void *))ldaputils_tree_cmp);

   return(child);
}


void ldaputils_tree_free(LDAPUtilsTree * tree)
{
   LDAPUtilsTree * child;
   LDAPUtilsTree * parent;

   assert(tree != NULL);

   parent = NULL;
   child  = tree;

   while(child != NULL)
   {
      // traverse to end of tree
      while(child->children_len > 0)
         child = child->children[(child->children_len--)-1];
      parent = child->parent;

      // free RDN
      if ((child->rdn))
      {
         free(child->rdn);
         child->rdn = NULL;
      };

      // free entry
      if ((child->entry))
      {
         ldaputils_entry_free(child->entry);
         child->entry = NULL;
      };

      // free children array
      if ((child->children))
      {
         free(child->children);
         child->children = NULL;
      };

      // free node
      free(child);

      child = parent;
   };

   return;
}


LDAPUtilsTree * ldaputils_tree_initialize(LDAPUtilsEntries * entries, int copy)
{
   LDAPUtilsTree   * tree;
   size_t            x;
   int               err;

   // initialize root of tree
   if ((tree = malloc(sizeof(LDAPUtilsTree))) == NULL)
      return(NULL);
   bzero(tree, sizeof(LDAPUtilsTree));

   if ((tree->rdn = strdup("")) == NULL)
   {
      ldaputils_tree_free(tree);
      return(NULL);
   };

   if (!(entries))
      return(tree);

   // add entries to tree
   for(x = 0; (x < entries->count); x++)
   {
      if ((err = ldaputils_tree_add_entry(tree, entries->list[x], copy)) != LDAP_SUCCESS)
      {
         ldaputils_tree_free(tree);
         return(NULL);
      };
   };

   return(tree);
}

size_t ldaputils_tree_level_count(LDAPUtilsTree * tree)
{
   size_t          x;
   LDAPUtilsTree * child;
   size_t          depth;

   assert(tree != NULL);

   depth = 0;

   for(x = 0; x < tree->children_len; x++)
   {
      child = tree->children[x];
      while (child->children_len < 2)
         child = child->children[0];
      ldaputils_tree_level_count_recursive(child, 1, &depth);
   };

   return(depth);
}


void ldaputils_tree_level_count_recursive(LDAPUtilsTree * tree, size_t level, size_t * depthp)
{
   size_t x;

   assert(tree   != NULL);
   assert(depthp != NULL);

   level++;

   if (level > *depthp)
      *depthp = level;

   for(x = 0; x < tree->children_len; x++)
      ldaputils_tree_level_count_recursive(tree->children[x], level, depthp);

   return;
}


void ldaputils_tree_print_bullets(LDAPUtilsTree * tree)
{
   size_t          x;
   LDAPUtilsTree * child;
   char            dn[512];
   char            tmp[512];

   assert(tree != NULL);

   for(x = 0; x < tree->children_len; x++)
   {
      snprintf(dn, sizeof(dn), "%s", tree->children[x]->rdn);
      child = tree->children[x];
      while (child->children_len < 2)
      {
         snprintf(tmp, sizeof(tmp), "%s, %s", child->children[0]->rdn, dn);
         strncpy(dn, tmp, sizeof(dn));
         child = child->children[0];
      };
      printf("* %s\n", dn);
      ldaputils_tree_print_bullets_recursive(child, 0);
      printf("\n");
   };

   return;
}


void ldaputils_tree_print_bullets_recursive(LDAPUtilsTree * tree, size_t level)
{
   size_t x;
   size_t y;

   assert(tree != NULL);

   level++;

   for(x = 0; x < tree->children_len; x++)
   {
      for(y = 0; y < level; y++)
         printf("  ");
      printf("* %s\n", tree->children[x]->rdn);
      ldaputils_tree_print_bullets_recursive(tree->children[x], level);
   };

   return;
}


void ldaputils_tree_print_hierarchy(LDAPUtilsTree * tree)
{
   size_t          x;
   size_t          depth;
   char          * map;
   LDAPUtilsTree * child;
   char            dn[512];
   char            tmp[512];

   assert(tree != NULL);

   // initializes delmiter map
   depth = ldaputils_tree_level_count(tree);
   if ((map = malloc(depth+1)) == NULL)
      return;
   for(x = 0; x < depth; x++)
      map[x] = ' ';
   map[x] = '\0';

   // loops through root DNs
   for(x = 0; x < tree->children_len; x++)
   {
      snprintf(dn, sizeof(dn), "%s", tree->children[x]->rdn);
      child = tree->children[x];
      while (child->children_len < 2)
      {
         snprintf(tmp, sizeof(tmp), "%s, %s", child->children[0]->rdn, dn);
         strncpy(dn, tmp, sizeof(dn));
         child = child->children[0];
      };
      printf("+--%s\n", dn);
      ldaputils_tree_print_hierarchy_recursive(child, 0, map);

      printf("\n");
   };

   free(map);

   return;
}


void ldaputils_tree_print_hierarchy_recursive(LDAPUtilsTree * tree, size_t level, char * map)
{
   size_t x;
   size_t y;

   assert(tree != NULL);

   level++;

   for(x = 0; x < tree->children_len; x++)
   {
      for(y = 0; y < level; y++)
         printf("%c  ", map[y]);
      if ((x+1) < tree->children_len)
      {
         map[level] = '|';
         printf("+--%s\n", tree->children[x]->rdn);
      } else {
         map[level] = ' ';
         printf("\\--%s\n", tree->children[x]->rdn);
      };
      ldaputils_tree_print_hierarchy_recursive(tree->children[x], level, map);
   };

   if (tree->children_len == 0)
      return;
   for(y = 0; y < level; y++)
      printf("%c  ", map[y]);
   printf("\n");

   return;
}


/* end of source file */
