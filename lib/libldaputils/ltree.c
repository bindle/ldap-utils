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

typedef struct ldap_utils_tree_recur LDAPUtilsTreeRecursion;

struct ldap_utils_tree_recur
{
   char                * map;
   size_t                prevempty;
   LDAPUtilsTreeOpts   * opts;
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

void ldaputils_tree_print_bullets(LDAPUtilsTree * tree, LDAPUtilsTreeOpts * opts);

void ldaputils_tree_print_bullets_recursive(LDAPUtilsTree * tree, size_t level);

void ldaputils_tree_print_indent(LDAPUtilsTree * tree, size_t level, LDAPUtilsTreeRecursion * recur);

void ldaputils_tree_print_recursive(LDAPUtilsTree * tree, size_t level, LDAPUtilsTreeRecursion * recur);

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


void ldaputils_tree_print(LDAPUtilsTree * tree, LDAPUtilsTreeOpts * opts)
{
   size_t                    x;
   size_t                    depth;
   LDAPUtilsTree           * child;
   char                      dn[512];
   char                      tmp[512];
   LDAPUtilsTreeRecursion    recur;

   assert(tree != NULL);
   assert(opts != NULL);

   recur.opts = opts;

   // initializes delmiter map
   depth = ldaputils_tree_level_count(tree);
   if ((recur.map = malloc(depth+1)) == NULL)
      return;
   for(x = 0; x < depth; x++)
      recur.map[x] = ' ';
   recur.map[x] = '\0';

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
      if (opts->style == LDAPUTILS_TREE_BULLETS)
         printf("* %s\n", dn);
      else
         printf("+--%s\n", dn);
      ldaputils_tree_print_recursive(child, 0, &recur);

      printf("\n");
   };

   free(recur.map);

   return;
}

void ldaputils_tree_print_indent(LDAPUtilsTree * tree, size_t level, LDAPUtilsTreeRecursion * recur)
{
   size_t y;

   assert(tree  != NULL);
   assert(recur != NULL);

   // prints indent string
   switch(recur->opts->style)
   {
      case LDAPUTILS_TREE_BULLETS:
      for(y = 0; y < level; y++)
         printf("  ");
      break;

      default:
      printf("  ");
      for(y = 1; y < level; y++)
         printf("  %c", recur->map[y]);
      break;
   };
}


void ldaputils_tree_print_recursive(LDAPUtilsTree * tree, size_t level, LDAPUtilsTreeRecursion * recur)
{
   size_t x;
   size_t y;
   size_t z;
   size_t stop;
   size_t noleaf;
   size_t leaf_count;
   size_t children_count;
   size_t have_children;

   LDAPUtilsEntry * entry;
   size_t           attr;
   size_t           val;

   assert(tree != NULL);

   level++;

   if ((level >= recur->opts->maxdepth) && ((recur->opts->maxdepth)))
      return;

   // loops through children
   noleaf         = recur->opts->noleaf;
   stop           = 0;
   children_count = 0;
   leaf_count     = 0;
   for(x = 0; ((x < tree->children_len) && (!(stop))); x++)
   {
      if (tree->children[x]->children_len == 0)
      {
         if ((noleaf))
            continue;
         leaf_count++;
         if ( ((leaf_count+1) > recur->opts->maxleafs) && ((recur->opts->maxleafs)) )
            noleaf = 1;
      };
      children_count++;

      // prints indent string
      ldaputils_tree_print_indent(tree, level, recur);

      // checks for last non-leaf node
      if ((noleaf))
      {
         stop = 1;
         for(y = (x+1); y < tree->children_len; y++)
            if (tree->children[y]->children_len != 0)
            {
               y = tree->children_len;
               stop = 0;
            };
      };

      // checks for max children
      if ( ((recur->opts->maxchildren)) && (children_count >= recur->opts->maxchildren))
         stop = 1;

      // print RDN and update indent map
      if (recur->opts->style == LDAPUTILS_TREE_BULLETS)
      {
         printf("* %s\n", tree->children[x]->rdn);
      } else if ( ((x+1) < tree->children_len) && (!(stop)) ) {
         recur->map[level] = '|';
         printf("  +--%s\n", tree->children[x]->rdn);
      } else {
         recur->map[level] = ' ';
         printf("  \\--%s\n", tree->children[x]->rdn);
      };

      // prints requested attributes
      if ((entry = tree->children[x]->entry) != NULL)
      {
         // determines if there are children of this node
         if (recur->opts->noleaf)
         {
            have_children = 0;
            for(z = 0; ((z < tree->children[x]->children_len)&&((!(have_children)))); z++)
               have_children = (tree->children[x]->children[z]->children_len > 0) ? 1 : 0;
         } else {
            have_children = (tree->children[x]->children_len) ? 1 : 0;
         };

         if ((recur->opts->style == LDAPUTILS_TREE_BULLETS) && (entry->attrs_count > 0))
         {
            ldaputils_tree_print_indent(tree, level, recur);
            printf("  * Attributes\n");
         };

         // loops through attributes
         for (attr = 0; attr < entry->attrs_count; attr++)
         {
            // loops through values
            ldaputils_tree_print_indent(tree, level+1, recur);
            for(val = 0; ((entry->attrs[attr]->vals[val])); val++)
            {
               // prints attribute and value
               if (recur->opts->style == LDAPUTILS_TREE_BULLETS)
               {
                  printf("  - %s: %s\n", entry->attrs[attr]->name, entry->attrs[attr]->vals[val]->bv_val);
               } else {
                  printf("  %c  %s: %s\n", (have_children) ? '|' : ' ', entry->attrs[attr]->name, entry->attrs[attr]->vals[val]->bv_val);
               };
            };
         };

         // prints empty line to attributes more readable in hierarchy in style
         if (recur->opts->style == LDAPUTILS_TREE_BULLETS)
         {
            if (!(recur->opts->compact))
            {
               ldaputils_tree_print_indent(tree, level, recur);
               printf("\n");
            };
         } else if ((entry->attrs_count > 0) && (!(recur->opts->compact)))
         {
            if ( (!(stop)) || ((have_children)) )
            {
               ldaputils_tree_print_indent(tree, level+1, recur);
               if ((have_children))
                  printf("  |\n");
               else
                  printf("\n");
            };
         };
      };

      // recurses to next child
      ldaputils_tree_print_recursive(tree->children[x], level, recur);
   };

   if ((recur->opts->compact))
      return;
   if (recur->opts->style == LDAPUTILS_TREE_BULLETS)
      return;

   if (children_count == 0)
   {
      recur->prevempty = 0;
      return;
   };
   if ((recur->prevempty))
      return;
   recur->prevempty = 1;
   ldaputils_tree_print_indent(tree, level, recur);
   printf("\n");

   return;
}


/* end of source file */
