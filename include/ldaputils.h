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
/*
 *  include/ldap-utils.h - common includes and prototypes
 */
#ifndef __LDAPUTILS_H
#define __LDAPUTILS_H 1

///////////////
//           //
//  Headers  //
//           //
///////////////
// MARK: - Headers

#include <ldaputils_cdefs.h>

#include <inttypes.h>


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
// MARK: - Definitions

#ifndef PACKAGE_BUGREPORT
#define PACKAGE_BUGREPORT ""
#endif
#ifndef PACKAGE_COPYRIGHT
#define PACKAGE_COPYRIGHT "Copyright (C) 2008 David M. Syzdek."
#endif
#ifndef PACKAGE_NAME
#define PACKAGE_NAME "LDAP Utilities"
#endif
#ifndef PACKAGE_TARNAME
#define PACKAGE_TARNAME "ldap-utils"
#endif
#ifndef PACKAGE_VERSION
#define PACKAGE_VERSION ""
#endif


#define LDAPUTILS_BUFF_LEN                 4096
#define LDAPUTILS_OPT_LEN                  128


#define LDAPUTILS_OPTIONS_COMMON           "cd:D:hH:np:P:uvVw:Wxy:Y:Z"
#define LDAPUTILS_OPTIONS_SEARCH           "b:l:Ls:S:z:"


#define LDAPUTILS_TREE_HIERARCHY           0x0000
#define LDAPUTILS_TREE_BULLETS             0x0001


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
// MARK: - Datatypes

typedef struct ldap_utils_attribute    LDAPUtilsAttribute;
typedef struct ldap_utils_entry        LDAPUtilsEntry;
typedef struct ldap_utils_entries      LDAPUtilsEntries;
typedef struct ldap_utils_tree         LDAPUtilsTree;
typedef struct ldaputils_config_struct LDAPUtils;
typedef struct ldap_utils_tree_opts    LDAPUtilsTreeOpts;

struct ldap_utils_tree_opts
{
   size_t    noleaf;
   size_t    maxdepth;
   size_t    maxleafs;
   size_t    maxchildren;
   size_t    style;
   size_t    compact;
   size_t    expandall;
};


// store common structs
struct ldaputils_config_struct
{
   LDAP *            ld;           ///< LDAP descriptor
   const char *      prog_name;    ///< program name
   int               continuous;   // -c continuous operation mode
   int               dryrun;       // -n dry run mode
   int               scope;        // -s LDAP search scope
   int               tls_req;      // -Z use TLS
   int               silent;       // -L
   int               verbose;      // -v verbose mode
   int               want_pass;    // -W prompt for passowrd
   int               pad0;
   struct berval     passwd;       //    stores password from -y, -w, and -W
   char **           attrs;        //    result attributes
   const char *      sasl_mech;    // -Y sasl mechanism
   const char *      binddn;       // -D bind DN
   const char *      filter;       //    search filter
   const char *      passfile;     // -y password file
   const char *      sortattr;     // -S sort by attribute
};


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
// MARK: - Prototypes
LDAPUTILS_BEGIN_C_DECLS


//---------------------//
// password prototypes //
//---------------------//
// MARK: password prototypes

_LDAPUTILS_F char *
ldaputils_getpass(
         const char *                  prompt );


_LDAPUTILS_F int
ldaputils_pass(
         LDAPUtils *                   lud );


//-------------------------------//
// entries amd values prototypes //
//-------------------------------//
// MARK: entries amd values prototypes

_LDAPUTILS_F int
ldaputils_berval_cmp(
         const struct berval **        ptr1,
         const struct berval **        ptr2 );


_LDAPUTILS_F void
ldaputils_entries_free(
         LDAPUtilsEntries *            entries );


_LDAPUTILS_F int
ldaputils_entries_sort(
         LDAPUtilsEntries *            entries,
         int                           (*compar)(const void *, const void *) );


_LDAPUTILS_F int
ldaputils_entry_cmp(
         const void *                  ptr1,
         const void *                  ptr2 );


_LDAPUTILS_F int
ldaputils_entry_cmp_dn(
         const void *                  ptr1,
         const void *                  ptr2 );


_LDAPUTILS_F void
ldaputils_entry_free(
         LDAPUtilsEntry *              entry );


_LDAPUTILS_F int
ldaputils_count_entries(
         LDAPUtilsEntries *            entries );


_LDAPUTILS_F LDAPUtilsEntry *
ldaputils_first_entry(
         LDAPUtilsEntries *            entries );


_LDAPUTILS_F LDAPUtilsEntry *
ldaputils_next_entry(
         LDAPUtilsEntries *            entries );


_LDAPUTILS_F LDAPUtilsEntries *
ldaputils_get_entries(
         LDAP *                        ld,
         LDAPMessage *                 res,
         const char *                  sortattr );


_LDAPUTILS_F char **
ldaputils_get_values(
            LDAP *                     ld,
            LDAPMessage *              entry,
            const char *               attr );


_LDAPUTILS_F void
ldaputils_value_free(
            char **                    vals );


_LDAPUTILS_F void
ldaputils_value_free_len(
            struct berval **           vals );


_LDAPUTILS_F int
ldaputils_values_sort(
            struct berval **           vals );


//----------------------//
// utilities prototypes //
//----------------------//
// MARK: utilities prototypes

_LDAPUTILS_F char *
ldaputils_chomp(
            char *                     str );


//--------------------------//
// configuration prototypes //
//--------------------------//
// MARK: configuration prototypes

_LDAPUTILS_F int
ldaputils_getopt(
            LDAPUtils *                lud,
            int                        c,
            const char *               arg );


_LDAPUTILS_F void
ldaputils_params(
            LDAPUtils *                lud );


_LDAPUTILS_F const char *
ldaputils_get_dn(
            LDAPUtilsEntry *           entry );


_LDAPUTILS_F const char *
ldaputils_get_rdn(
            LDAPUtilsEntry *           entry );


_LDAPUTILS_F const char * const *
ldaputils_get_dn_components(
            LDAPUtilsEntry *           entry,
            size_t *                   lenp );


_LDAPUTILS_F const char *
ldaputils_get_prog_name(
            LDAPUtils *                lud );


_LDAPUTILS_F LDAP *
ldaputils_get_ld(
            LDAPUtils *                lud );


_LDAPUTILS_F const char * const *
ldaputils_get_attribute_list(
            LDAPUtils *                lud );


//------------------//
// usage prototypes //
//------------------//
// MARK: usage prototypes

_LDAPUTILS_F void
ldaputils_usage(
            void );


_LDAPUTILS_F void
ldaputils_usage_common(
            const char *               short_options );


_LDAPUTILS_F void
ldaputils_usage_search(
            const char *               short_options );


_LDAPUTILS_F void
ldaputils_version(
            const char *               prog_name );


//----------------------------//
// LDAP operations prototypes //
//----------------------------//
// MARK: LDAP operations prototypes

_LDAPUTILS_F int
ldaputils_bind_s(
            LDAPUtils *                lud );


_LDAPUTILS_F int
ldaputils_initialize(
            LDAPUtils **               lup,
            const char *               prog_name );


_LDAPUTILS_F int
ldaputils_search(
            LDAPUtils *                lud,
            LDAPMessage **             resp );


_LDAPUTILS_F void
ldaputils_unbind(
            LDAPUtils *                lud );


//----------------------//
// LDAP tree prototypes //
//----------------------//
// MARK: LDAP tree prototypes

_LDAPUTILS_F LDAPUtilsTree *
ldaputils_get_tree(
            LDAP *                     ld,
            LDAPMessage *              res,
            int                        copy );


_LDAPUTILS_F int
ldaputils_tree_add_dn(
            LDAPUtilsTree *            tree,
            const char *               dn,
            LDAPUtilsTree **           nodep );


_LDAPUTILS_F int
ldaputils_tree_add_entry(
            LDAPUtilsTree *            tree,
            LDAPUtilsEntry *           entry,
            int                        copy );


_LDAPUTILS_F void
ldaputils_tree_free(
            LDAPUtilsTree *            tree );


_LDAPUTILS_F LDAPUtilsTree *
ldaputils_tree_initialize(
            LDAPUtilsEntries *         entries,
            int                        copy );


_LDAPUTILS_F size_t
ldaputils_tree_level_count(
            LDAPUtilsTree *            tree,
            LDAPUtilsTreeOpts *        opts );


_LDAPUTILS_F void
ldaputils_tree_print(
            LDAPUtilsTree *            tree,
            LDAPUtilsTreeOpts *        opts );


LDAPUTILS_END_C_DECLS
#endif /* end of header */
