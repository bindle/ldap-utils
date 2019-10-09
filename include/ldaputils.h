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
/*
 *  include/ldap-utils.h - common includes and prototypes
 */
#ifndef __LDAPUTILS_H
#define __LDAPUTILS_H 1
#undef  __LDAPUTILS_PMARK

///////////////
//           //
//  Headers  //
//           //
///////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Headers
#endif

#include <ldaputils_cdefs.h>

#include <inttypes.h>
#include <ldap.h>


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Definitions
#endif

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


#ifndef LDAP_VENDOR_NAME
#define LDAP_VENDOR_NAME "Unknown"
#endif
#ifndef LDAP_VENDOR_VERSION
#define LDAP_VENDOR_VERSION 0
#endif


#define LDAPUTILS_BUFF_LEN                 4096
#define LDAPUTILS_OPT_LEN                  128

#define LDAPUTILS_OPTIONS_COMMON           "9cd:D:h:H:Lnp:P:uvVw:Wxy:Y:Z"
#define LDAPUTILS_OPTIONS_SEARCH           "b:l:s:S:z:"


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Datatypes
#endif

typedef struct ldap_utils_attribute LDAPUtilsAttribute;
struct ldap_utils_attribute
{
   char           * name;
   struct berval ** vals;
};


typedef struct ldap_utils_entry LDAPUtilsEntry;
struct ldap_utils_entry
{
   char                * dn;
   const char          * rdn;
   char                * sortval;
   size_t                components_len;
   size_t                attrs_count;
   char               ** components;
   LDAPUtilsAttribute ** attrs;
};


/* store common structs */
typedef struct ldaputils_config_struct   LDAPUtils;
struct ldaputils_config_struct
{
   LDAP         * ld;                          ///< LDAP descriptor
   const char   * prog_name;                   ///< program name
   int            continuous;                  // -c continuous operation mode
   int            dryrun;                      // -n dry run mode
   int            port;                        // -p LDAP server port
   int            scope;                       // -s LDAP search scope
   int            tls_req;                     // -Z use TLS
   int            verbose;                     // -v verbose mode
   int            version;                     // -P LDAP protocol version
   int            want_pass;                   // -W prompt for passowrd
   struct berval  passwd;                      //    stores password from -y, -w, and -W
   char           uribuff[LDAPUTILS_OPT_LEN];
   char        ** attrs;                       //    result attributes
   const char   * sasl_mech;                   // -Y sasl mechanism
   char         * basedn;                      // -b base DN
   const char   * binddn;                      // -D bind DN
   const char   * filter;                      //    search filter
   const char   * host;                        // -h LDAP host
   const char   * passfile;	                 // -y password file
   const char   * sortattr;	                 // -S sort by attribute
   const char   * uri;                         // -H LDAP URI
};


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Prototypes
#endif
LDAPUTILS_BEGIN_C_DECLS

// removes newlines and carriage returns
char * ldaputils_chomp(char * str);

// parses LDAP command line arguments
int ldaputils_cmdargs(LDAPUtils * lud, int c, const char * arg);

// prints configuration to stdout
void ldaputils_config_print(LDAPUtils * lud);

// prints string to stdout
const char * ldaputils_config_print_str(const char * str);

// retrieves password
int ldaputils_pass(LDAPUtils * lud);

// getpass() replacement -- SUSV 2 deprecated getpass()
char * ldaputils_getpass(const char * prompt);

// retrieves password from file
int ldaputils_passfile(LDAPUtils * lud);

// prints program usage and exits
void ldaputils_usage(void);

// displays usage for common options
void ldaputils_usage_common(const char * short_options);

// displays search usage for search options
void ldaputils_usage_search(const char * short_options);

// displays usage
void ldaputils_version(const char * prog_name);

// parses LDAP command line arguments
int ldaputils_common_cmdargs(LDAPUtils * lud, int c, const char * arg);

// compares two LDAP values for sorting
int ldaputils_cmp_berval(const struct berval ** ptr1, const struct berval ** ptr2);

// compares two LDAP values for sorting
int ldaputils_cmp_entry(const void * ptr1, const void * ptr2);

// compares two LDAP entry DNs for sorting
int ldaputils_cmp_entrydn(const void * ptr1, const void * ptr2);

// frees list of entries
void ldaputils_free_entries(LDAPUtilsEntry ** entries);

// retrieves LDAP entries from result
LDAPUtilsEntry ** ldaputils_get_entries(LDAP * ld, LDAPMessage * res,
   const char * sortattr);

// retrieves values of an LDAP attribute
char * ldaputils_get_vals(LDAPUtils * lud, LDAPUtilsEntry * entry,
   const char * attr);

// connects and binds to LDAP server
int ldaputils_initialize(LDAPUtils ** lup, const char * prog_name);

// connects and binds to LDAP server
int ldaputils_bind_s(LDAPUtils * lud);

// connects and binds to LDAP server
int ldaputils_search(LDAPUtils * lud, LDAPMessage ** resp);

// sorts values
int ldaputils_sort_entries(LDAPUtilsEntry ** entries, int (*compar)(const void *, const void *));

// sorts values
int ldaputils_sort_values(struct berval ** vals);

// frees common config
void ldaputils_unbind(LDAPUtils * lud);

LDAPUTILS_END_C_DECLS
#endif /* end of header */
