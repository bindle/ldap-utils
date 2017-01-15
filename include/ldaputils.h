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

///////////////
//           //
//  Headers  //
//           //
///////////////

#include <ldaputils_cdefs.h>

#include <inttypes.h>
#include <ldap.h>


///////////////////
//               //
//  Definitions  //
//               //
///////////////////

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

#define LDAPUTILS_OPTIONS_COMMON           "9cd:D:h:H:np:P:uvVw:Wxy:Z"
#define LDAPUTILS_OPTIONS_SEARCH           "b:l:s:S:z:"


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////

typedef struct ldap_utils_entry LDAPUtilsEntry;
struct ldap_utils_entry
{
   char   * dn;
   char   * sortval;
   size_t   count;
   struct ldap_utils_attribute ** attributes;
};


typedef struct ldap_utils_attribute LDAPUtilsAttribute;
struct ldap_utils_attribute
{
   char           * name;
   struct berval ** vals;
};


/* store common structs */
typedef struct ldaputils_config_struct   LDAPUtils;
struct ldaputils_config_struct
{
   LDAP         * ld;                          ///< LDAP descriptor
   char         * prog_name;                   ///< program name
   int            continuous;                  // -c continuous operation mode
   int            dryrun;                      // -n dry run mode
   int            port;                        // -p LDAP server port
   int            scope;                       // -s LDAP search scope
   int            verbose;                     // -v verbose mode
   unsigned       version;                     // -P LDAP protocol version
   char           bindpw[LDAPUTILS_OPT_LEN];   // -W, -w bind password
   char           uribuff[LDAPUTILS_OPT_LEN];
   char        ** attrs;                       //    result attributes
   const char   * basedn;                      // -b base DN
   const char   * binddn;                      // -D bind DN
   const char   * filter;                      //    search filter
   const char   * host;                        // -h LDAP host
   const char   * passfile;	                 // -y password file
   const char   * sortattr;	                 // -S sort by attribute
};


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
LDAPUTILS_BEGIN_C_DECLS

// removes newlines and carriage returns
char * ldaputils_chomp(char * str);

// parses LDAP command line arguments
int ldaputils_cmdargs(LDAPUtils * cnf, int c, const char * arg);

// frees common config
void ldaputils_config_free(LDAPUtils * cnf);

// prints configuration to stdout
void ldaputils_config_print(LDAPUtils * cnf);

// prints string to stdout
const char * ldaputils_config_print_str(const char * str);

// getpass() replacement -- SUSV 2 deprecated getpass()
int ldaputils_getpass(const char * prompt, char * buff, size_t size);

// retrieves password from file
int ldaputils_passfile(LDAPUtils * cnf, const char * file,
   char * buff, size_t size);

// prints program usage and exits
void ldaputils_usage(void);

// displays usage for common options
void ldaputils_usage_common(const char * short_options);

// displays search usage for search options
void ldaputils_usage_search(const char * short_options);

// displays usage
void ldaputils_version(const char * prog_name);

// parses LDAP command line arguments
int ldaputils_common_cmdargs(LDAPUtils * cnf, int c, const char * arg);

// sets LDAP server's bind password
int ldaputils_config_set_bindpw(LDAPUtils * cnf, const char * arg);

// sets LDAP server's host name
int ldaputils_config_set_host(LDAPUtils * cnf, const char * arg);

// sets LDAP TCP port
int ldaputils_config_set_port(LDAPUtils * cnf, const char * arg);

// sets LDAP protocol version
int ldaputils_config_set_version(LDAPUtils * cnf, const char * arg);

// compares two LDAP values for sorting
int ldaputils_cmp_berval(const struct berval ** ptr1, const struct berval ** ptr2);

// compares two LDAP values for sorting
int ldaputils_cmp_entry(const LDAPUtilsEntry ** ptr1, const LDAPUtilsEntry ** ptr2);

// frees list of entries
void ldaputils_free_entries(LDAPUtilsEntry ** entries);

// retrieves LDAP entries from result
LDAPUtilsEntry ** ldaputils_get_entries(LDAPUtils * cnf, LDAP * ld,
   LDAPMessage * res, const char * sortattr);

// retrieves values of an LDAP attribute
char * ldaputils_get_vals(LDAPUtils * cnf, LDAPUtilsEntry * entry,
   const char * attr);

// connects and binds to LDAP server
int ldaputils_initialize(LDAPUtils ** lup, const char * prog_name);

// connects and binds to LDAP server
LDAP * ldaputils_initialize_conn(LDAPUtils * cnf);

// connects and binds to LDAP server
int ldaputils_search(LDAP * ld, LDAPUtils * cnf, LDAPMessage ** resp);

// sorts values
int ldaputils_sort_entries(LDAPUtilsEntry ** entries);

// sorts values
int ldaputils_sort_values(struct berval ** vals);


LDAPUTILS_END_C_DECLS
#endif /* end of header */
