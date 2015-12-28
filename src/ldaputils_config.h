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
 *  @file src/ldaputils_config.c  contains shared functions and variables
 */
#ifndef _LDAP_UTILS_SRC_LDAPUTILS_CONFIG_H
#define _LDAP_UTILS_SRC_LDAPUTILS_CONFIG_H 1


///////////////
//           //
//  Headers  //
//           //
///////////////

#include <ldap-utils.h>

///////////////////
//               //
//  Definitions  //
//               //
///////////////////

#define LDAPUTILS_BUFF_LEN                 4096
#define LDAPUTILS_OPT_LEN                  128

#define LDAPUTILS_OPTIONS_COMMON           "9cCd:D:h:H:np:P:uvVw:Wxy:Z"
#define LDAPUTILS_OPTIONS_SEARCH           "b:l:s:S:z:"


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////

/* store common structs */
typedef struct ldaputils_config_struct   lutils_config;
struct ldaputils_config_struct
{
   int            continuous;                  // -c continuous operation mode
   long           debug;                       // -d debug level
   int            dryrun;                      // -n dry run mode
   int            port;                        // -p LDAP server port
   int            referrals;                   // -C chase referrals
   int            scope;                       // -s LDAP search scope
   int            sizelimit;                   // -z size limit
   int            timelimit;                   // -l time limit
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
   const char   * uri;                         // -H LDAP URI
   LDAPURLDesc  * ludp;                        // pointer to LDAP URL
};


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////

// removes newlines and carriage returns
char * ldaputils_chomp PARAMS((char * str));

// parses LDAP command line arguments
int ldaputils_cmdargs PARAMS((lutils_config * cnf, int c, const char * arg));

// frees common config
void ldaputils_config_free PARAMS((lutils_config * cnf));

// initializes the common config
void ldaputils_config_init PARAMS((lutils_config * cnf));

// prints configuration to stdout
void ldaputils_config_print PARAMS((lutils_config * cnf));

// prints string to stdout
const char * ldaputils_config_print_str PARAMS((const char * str));

// getpass() replacement -- SUSV 2 deprecated getpass()
int ldaputils_getpass PARAMS((const char * prompt, char * buff, size_t size));

// retrieves password from file
int ldaputils_passfile PARAMS((const char * file, char * buff, size_t size));

// prints program usage and exits
void ldaputils_usage PARAMS((void));

// displays usage for common options
void ldaputils_usage_common PARAMS((const char * short_options));

// displays search usage for search options
void ldaputils_usage_search PARAMS((const char * short_options));

// displays usage
void ldaputils_version PARAMS((void));

#endif /* end of header file */
