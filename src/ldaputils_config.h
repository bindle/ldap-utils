/*
 *  LDAP Utilities
 *  Copyright (c) 2008 David M. Syzdek <david@syzdek.net>.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
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
typedef struct ldaputils_config_struct   LdapUtilsConfig;
typedef struct ldaputils_config_struct * LdapUtilsConfigRef;
struct ldaputils_config_struct
{
   int            continuous;                  // -c continuous operation mode
   int            debug;                       // -d debug level
   int            dryrun;                      // -n dry run mode
   int            port;                        // -p LDAP server port
   int            referrals;                   // -C chase referrals
   int            scope;                       // -s LDAP search scope
   int            sizelimit;                   // -z size limit
   int            timelimit;                   // -l time limit
   int            verbose;                     // -v verbose mode
   unsigned       version;                     // -P LDAP protocol version
   char           bindpw[LDAPUTILS_OPT_LEN];   // -W, -w bind password
   char           uri[LDAPUTILS_OPT_LEN];      // -H LDAP URI
   char        ** attrs;                       //    result attributes
   const char   * basedn;                      // -b base DN
   const char   * binddn;                      // -D bind DN
   const char   * filter;                      //    search filter
   const char   * host;                        // -h LDAP host
   const char   * passfile;	                 // -y password file
   const char   * sortattr;	                 // -S sort by attribute
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
int ldaputils_cmdargs PARAMS((LdapUtilsConfig * cnf, int c, const char * arg));

// frees common config
void ldaputils_config_free PARAMS((LdapUtilsConfig * cnf));

// initializes the common config
void ldaputils_config_init PARAMS((LdapUtilsConfig * cnf));

// getpass() replacement -- SUSV 2 deprecated getpass()
int ldaputils_getpass PARAMS((const char * prompt, char * buff, size_t len));

// retrieves password from file
int ldaputils_passfile PARAMS((const char * file, char * buff, ssize_t len));

// prints program usage and exits
void ldaputils_usage PARAMS((void));

// displays usage for common options
void ldaputils_usage_common PARAMS((void));

// displays search usage for search options
void ldaputils_usage_search PARAMS((void));

// displays usage
void ldaputils_version PARAMS((void));

#endif /* end of header file */
