/*
 *  LDAP Utilities
 *  Copyright (c) 2008 David M. Syzdek <ldap-utils-project@syzdek.net>.
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
 *  @file src/ldaputils_common.c contains shared functions and variables
 */
#ifndef _LDAP_UTILS_SRC_LDAPUTILS_COMMON_H
#define _LDAP_UTILS_SRC_LDAPUTILS_COMMON_H 1


///////////////
//           //
//  Headers  //
//           //
///////////////

#include <ldap-utils.h>
#include <sys/types.h>


///////////////////
//               //
//  Definitions  //
//               //
///////////////////


#define LDAPUTILS_BUFF_LEN                 4096
#define LDAPUTILS_OPT_LEN                  128

#define LDAPUTILS_COMMON_OPTIONS           "cCD:h:H:p:P:uv:Vw:Wxy:Z"

#define LDAPUTILS_COMMON_OPT_VERBOSE        0x0001
#define LDAPUTILS_COMMON_OPT_QUITE          0x0002
#define LDAPUTILS_COMMON_OPT_CONTINUOUS     0x0004
#define LDAPUTILS_COMMON_OPT_REFERRALS      0x0008
#define LDAPUTILS_COMMON_OPT_PASSWDPROMPT   0x0010
#define LDAPUTILS_COMMON_OPT_SIMPLEAUTH	  0x0020
#define LDAPUTILS_COMMON_OPT_TLS            0x0040
#define LDAPUTILS_COMMON_OPT_REQUIRETLS     0x0080
#define LDAPUTILS_COMMON_OPT_DEBUG          0x0100

#define LDAPUTILS_DEFAULT_URI               "ldap://localhost/"
#define LDAPUTILS_DEFAULT_HOST              "localhost"
#define LDAPUTILS_DEFAULT_PORT              389


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////

/* store common structs */
typedef struct ldaputils_common_config_struct   LdapUtilsConfig;
typedef struct ldaputils_common_config_struct * LdapUtilsConfigRef;
struct ldaputils_common_config_struct
{
   int           continuous;                  // -c continuous operation mode
   int           debug;                       // -d debug level
   int           port;                        // -p LDAP server port
   int           referrals;                   // -C chase referrals
   int           sizelimit;                   // -z size limit
   int           timelimit;                   // -l time limit
   int           verbose;                     // -v verbose mode
   unsigned      common_opts;                 // -u, -c, -C, -W, -x, -Z, -ZZ, -L, -LL, -LLL, -x
   unsigned      version;                     // -P LDAP protocol version
   char          bindpw[LDAPUTILS_OPT_LEN];   // -W, -w bind password
   const char  * binddn;                      // -D bind DN
   const char  * host;                        // -h LDAP host
   const char  * passfile;                    // -y read password from file
   const char  * sortattr;	                   // -S sort by attribute
   LDAPURLDesc * ludp;                        // pointer to LDAP URL
};


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////

// parses LDAP command line arguments
int ldaputils_common_cmdargs PARAMS((LdapUtilsConfig * cnf, int c, const char * arg));

// frees common config
void ldaputils_common_config_free PARAMS((LdapUtilsConfig * cnf));

// initializes the common config
void ldaputils_common_config_init PARAMS((LdapUtilsConfig * cnf));

// sets LDAP server's bind DN
int ldaputils_common_config_set_binddn PARAMS((LdapUtilsConfig * cnf, const char * arg));

// sets LDAP server's bind password
int ldaputils_common_config_set_bindpw PARAMS((LdapUtilsConfig * cnf, const char * arg));

// sets LDAP server's bind password
int ldaputils_common_config_set_bindpw_prompt PARAMS((LdapUtilsConfig * cnf));

// toggles continuous mode
int ldaputils_common_config_set_continuous PARAMS((LdapUtilsConfig * cnf));

// sets LDAP debug level
int ldaputils_common_config_set_debug PARAMS((LdapUtilsConfig * cnf, const char * arg));

// sets LDAP server's host name
int ldaputils_common_config_set_host PARAMS((LdapUtilsConfig * cnf, const char * arg));

// sets LDAP TCP port
int ldaputils_common_config_set_port PARAMS((LdapUtilsConfig * cnf, const char * arg));

// toggles following referrals
int ldaputils_common_config_set_referrals PARAMS((LdapUtilsConfig * cnf));

// sets LDAP server's URI
int ldaputils_common_config_set_uri PARAMS((LdapUtilsConfig * cnf, const char * arg));

// toggles verbose mode
int ldaputils_common_config_set_verbose PARAMS((LdapUtilsConfig * cnf));

// sets LDAP protocol version
int ldaputils_common_config_set_version PARAMS((LdapUtilsConfig * cnf, const char * arg));

// displays common usage
void ldaputils_common_usage PARAMS((void));

// displays search usage
void ldaputils_search_usage PARAMS((void));

// prints program usage and exits
void ldaputils_usage PARAMS((void));

// displays usage
void ldaputils_version PARAMS((void));


#endif /* end of header file */
