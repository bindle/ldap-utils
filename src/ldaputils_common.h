/*
 *  $Id$
 */
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
/*
 *  src/ldaputils_common.c - contains shared functions and variables
 */
#ifndef _LDAP_UTILS_SRC_LDAPUTILS_COMMON_H
#define _LDAP_UTILS_SRC_LDAPUTILS_COMMON_H 1

//////////////
//          //
//  Macros  //
//          //
//////////////

/*
 * The macro "PARAMS" is taken verbatim from section 7.1 of the
 * Libtool 1.5.14 manual.
 */
/* PARAMS is a macro used to wrap function prototypes, so that
   compilers that don't understand ANSI C prototypes still work,
   and ANSI C compilers can issue warnings about type mismatches. */
#undef PARAMS
#if defined (__STDC__) || defined (_AIX) \
        || (defined (__mips) && defined (_SYSTYPE_SVR4)) \
        || defined(WIN32) || defined (__cplusplus)
# define PARAMS(protos) protos
#else
# define PARAMS(protos) ()
#endif


///////////////
//           //
//  Headers  //
//           //
///////////////

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef WIN32
#include <windows.h>
#endif

#include <inttypes.h>
#include <sys/types.h>


///////////////////
//               //
//  i18l Support //
//               //
///////////////////

#ifdef HAVE_GETTEXT
#   include <gettext.h> 
#   define _(String) gettext (String) 
#   define gettext_noop(String) String 
#   define N_(String) gettext_noop (String) 
#else
#   define _(String) (String) 
#   define N_(String) String 
#   define textdomain(Domain) 
#   define bindtextdomain(Package, Directory) 
#endif


///////////////////
//               //
//  Definitions  //
//               //
///////////////////

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

#define MY_BUFF_LEN                 4096
#define MY_OPT_LEN                  128

#define MY_COMMON_OPTIONS           "cCD:h:H:p:P:uv:Vw:Wxy:Z"

#define MY_COMMON_OPT_VERBOSE        0x0001
#define MY_COMMON_OPT_QUITE          0x0002
#define MY_COMMON_OPT_CONTINUOUS     0x0004
#define MY_COMMON_OPT_REFERRALS      0x0008
#define MY_COMMON_OPT_PASSWDPROMPT   0x0010
#define MY_COMMON_OPT_SIMPLEAUTH	    0x0020
#define MY_COMMON_OPT_TLS            0x0040
#define MY_COMMON_OPT_REQUIRETLS     0x0080
#define MY_COMMON_OPT_DEBUG          0x0100

#define MY_DEFAULT_URI               "ldap://localhost/"
#define MY_DEFAULT_HOST              "localhost"
#define MY_DEFAULT_PORT              389


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////

/* store common structs */
typedef struct ldaputils_common_config_struct LdapUtilsConfig;
struct ldaputils_common_config_struct
{
   int           continuous;           // -c continuous operation mode
   int           debug;                // -d debug level
   int           port;                 // -p LDAP server port
   int           scope;                // -s LDAP search scope
   int           referrals;            // -C chase referrals
   int           sizelimit;            // -z size limit
   int           timelimit;            // -l time limit
   unsigned      noinit;               // used to ignore config files
   unsigned      common_opts;          // -u, -c, -C, -W, -x, -Z, -ZZ, -L, -LL, -LLL, -x
   unsigned      version;              // -P LDAP protocol version
   char          bindpw[MY_OPT_LEN];   // -W, -w bind password
   const char  * basedn;               // -b
   const char  * binddn;               // -D bind DN
   const char  * host;                 // -h LDAP host
   const char  * passfile;             // -y read password from file
   const char  * sortattr;	            // -S sort by attribute
   LDAPURLDesc * ludp;                 // pointer to LDAP URL
};


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////

/* removes newlines and carriage returns */
char * chomp PARAMS((char * str));

/* parses LDAP command line arguments */
int ldaputils_common_cmdargs PARAMS((LdapUtilsConfig * cnf, int c, const char * arg));

/* parses LDAP config file */
//int ldaputils_common_config PARAMS((LdapUtilsConfig * cnf));

/* frees common config */
void ldaputils_common_config_free PARAMS((LdapUtilsConfig * cnf));

/* generates file name from format string */
//int ldaputils_common_config_name PARAMS((MyCommonConfig * cnf, char * str,
//	unsigned str_len, const char * fmt));

/* parses LDAP config file */
//int ldaputils_common_config_parse PARAMS((MyCommonConfig * cnf, const char * name));

/* parses LDAP config file */
//int ldaputils_common_config_setopt PARAMS((MyCommonConfig * cnf, const char * opt,
//        const char * arg));

/* sets search scope */
int ldaputils_common_config_set_scope PARAMS((LdapUtilsConfig * cnf, const char * arg));

/* processes environment variables */
//int ldaputils_common_environment PARAMS((MyCommonConfig * cnf));

/* getpass() replacement -- SUSV 2 deprecated getpass() */
int ldaputils_common_getpass PARAMS((const char * prompt, char * buff, ssize_t len));

// displays common usage
void ldaputils_common_usage PARAMS((void));

// displays usage
void ldaputils_common_version PARAMS((void));

// displays search usage
void ldaputils_search_usage PARAMS((void));

// prints program usage and exits
void ldaputils_usage PARAMS((void));


#endif /* end of header file */
