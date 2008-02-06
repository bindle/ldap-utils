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

///////////////
//           //
//  Headers  //
//           //
///////////////
#ifdef _LDAP_UTILS_SRC_LDAPUTILS_COMMON_C

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef WIN32
#include <windows.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
//#include <sys/uio.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <ldap-utils.h>

#endif

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

#define MY_BUFF_LEN             4096
#define MY_OPT_LEN              1024

#define MY_COMMON_OPTIONS		"cCD:h:H:p:P:uv:Vw:Wxy:Z"

#define MY_COMMON_OPT_VERBOSE		0x0001
#define MY_COMMON_OPT_QUITE		0x0002
#define MY_COMMON_OPT_CONTINUOUS	0x0004
#define MY_COMMON_OPT_REFERRALS		0x0008
#define MY_COMMON_OPT_PASSWDPROMPT	0x0010
#define MY_COMMON_OPT_SIMPLEAUTH	0x0020
#define MY_COMMON_OPT_TLS		0x0040
#define MY_COMMON_OPT_REQUIRETLS	0x0080
#define MY_COMMON_OPT_DEBUG		0x0100

#define MY_DEFAULT_HOST			"localhost"
#define MY_DEFAULT_PORT			389


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////

/* store common structs */
typedef struct my_common_config_struct MyCommonConfig;
struct my_common_config_struct
{
   unsigned      noinit;	// used to ignore config files
   unsigned      common_opts;
   unsigned      version;
   int      port;
   int      sizelimit;
   int      timelimit;
   char        * basedn;
   char        * binddn;
   char        * bindpw;
   char        * host;
   char        * uri;
   const char  * ldapconf;
   const char  * ldaprc;
   const char  * home;
   const char  * homepath;
   const char  * passfile;
};


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////

/* parses LDAP command line arguments */
int my_common_cmdargs PARAMS((MyCommonConfig * cnf, int c, char * arg));

/* parses LDAP config file */
int my_common_config PARAMS((MyCommonConfig * cnf));

/* frees common config */
void my_common_config_free PARAMS((MyCommonConfig * cnf));

/* generates file name from format string */
int my_common_config_name PARAMS((MyCommonConfig * cnf, char * str,
	unsigned str_len, const char * fmt));

/* parses LDAP config file */
int my_common_config_parse PARAMS((MyCommonConfig * cnf, const char * name));

/* parses LDAP config file */
int my_common_config_setopt PARAMS((MyCommonConfig * cnf, const char * opt,
        const char * arg));

/* processes environment variables */
int my_common_environment PARAMS((MyCommonConfig * cnf));

/* displays common usage */
void my_common_usage PARAMS((void));

/* displays usage */
void my_common_version PARAMS((void));

#endif /* end of header file */
