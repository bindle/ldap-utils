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
 *  @file src/ldaputils_common.c  contains shared functions and variables
 */
#define _LDAP_UTILS_SRC_LDAPUTILS_COMMON_C 1
#include "ldaputils_common.h"

///////////////
//           //
//  Headers  //
//           //
///////////////

#include <inttypes.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "ldaputils_misc.h"


/////////////////
//             //
//  Functions  //
//             //
/////////////////

/// parses LDAP command line arguments
/// @param[in] cnf
/// @param[in] c
/// @param[in] arg
int ldaputils_common_cmdargs(LdapUtilsConfig * cnf, int c, const char * arg)
{
   /* checks argument */
   switch(c)
   {
      case -1:       /* no more arguments */
      case 0:        /* long options toggles */
         return(c);
      case '9':
         ldaputils_usage();
         return(-2);
      case 'c':
         return(ldaputils_common_config_set_continuous(cnf));
      case 'C':
         return(ldaputils_common_config_set_referrals(cnf));
      case 'd':
         return(ldaputils_common_config_set_debug(cnf, arg));
      case 'D':
         return(ldaputils_common_config_set_bindpw(cnf, arg));
      case 'h':
         return(ldaputils_common_config_set_host(cnf, arg));
      case 'H':
         return(ldaputils_common_config_set_uri(cnf, arg));
      case 'p':
         return(ldaputils_common_config_set_port(cnf, arg));
      case 'P':
         return(ldaputils_common_config_set_version(cnf, arg));
      case 'v':
         return(ldaputils_common_config_set_verbose(cnf));
      case 'V':
         ldaputils_version();
         return(-2);
      case 'w':
         return(ldaputils_common_config_set_bindpw(cnf, arg));
      case 'W':
         return(ldaputils_common_config_set_bindpw_prompt(cnf));
      default:
         return(c);
   };

   /* ends function */
   return(c);
}


/// frees common config
/// @param[in] cnf
void ldaputils_common_config_free(LdapUtilsConfig * cnf)
{
   if (!(cnf))
      return;

   if (cnf->ludp)
      ldap_free_urldesc(cnf->ludp);
   cnf->ludp = NULL;

   return;
}


/// initializes the common config
/// @param[in] cnf  reference to common configuration struct
void ldaputils_common_config_init(LdapUtilsConfig * cnf)
{
   memset(cnf, 0, sizeof(LdapUtilsConfig));
   cnf->referrals  = 0;
   return;
}


/// sets LDAP server's bind DN
/// @param[in] cnf   reference to common configuration struct
/// @param[in] arg   value of the command line argument
int ldaputils_common_config_set_binddn(LdapUtilsConfig * cnf, const char * arg)
{
   cnf->binddn = arg;
   return(0);
}


/// sets LDAP server's bind password
/// @param[in] cnf   reference to common configuration struct
/// @param[in] arg   value of the command line argument
int ldaputils_common_config_set_bindpw(LdapUtilsConfig * cnf, const char * arg)
{
   strncpy(cnf->bindpw, arg, LDAPUTILS_OPT_LEN);
   return(0);
}


/// sets LDAP server's bind password
/// @param[in] cnf   reference to common configuration struct
/// @param[in] arg   value of the command line argument
int ldaputils_common_config_set_bindpw_prompt(LdapUtilsConfig * cnf)
{
   // TRANSLATORS: The following string is used as a prompt when the program
   // requests the user's LDAP bind password.
   ldaputils_getpass(_("Enter LDAP Password: "), cnf->bindpw, LDAPUTILS_OPT_LEN);
   return(0);
}


/// toggles continuous mode
/// @param[in] cnf   reference to common configuration struct
int ldaputils_common_config_set_continuous(LdapUtilsConfig * cnf)
{
   cnf->continuous++;
   return(0);
}


/// sets LDAP debug level
/// @param[in] cnf   reference to common configuration struct
/// @param[in] arg   value of the command line argument
int ldaputils_common_config_set_debug(LdapUtilsConfig * cnf, const char * arg)
{
   cnf->debug = atol(arg);
   return(0);
}


/// sets LDAP server's host name
/// @param[in] cnf   reference to common configuration struct
/// @param[in] arg   value of the command line argument
int ldaputils_common_config_set_host(LdapUtilsConfig * cnf, const char * arg)
{
   cnf->host = arg;
   return(0);
}


/// sets LDAP TCP port
/// @param[in] cnf   reference to common configuration struct
/// @param[in] arg   value of the command line argument
int ldaputils_common_config_set_port(LdapUtilsConfig * cnf, const char * arg)
{
   int i;
   i = atol(arg);
   if ( (i < 1) || (i > 0xffff) )
   {
      fprintf(stderr, _("%s: invalid TCP port\n"), PROGRAM_NAME);
      fprintf(stderr, _("Try `%s --help' for more information.\n"), PROGRAM_NAME);
      return(1);
   };
   cnf->port = i;
   return(0);
}


/// toggles following referrals
/// @param[in] cnf   reference to common configuration struct
int ldaputils_common_config_set_referrals(LdapUtilsConfig * cnf)
{
   if (cnf->referrals < 0)
      cnf->referrals = 0;
   cnf->referrals++;
   return(0);
}


/// sets LDAP server's URI
/// @param[in] cnf   reference to common configuration struct
/// @param[in] arg   value of the command line argument
int ldaputils_common_config_set_uri(LdapUtilsConfig * cnf, const char * arg)
{
   if ((cnf->ludp))
      ldap_free_urldesc(cnf->ludp);
   cnf->ludp = NULL;
   
   if ((ldap_url_parse(arg, &cnf->ludp)))
   {
      // TRANSLATORS: The following strings provide an error message if the
      // URI provided on the command line is an invalid LDAP URI.
      fprintf(stderr, _("%s: invalid LDAP URI\n"), PROGRAM_NAME);
      fprintf(stderr, _("Try `%s --help' for more information.\n"), PROGRAM_NAME);
      return(1);
   };
   
   cnf->host  = cnf->ludp->lud_host;
   cnf->port  = cnf->ludp->lud_port;
   
   return(0);
}


/// toggles verbose mode
/// @param[in] cnf   reference to common configuration struct
int ldaputils_common_config_set_verbose(LdapUtilsConfig * cnf)
{
   cnf->verbose = 1;
   return(0);
}


/// sets LDAP protocol version
/// @param[in] cnf   reference to common configuration struct
/// @param[in] arg   value of the command line argument
int ldaputils_common_config_set_version(LdapUtilsConfig * cnf, const char * arg)
{
   int i;
   i = atol(arg);
   switch(i)
   {
      case 2:
      case 3:
         cnf->version = i;
      default:
         // TRANSLATORS: The following strings provide an error message if the
         // LDAP protocol version specified on the command line is an invalid
         // protocol version or unsupported protocol version.
         fprintf(stderr, _("%s: protocol version should be 2 or 3\n"), PROGRAM_NAME);
         fprintf(stderr, _("Try `%s --help' for more information.\n"), PROGRAM_NAME);
         return(1);
   };
   return(0);
}


/// displays usage
void ldaputils_common_usage(void)
{
   // TRANSLATORS: The following strings provide usage for common command
   // line arguments. Usage for program specific arguments is provided in
   // anothoer section. These strings are displayed if the program is
   // passed `--help' on the command line.
   fprintf(stderr, _("Common options:\n"
         "  -c                continuous operation mode (do not stop on errors)\n"
         "  -C                chase referrals (anonymously)\n"
         "  -d level          set LDAP debug level to `level'\n"
         "  -D binddn         bind DN\n"
         "  -h host           LDAP server\n"
         "  -H URI            LDAP Uniform Resource Identifier(s)\n"
         "  -p port           port on LDAP server\n"
         "  -P version        protocol version (default: 3)\n"
         "  -v, --verbose     run in verbose mode\n"
         "  -V, --version     print version number and exit\n"
         "  -w, passwd        bind password (for simple authentication)\n"
         "  -W                prompt for bind password\n"
         "  -y file           read password from file\n"
         "  --help            print this help and exit\n"
         "\n"
      )
   );
   return;
}


/// displays search usage
void ldaputils_search_usage(void)
{
   // TRANSLATORS: The following strings provide usage for search command
   // line arguments. Usage for program specific arguments is provided in
   // anothoer section. These strings are displayed if the program is
   // passed `--help' on the command line.
   printf(_("Search options:\n"
         "  -b basedn         base dn for search\n"
         "  -l limit          time limit (in seconds) for search\n"
         "  -s scope          one of base, one, or sub (search scope)\n"
         "  -S attr           sort results by attribute `attr'\n"
         "  -u                include User Friendly entry names in output\n"
         "  -z limit          size limit for search\n"
      )
   );
   return;
}


/// displays usage
void ldaputils_version(void)
{
   // TRANSLATORS: The following strings provide version and copyright
   // information if the program is passed --version on the command line.
   // The three strings referenced are: PROGRAM_NAME, PACKAGE_NAME,
   // PACKAGE_VERSION.
   printf(_( "%s (%s) %s\n"
         "Written by David M. Syzdek.\n"
         "\n"
         "Copyright (C) 2008 David M. Syzdek.\n"
         "This is free software; see the source for copying conditions.  There is NO\n"
         "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n"
      ), PROGRAM_NAME, PACKAGE_NAME, PACKAGE_VERSION
   );
   return;
}

/* end of source file */
