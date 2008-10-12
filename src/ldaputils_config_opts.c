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
 *  @file src/ldaputils_config_opts.c  contains shared functions and variables
 */
#define _LDAP_UTILS_SRC_LDAPUTILS_CONFIG_OPTS_C 1
#include "ldaputils_config_opts.h"

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
#include <unistd.h>
#include <string.h>


/////////////////
//             //
//  Functions  //
//             //
/////////////////

/// sets LDAP server's base DN
/// @param[in] cnf   reference to common configuration struct
/// @param[in] arg   value of the command line argument
int ldaputils_config_set_basedn(LdapUtilsConfig * cnf, const char * arg)
{
   cnf->basedn = arg;
   return(0);
}


/// sets LDAP server's bind DN
/// @param[in] cnf   reference to common configuration struct
/// @param[in] arg   value of the command line argument
int ldaputils_config_set_binddn(LdapUtilsConfig * cnf, const char * arg)
{
   cnf->binddn = arg;
   return(0);
}


/// sets LDAP server's bind password
/// @param[in] cnf   reference to common configuration struct
/// @param[in] arg   value of the command line argument
int ldaputils_config_set_bindpw(LdapUtilsConfig * cnf, const char * arg)
{
   strncpy(cnf->bindpw, arg, LDAPUTILS_OPT_LEN);
   return(0);
}


/// reads LDAP server's bind password from file
/// @param[in] cnf   reference to common configuration struct
/// @param[in] arg   value of the command line argument
int ldaputils_config_set_bindpw_file(LdapUtilsConfig * cnf, const char * arg)
{
   return(ldaputils_passfile(arg, cnf->bindpw, LDAPUTILS_OPT_LEN));
}


/// prompts for LDAP server's bind password
/// @param[in] cnf   reference to common configuration struct
/// @param[in] arg   value of the command line argument
int ldaputils_config_set_bindpw_prompt(LdapUtilsConfig * cnf)
{
   // TRANSLATORS: The following string is used as a prompt when the program
   // requests the user's LDAP bind password.
   ldaputils_getpass(_("Enter LDAP Password: "), cnf->bindpw, LDAPUTILS_OPT_LEN);
   return(0);
}


/// toggles continuous mode
/// @param[in] cnf   reference to common configuration struct
int ldaputils_config_set_continuous(LdapUtilsConfig * cnf)
{
   cnf->continuous++;
   return(0);
}


/// sets LDAP debug level
/// @param[in] cnf   reference to common configuration struct
/// @param[in] arg   value of the command line argument
int ldaputils_config_set_debug(LdapUtilsConfig * cnf, const char * arg)
{
   cnf->debug = atol(arg);
   return(0);
}


/// toggles dry run
/// @param[in] cnf   reference to common configuration struct
int ldaputils_config_set_dryrun(LdapUtilsConfig * cnf)
{
   cnf->dryrun++;
   return(0);
}


/// sets LDAP server's host name
/// @param[in] cnf   reference to common configuration struct
/// @param[in] arg   value of the command line argument
int ldaputils_config_set_host(LdapUtilsConfig * cnf, const char * arg)
{
   char uri[LDAPUTILS_OPT_LEN];
   snprintf(uri, LDAPUTILS_OPT_LEN, "ldap://%s:%i/", arg, cnf->port);
   ldaputils_config_set_uri(cnf, uri);
   return(0);
}


/// sets LDAP TCP port
/// @param[in] cnf   reference to common configuration struct
/// @param[in] arg   value of the command line argument
int ldaputils_config_set_port(LdapUtilsConfig * cnf, const char * arg)
{
   int          port;
   char         uri[LDAPUTILS_OPT_LEN];
   const char * host;
   port = atol(arg);
   if ( (port < 1) || (port > 0xffff) )
   {
      fprintf(stderr, _("%s: invalid TCP port\n"), PROGRAM_NAME);
      fprintf(stderr, _("Try `%s --help' for more information.\n"), PROGRAM_NAME);
      return(1);
   };
   if ((cnf->host))
      host = cnf->host;
   else
      host = "";
   snprintf(uri, LDAPUTILS_OPT_LEN, "ldap://%s:%i/", host, port);
   ldaputils_config_set_uri(cnf, uri);
   return(0);
}


/// toggles following referrals
/// @param[in] cnf   reference to common configuration struct
int ldaputils_config_set_referrals(LdapUtilsConfig * cnf)
{
   if (cnf->referrals < 0)
      cnf->referrals = 0;
   cnf->referrals++;
   return(0);
}


// sets LDAP search scope
int ldaputils_config_set_scope(LdapUtilsConfig * cnf, const char * arg)
{
   if (!(strcasecmp(arg, "sub")))
      cnf->scope = LDAP_SCOPE_SUBTREE;
   else if (!(strcasecmp(arg, "one")))
      cnf->scope = LDAP_SCOPE_SUBTREE;
   else if (!(strcasecmp(arg, "base")))
      cnf->scope = LDAP_SCOPE_BASE;
   else
   {
      fprintf(stderr, _("%s: scope should be base, one, or sub\n"), PROGRAM_NAME);
      return(1);
   };
   return(0);
}


/// sets LDAP size limit
/// @param[in] cnf   reference to common configuration struct
/// @param[in] arg   value of the command line argument
int ldaputils_config_set_sizelimit(LdapUtilsConfig * cnf, const char * arg)
{
   cnf->sizelimit = atol(arg);
   return(0);
}


/// sets sort attribute
/// @param[in] cnf   reference to common configuration struct
/// @param[in] arg   value of the command line argument
int ldaputils_config_set_sortattr(LdapUtilsConfig * cnf, const char * arg)
{
   cnf->sortattr = arg;
   return(0);
}


/// sets LDAP time limit
/// @param[in] cnf   reference to common configuration struct
/// @param[in] arg   value of the command line argument
int ldaputils_config_set_timelimit(LdapUtilsConfig * cnf, const char * arg)
{
   cnf->timelimit = atol(arg);
   return(0);
}


/// sets LDAP server's URI
/// @param[in] cnf   reference to common configuration struct
/// @param[in] arg   value of the command line argument
int ldaputils_config_set_uri(LdapUtilsConfig * cnf, const char * arg)
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
   strncpy(cnf->uri, arg, LDAPUTILS_OPT_LEN);
   
   return(0);
}


/// toggles verbose mode
/// @param[in] cnf   reference to common configuration struct
int ldaputils_config_set_verbose(LdapUtilsConfig * cnf)
{
   cnf->verbose = 1;
   return(0);
}


/// sets LDAP protocol version
/// @param[in] cnf   reference to common configuration struct
/// @param[in] arg   value of the command line argument
int ldaputils_config_set_version(LdapUtilsConfig * cnf, const char * arg)
{
   int i;
   i = atol(arg);
   switch(i)
   {
      case 2:
      case 3:
         cnf->version = i;
         return(0);
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


/* end of source file */
