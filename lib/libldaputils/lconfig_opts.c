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
 *  @file src/ldaputils_config_opts.c  contains shared functions and variables
 */
#define _LIB_LIBLDAPUTILS_LCONFIG_OPTS_C 1
#include "lconfig_opts.h"

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
#include <assert.h>


/////////////////
//             //
//  Functions  //
//             //
/////////////////


/// sets LDAP server's bind password
/// @param[in] cnf   reference to common configuration struct
/// @param[in] arg   value of the command line argument
int ldaputils_config_set_bindpw(LDAPUtils * cnf, const char * arg)
{
   strncpy(cnf->bindpw, arg, LDAPUTILS_OPT_LEN);
   return(0);
}


/// reads LDAP server's bind password from file
/// @param[in] cnf   reference to common configuration struct
/// @param[in] arg   value of the command line argument
int ldaputils_config_set_bindpw_file(LDAPUtils * cnf, const char * arg)
{
   return(ldaputils_passfile(cnf, arg, cnf->bindpw, LDAPUTILS_OPT_LEN));
}


/// prompts for LDAP server's bind password
/// @param[in] cnf   reference to common configuration struct
/// @param[in] arg   value of the command line argument
int ldaputils_config_set_bindpw_prompt(LDAPUtils * cnf)
{
   // TRANSLATORS: The following string is used as a prompt when the program
   // requests the user's LDAP bind password.
   ldaputils_getpass("Enter LDAP Password: ", cnf->bindpw, LDAPUTILS_OPT_LEN);
   return(0);
}


/// sets LDAP server's host name
/// @param[in] cnf   reference to common configuration struct
/// @param[in] arg   value of the command line argument
int ldaputils_config_set_host(LDAPUtils * cnf, const char * arg)
{
   int rc;
   snprintf(cnf->uribuff, LDAPUTILS_OPT_LEN, "ldap://%s:%i/", arg, cnf->port);
   if ((rc = ldap_set_option(cnf->ld, LDAP_OPT_URI, cnf->uribuff)) != LDAP_SUCCESS)
   {
      fprintf(stderr, "%s: ldap_set_option(LDAP_OPT_URI): %s\n", cnf->prog_name, ldap_err2string(rc));
      return(1);
   };
   return(0);
}


/// sets LDAP TCP port
/// @param[in] cnf   reference to common configuration struct
/// @param[in] arg   value of the command line argument
int ldaputils_config_set_port(LDAPUtils * cnf, const char * arg)
{
   int          port;
   int          rc;
   const char * host;
   port = (int)atol(arg);
   if ( (port < 1) || (port > 0xffff) )
   {
      fprintf(stderr, "%s: invalid TCP port\n", cnf->prog_name);
      fprintf(stderr, "Try `%s --help' for more information.\n", cnf->prog_name);
      return(1);
   };
   if ((cnf->host))
      host = cnf->host;
   else
      host = "";
   snprintf(cnf->uribuff, LDAPUTILS_OPT_LEN, "ldap://%s:%i/", host, port);
   if ((rc = ldap_set_option(cnf->ld, LDAP_OPT_URI, cnf->uribuff)) != LDAP_SUCCESS)
   {
      fprintf(stderr, "%s: ldap_set_option(LDAP_OPT_URI): %s\n", cnf->prog_name, ldap_err2string(rc));
      return(1);
   };
   return(0);
}


/// sets sort attribute
/// @param[in] cnf   reference to common configuration struct
/// @param[in] arg   value of the command line argument
int ldaputils_config_set_sortattr(LDAPUtils * cnf, const char * arg)
{
   cnf->sortattr = arg;
   return(0);
}


/// sets LDAP time limit
/// @param[in] cnf   reference to common configuration struct
/// @param[in] arg   value of the command line argument
int ldaputils_config_set_timelimit(LDAPUtils * cnf, const char * arg)
{
   cnf->timelimit = (int)atol(arg);
   return(0);
}


/// sets LDAP protocol version
/// @param[in] cnf   reference to common configuration struct
/// @param[in] arg   value of the command line argument
int ldaputils_config_set_version(LDAPUtils * cnf, const char * arg)
{
   int i;
   i = (int)atol(arg);
   switch(i)
   {
      case 2:
      case 3:
         cnf->version = (unsigned)i;
         return(0);
      default:
         // TRANSLATORS: The following strings provide an error message if the
         // LDAP protocol version specified on the command line is an invalid
         // protocol version or unsupported protocol version.
         fprintf(stderr, "%s: protocol version should be 2 or 3\n", cnf->prog_name);
         fprintf(stderr, "Try `%s --help' for more information.\n", cnf->prog_name);
         return(1);
   };
   return(0);
}


/* end of source file */
