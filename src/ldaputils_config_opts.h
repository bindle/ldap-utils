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
 *  @file src/ldaputils_config_opts.c contains shared functions and variables
 */
#ifndef _LDAP_UTILS_SRC_LDAPUTILS_CONFIG_OPTS_H
#define _LDAP_UTILS_SRC_LDAPUTILS_CONFIG_OPTS_H 1


///////////////
//           //
//  Headers  //
//           //
///////////////

#include "ldaputils_config.h"


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////

// parses LDAP command line arguments
int ldaputils_common_cmdargs PARAMS((LdapUtilsConfig * cnf, int c, const char * arg));

// sets LDAP server's base DN
int ldaputils_config_set_basedn PARAMS((LdapUtilsConfig * cnf, const char * arg));

// sets LDAP server's bind DN
int ldaputils_config_set_binddn PARAMS((LdapUtilsConfig * cnf, const char * arg));

// sets LDAP server's bind password
int ldaputils_config_set_bindpw PARAMS((LdapUtilsConfig * cnf, const char * arg));

// reads LDAP server's bind password from file
int ldaputils_config_set_bindpw_file PARAMS((LdapUtilsConfig * cnf, const char * arg));

// sets LDAP server's bind password
int ldaputils_config_set_bindpw_prompt PARAMS((LdapUtilsConfig * cnf));

// toggles continuous mode
int ldaputils_config_set_continuous PARAMS((LdapUtilsConfig * cnf));

// sets LDAP debug level
int ldaputils_config_set_debug PARAMS((LdapUtilsConfig * cnf, const char * arg));

// toggles dry run
int ldaputils_config_set_dryrun PARAMS((LdapUtilsConfig * cnf));

// sets LDAP server's host name
int ldaputils_config_set_host PARAMS((LdapUtilsConfig * cnf, const char * arg));

// sets LDAP TCP port
int ldaputils_config_set_port PARAMS((LdapUtilsConfig * cnf, const char * arg));

// toggles following referrals
int ldaputils_config_set_referrals PARAMS((LdapUtilsConfig * cnf));

// sets LDAP search scope
int ldaputils_config_set_scope PARAMS((LdapUtilsConfig * cnf, const char * arg));

// sets LDAP size limit
int ldaputils_config_set_sizelimit PARAMS((LdapUtilsConfig * cnf, const char * arg));

// sets sort attribute
int ldaputils_config_set_sortattr PARAMS((LdapUtilsConfig * cnf, const char * arg));

// sets LDAP time limit
int ldaputils_config_set_timelimit PARAMS((LdapUtilsConfig * cnf, const char * arg));

// sets LDAP server's URI
int ldaputils_config_set_uri PARAMS((LdapUtilsConfig * cnf, const char * arg));

// toggles verbose mode
int ldaputils_config_set_verbose PARAMS((LdapUtilsConfig * cnf));

// sets LDAP protocol version
int ldaputils_config_set_version PARAMS((LdapUtilsConfig * cnf, const char * arg));


#endif /* end of header file */
