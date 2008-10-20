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
 *  @file src/ldaputils_ldap.c  contains shared functions and variables
 */
#ifndef _LDAP_UTILS_SRC_LDAPUTILS_LDAP_H
#define _LDAP_UTILS_SRC_LDAPUTILS_LDAP_H 1


///////////////
//           //
//  Headers  //
//           //
///////////////

#include <ldap-utils.h>
#include "ldaputils_config.h"


///////////////////
//               //
//  Definitions  //
//               //
///////////////////


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////

// compares two LDAP values for sorting
int ldaputils_cmp_berval PARAMS((const struct berval ** ptr1, const struct berval ** ptr2));

// compares two LDAP values for sorting
int ldaputils_cmp_entry PARAMS((const LDAPUtilsEntry ** ptr1, const LDAPUtilsEntry ** ptr2));

// frees list of entries
void ldaputils_free_entries PARAMS((LDAPUtilsEntry ** entries));

// retrieves LDAP entries from result
LDAPUtilsEntry ** ldaputils_get_entries PARAMS((LDAP * ld, LDAPMessage * res, const char * sortattr));

// retrieves values of an LDAP attribute
char * ldaputils_get_vals PARAMS((LDAPUtilsEntry * entry, const char * attr));

// connects and binds to LDAP server
LDAP * ldaputils_initialize PARAMS((LdapUtilsConfig * cnf));

// connects and binds to LDAP server
int ldaputils_search PARAMS((LDAP * ld, LdapUtilsConfig * cnf, LDAPMessage ** resp));

// sorts values
int ldaputils_sort_entries PARAMS((LDAPUtilsEntry ** entries));

// sorts values
int ldaputils_sort_values PARAMS((struct berval ** vals));

#endif /* end of header file */
