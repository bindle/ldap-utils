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
