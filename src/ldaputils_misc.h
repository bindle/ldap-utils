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
#ifndef _LDAP_UTILS_SRC_LDAPUTILS_MISC_H
#define _LDAP_UTILS_SRC_LDAPUTILS_MISC_H 1


///////////////
//           //
//  Headers  //
//           //
///////////////

#include <ldap-utils.h>


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////

// removes newlines and carriage returns
char * ldaputils_chomp PARAMS((char * str));

// getpass() replacement -- SUSV 2 deprecated getpass()
int ldaputils_getpass PARAMS((const char * prompt, char * buff, size_t len));

#endif /* end of header file */
