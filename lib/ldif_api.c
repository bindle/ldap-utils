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
 *  @file lib/ldif_api.c provides methods for accessing library functionality
 */
#define _LDAP_UTILS_LIB_LDIF_API_C 1
#include "ldif_api.h"

///////////////
//           //
//  Headers  //
//           //
///////////////

#include "libldif.h"


/////////////////
//             //
//  Functions  //
//             //
/////////////////

/// returns package version
const char * ldif_package_version(void)
{
   return(PACKAGE_VERSION);
}

/* end of source file */
