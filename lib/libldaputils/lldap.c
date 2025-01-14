/*
 *  LDAP Utilities
 *  Copyright (C) 2012, 2019 David M. Syzdek <david@syzdek.net>.
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
 */
/**
 *  @file lib/libldaputils/lldap.c contains LDAP functions and variables
 */
#define _LIB_LIBLDAPUTILS_LLDAP_C 1
#include "lldap.h"

///////////////
//           //
//  Headers  //
//           //
///////////////
// MARK: - Headers

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <ldap.h>
#include <stdlib.h>
#include <assert.h>

#include "lconfig.h"


/////////////////
//             //
//  Functions  //
//             //
/////////////////
// MARK: - Functions

/// connects and binds to LDAP server
/// @param[in] lud   reference to LDAP utilities struct
///
/// @return    Returns the error code from the OpenLDAP library
/// @see       ldaputils_search, ldaputils_initialize
int ldaputils_bind_s(LDAPUtils * lud)
{
   int          err;
   LDAP       * ld;
   BerValue   * servercredp;

   ld          = lud->ld;
   servercredp = NULL;

   // starts TLS
   if (lud->tls_req > 0)
      if ((err = ldap_start_tls_s(lud->ld, NULL, NULL)) != LDAP_SUCCESS)
         if (lud->tls_req > 1)
            return(err);

   // binds to LDAP
   if ((err = ldap_sasl_bind_s(ld, lud->binddn, lud->sasl_mech, &lud->passwd, NULL, NULL, &servercredp)) != LDAP_SUCCESS)
      return(err);

   return(LDAP_SUCCESS);
}


/// connects and binds to LDAP server
/// @param[in]  lud    reference to LDAP utilities struct
/// @param[out] resp   reference for returned LDAPMessage
///
/// @return    Returns the error code from the OpenLDAP library
/// @see       ldaputils_search, ldaputils_initialize
int ldaputils_search(LDAPUtils * lud, LDAPMessage ** resp)
{
   int    rc;
   int    err;
   int    msgid;
   LDAP * ld;

   ld  = lud->ld;

   if ((err = ldap_search_ext(ld, NULL, lud->scope, lud->filter, lud->attrs, 0, NULL, NULL, NULL, -1, &msgid)) != LDAP_SUCCESS)
      return(err);

   switch((err = ldap_result(ld, msgid, LDAP_MSG_ALL, NULL, resp)))
   {
      case 0:
      break;

      case -1:
      return(err);

      default:
      break;
   };

   rc = ldap_parse_result(ld, *resp, &err, NULL, NULL, NULL, NULL, 0);
   if (rc != LDAP_SUCCESS)
      return(rc);
   if (err != LDAP_SUCCESS)
      return(err);

   return(LDAP_SUCCESS);
}

/* end of source file */
