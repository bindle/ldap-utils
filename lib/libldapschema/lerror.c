
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
 *   @file src/ldapschema/lerror.c  contains error functions and variables
 */
#define _LIB_LIBLDAPSCHEMA_LERROR_C 1
#include "lerror.h"

///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <ldap.h>
#include <stdlib.h>
#include <assert.h>


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

/// initializes LDAP schema
/// @param[in]    err         Numeric error code
///
/// @return    Returns a string representation of the error code.
/// @see       ldapschema_free, ldapschema_initialize, ldapschema_errno
const char * ldapschema_err2string( int err )
{
   switch(err)
   {
      case LDAPSCHEMA_SUCCESS:      return("success");
      case LDAPSCHEMA_NO_MEMORY:    return("out of virtual memory");
      default:                      return("unknown error");
   };

   return(LDAP_SUCCESS);
}


/// initializes LDAP schema
/// @param[in]  lsd    Reference to allocated ldap_schema struct
///
/// @return    Returns a numeric code of last error
/// @see       ldapschema_free, ldapschema_initialize, ldapschema_err2string
int ldapschema_errno( LDAPSchema * lsd )
{
   assert(lsd != NULL);
   return(lsd->errcode);
}

/* end of source file */
