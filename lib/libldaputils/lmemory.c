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
 *  @file src/ldaputils_misc.c contains shared functions and variables
 */
#define _LIB_LIBLDAPUTILS_LMEMORY_C 1
#include "lmemory.h"

///////////////
//           //
//  Headers  //
//           //
///////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Headers
#endif

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
#ifdef __LDAPUTILS_PMARK
#pragma mark - Functions
#endif

/// removes newlines and carriage returns
/// @param[in] str
char * ldaputils_chomp(char * str)
{
   char * idx;

   if (!(str))
      return(NULL);

   if ((idx = strchr(str, '\n')))
      idx[0] = '\0';
   if ((idx = strchr(str, '\r')))
      idx[0] = '\0';

   return(str);
}


// connects and binds to LDAP server
int ldaputils_initialize(LDAPUtils ** ludp, const char * prog_name)
{
   int         err;
   char      * idx;
   int         i;
   LDAPUtils * lud;

   assert(ludp      != NULL);
   assert(prog_name != NULL);

   // allocate initial memory for base struct
   if ((lud = malloc(sizeof(LDAPUtils))) == NULL)
      return(LDAP_NO_MEMORY);
   bzero(lud, sizeof(LDAPUtils));

   // save program name
   if ((idx = rindex(prog_name, '/')) != NULL)
      if (idx[1] != '\0')
         prog_name = &idx[1];
   lud->prog_name = prog_name;

   // set defaults
   lud->scope = LDAP_SCOPE_SUB;

   // initialize LDAP library
   if ((err = ldap_initialize(&lud->ld, NULL)) != LDAP_SUCCESS)
   {
      ldaputils_unbind(lud);
      return(err);
   };

   // set defaults
   lud->scope = LDAP_SCOPE_SUBTREE;
   i = 3; ldap_set_option(lud->ld, LDAP_OPT_PROTOCOL_VERSION, &i);

   *ludp = lud;

   return(LDAP_SUCCESS);
}


/// frees common config
/// @param[in] lud
void ldaputils_unbind(LDAPUtils * lud)
{
   if (!(lud))
      return;

   if ((lud->ld))
      ldap_unbind_ext_s(lud->ld, NULL, NULL);

   if ((lud->attrs))
      free(lud->attrs);

   free(lud);

   return;
}

/* end of source file */
