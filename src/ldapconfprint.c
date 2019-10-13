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
 *  @file src/ldapconfprint.c export LDAP data to CSV file
 */
/*
 *  Simple Build:
 *     export CFLAGS='-DPROGRAM_NAME="ldapconfprint" -Wall -I../include'
 *     gcc ${CFLAGS} -c ldapconfprint.c
 *     gcc ${CFLAGS} -c ldaputils_config.c
 *     gcc ${CFLAGS} -c ldaputils_config_opts.c
 *     gcc ${CFLAGS} -o ldapconfprint ldapconfprint.o ldaputils_config.o \
 *             ldaputils_config_opts.o -lldap
 *
 *  Libtool Build:
 *     export CFLAGS='-DPROGRAM_NAME="ldapconfprint" -Wall -I../include'
 *     libtool --mode=compile --tag=CC gcc ${CFLAGS} -c ldapconfprint.c
 *     libtool --mode=compile --tag=CC gcc ${CFLAGS} -c ldaputils_config.c
 *     libtool --mode=compile --tag=CC gcc ${CFLAGS} -c ldaputils_config_opts.c
 *     libtool --mode=link    --tag=CC gcc ${CFLAGS} -o ldapconfprint \
 *             ldapconfprint.o ldaputils_config.o ldaputils_config_opts.o \
 *             -lldap
 *
 *  Libtool Clean:
 *     libtool --mode=clean rm -f ldapconfprint.lo ldaputils_config.lo \
 *             ldaputils_config_opts.lo ldapconfprint
 */
#define _LDAP_UTILS_SRC_LDAPCONFPRINT 1
#undef __LDAPUTILS_PMARK


///////////////
//           //
//  Headers  //
//           //
///////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Headers
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <getopt.h>

#define LDAP_DEPRECATED 1
#include <ldap.h>
#include <ldaputils.h>


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Definitions
#endif

#ifndef PROGRAM_NAME
#define PROGRAM_NAME "ldapconfprint"
#endif

#define MY_SHORT_OPTIONS LDAPUTILS_OPTIONS_COMMON LDAPUTILS_OPTIONS_SEARCH "o:"


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Prototypes
#endif

// main statement
int main(int argc, char * argv[]);

// parses configuration
int my_config(int argc, char * argv[], LDAPUtils ** ludp);


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Functions
#endif

/// prints program usage and exits
void ldaputils_usage(void)
{
   printf("Usage: %s [options] [filter [attributes...]]\n", PROGRAM_NAME);
   ldaputils_usage_search(MY_SHORT_OPTIONS);
   ldaputils_usage_common(MY_SHORT_OPTIONS);
   printf("\nReport bugs to <%s>.\n", PACKAGE_BUGREPORT);
   return;
}


/// main statement
/// @param[in] argc   number of arguments
/// @param[in] argv   array of arguments
int main(int argc, char * argv[])
{
   LDAPUtils * lud;

   if ((my_config(argc, argv, &lud)))
      return(1);
   if (!(lud))
      return(0);

   ldaputils_bind_s(lud);

   ldaputils_params(lud);

   ldaputils_unbind(lud);

   return(0);
}


/// parses configuration
/// @param[in] argc   number of arguments
/// @param[in] argv   array of arguments
int my_config(int argc, char * argv[], LDAPUtils ** ludp)
{
   int               c;
   int               err;
   int               option_index;

   static char   short_options[] = MY_SHORT_OPTIONS;
   static struct option long_options[] =
   {
      {"help",          no_argument, 0, 'h'},
      {"verbose",       no_argument, 0, 'v'},
      {"version",       no_argument, 0, 'V'},
      {NULL,            0,           0, 0  }
   };

   option_index = 0;
   *ludp        = NULL;

   // initialize ldap utilities
   if ((err = ldaputils_initialize(ludp, PROGRAM_NAME)) != LDAP_SUCCESS)
   {
      fprintf(stderr, "%s: ldaputils_initialize(): %s\n", PROGRAM_NAME, ldap_err2string(err));
      ldaputils_unbind(*ludp);
      return(1);
   };

   // loops through args
   while((c = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1)
   {
      switch(ldaputils_getopt(*ludp, c, optarg))
      {
         // shared option exit without error
         case -2:
         ldaputils_unbind(*ludp);
         *ludp = NULL;
         return(0);

         // no more arguments
         case -1:
         break;

         // long options toggles
         case 0:
         break;

         // shared option error
         case 1:
         ldaputils_unbind(*ludp);
         *ludp = NULL;
         return(1);

         // argument error
         case '?':
         fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
         ldaputils_unbind(*ludp);
         *ludp = NULL;
         return(1);

         default:
         fprintf(stderr, "%s: unrecognized option `--%c'\n", PROGRAM_NAME, c);
         fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
         ldaputils_unbind(*ludp);
         *ludp = NULL;
         return(1);
      };
   };

   // saves filter
   if (argc > optind)
      (*ludp)->filter = argv[optind];

   if (argc <= (optind+1))
      return(0);

   // configures LDAP attributes to return in results
   if (!((*ludp)->attrs = (char **) malloc(sizeof(char *) * (size_t)(argc-optind))))
   {
      fprintf(stderr, "%s: out of virtual memory\n", PROGRAM_NAME);
      ldaputils_unbind(*ludp);
      return(1);
   };
   for(c = 0; c < (argc-optind-1); c++)
      (*ludp)->attrs[c] = argv[optind+1+c];
   (*ludp)->attrs[c] = NULL;

   // reads password
   if ((err = ldaputils_pass(*ludp)) != 0)
   {
      ldaputils_unbind(*ludp);
      return(1);
   };

   return(0);
}

/* end of source file */
