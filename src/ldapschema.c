/*
 *  LDAP Utilities
 *  Copyright (C) 2019 David M. Syzdek <david@syzdek.net>.
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
 *  @file src/ldapschema.c display LDAP schema
 */
/*
 *  Simple Build:
 *     export CFLAGS='-DPROGRAM_NAME="ldapschema" -Wall -I../include'
 *     gcc ${CFLAGS} -c ldapschema.c
 *     gcc ${CFLAGS} -lldap -o ldapschema ldapschema.o
 *
 *  Libtool Build:
 *     export CFLAGS='-DPROGRAM_NAME="ldapschema" -Wall -I../include'
 *     libtool --mode=compile --tag=CC gcc ${CFLAGS} -c ldapschema.c
 *     libtool --mode=link    --tag=CC gcc ${CFLAGS} -lldap -o ldapschema \
 *             ldapschema.lo
 *
 *  Libtool Clean:
 *     libtool --mode=clean rm -f ldapschema.lo ldapschema
 */
#define _LDAP_UTILS_SRC_LDAPSCHEMA 1


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
#include <strings.h>
#include <time.h>
#include <getopt.h>
#include <assert.h>

#define LDAP_DEPRECATED 1
#include <ldap.h>
#include <ldaputils.h>
#include <ldapschema.h>


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Definitions
#endif

#ifndef PROGRAM_NAME
#define PROGRAM_NAME "ldaptree"
#endif

#define MY_SHORT_OPTIONS LDAPUTILS_OPTIONS_COMMON LDAPUTILS_OPTIONS_SEARCH "87:6:5:4:3"


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Datatypes
#endif

/* configuration union */
typedef struct my_config MyConfig;
struct my_config
{
   LDAPUtils          * lud;
   LDAPSchema         * lsd;
};


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
int my_config(int argc, char * argv[], MyConfig ** cnfp);

// fress resources
void my_unbind(MyConfig * cnf);


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
   ldaputils_usage_common(MY_SHORT_OPTIONS);
   printf("Display Options:\n");
   printf("  --compact                 remove white space used for styling\n");
   printf("\nReport bugs to <%s>.\n", PACKAGE_BUGREPORT);
   return;
}


/// main statement
/// @param[in] argc   number of arguments
/// @param[in] argv   array of arguments
int main(int argc, char * argv[])
{
   int                    err;
   MyConfig             * cnf;

   cnf = NULL;

   // initializes resources and parses CLI arguments
   if ((err = my_config(argc, argv, &cnf)) != 0)
      return(1);
   if (!(cnf))
      return(0);

   // starts TLS and binds to LDAP
   if ((err = ldaputils_bind_s(cnf->lud)) != LDAP_SUCCESS)
   {
      fprintf(stderr, "%s: ldap_sasl_bind_s(): %s\n", cnf->lud->prog_name, ldap_err2string(err));
      my_unbind(cnf);
      return(1);
   };

   // fetches schema
   if ((err = ldapschema_fetch(cnf->lsd, cnf->lud->ld)) != LDAP_SUCCESS)
   {
      fprintf(stderr, "%s: ldapschema_fetch(): %s\n", cnf->lud->prog_name, ldapschema_err2string(err));
      my_unbind(cnf);
      return(1);
   };

   ldapschema_print_syntaxes(cnf->lsd);
   ldapschema_print_attributetypes(cnf->lsd);

   // frees resources
   my_unbind(cnf);

   return(0);
}


/// parses configuration
/// @param[in] argc   number of arguments
/// @param[in] argv   array of arguments
/// @param[in] cnfp   reference to configuration pointer
int my_config(int argc, char * argv[], MyConfig ** cnfp)
{
   int        c;
   int        err;
   int        option_index;
   MyConfig * cnf;

   static char   short_options[] = MY_SHORT_OPTIONS;
   static struct option long_options[] =
   {
      {"compact",        no_argument,      0, '3'},
      {"style",         required_argument, 0, '4'},
      {"style",         required_argument, 0, '4'},
      {"max-nodes",     required_argument, 0, '5'},
      {"maxnodes",      required_argument, 0, '5'},
      {"max-leafs",     required_argument, 0, '6'},
      {"maxleafs",      required_argument, 0, '6'},
      {"max-depth",     required_argument, 0, '7'},
      {"maxdepth",      required_argument, 0, '7'},
      {"no-leafs",      no_argument,       0, '8'},
      {"noleafs",       no_argument,       0, '8'},
      {"help",          no_argument,       0, 'h'},
      {"verbose",       no_argument,       0, 'v'},
      {"version",       no_argument,       0, 'V'},
      {NULL,            0,                 0, 0  }
   };

   // allocates memory for configuration
   if (!(cnf = (MyConfig *) malloc(sizeof(MyConfig))))
   {
      fprintf(stderr, "%s: out of virtual memory\n", PROGRAM_NAME);
      return(1);
   };
   memset(cnf, 0, sizeof(MyConfig));

   // initialize ldap utilities
   if ((err = ldaputils_initialize(&cnf->lud, PROGRAM_NAME)) != LDAP_SUCCESS)
   {
      fprintf(stderr, "%s: ldaputils_initialize(): %s\n", PROGRAM_NAME, ldap_err2string(err));
      my_unbind(cnf);
      return(1);
   };

   // initialize ldap schema
   if ((err = ldapschema_initialize(&cnf->lsd)) != LDAP_SUCCESS)
   {
      fprintf(stderr, "%s: ldapschema_initialize(): %s\n", PROGRAM_NAME, ldapschema_err2string(err));
      my_unbind(cnf);
      return(1);
   };

   // loops through args
   option_index = 0;
   while((c = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1)
   {
      switch(ldaputils_getopt(cnf->lud, c, optarg))
      {
         // shared option exit without error
         case -2:
         my_unbind(cnf);
         return(0);

         // no more arguments
         case -1:
         break;

         // long options toggles
         case 0:
         break;

         // shared option error
         case 1:
         my_unbind(cnf);
         return(1);

         // argument error
         case '?':
         fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
         my_unbind(cnf);
         return(1);

         // unknown argument error
         default:
         fprintf(stderr, "%s: unrecognized option `--%c'\n", PROGRAM_NAME, c);
         fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
         my_unbind(cnf);
         return(1);
      };
   };

   // reads password
   if ((err = ldaputils_pass(cnf->lud)) != 0)
   {
      my_unbind(cnf);
      return(1);
   };

   *cnfp = cnf;

   return(0);
}


// fress resources
void my_unbind(MyConfig * cnf)
{
   assert(cnf != NULL);

   if ((cnf->lud))
      ldaputils_unbind(cnf->lud);

   if ((cnf->lsd))
      ldapschema_free(cnf->lsd);

   free(cnf);

   return;
}

/* end of source file */
