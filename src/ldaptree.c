/*
 *  LDAP Utilities
 *  Copyright (C) 2019 Bindle Binaries <syzdek@bindlebinaries.com>.
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
 *  @file src/ldaptree.c display LDAP tree structure
 */
/*
 *  Simple Build:
 *     export CFLAGS='-DPROGRAM_NAME="ldaptree" -Wall -I../include'
 *     gcc ${CFLAGS} -c ldaptree.c
 *     gcc ${CFLAGS} -c ldaputils_config.c
 *     gcc ${CFLAGS} -c ldaputils_config_opts.c
 *     gcc ${CFLAGS} -c ldaputils_ldap.c
 *     gcc ${CFLAGS} -lldap -o ldaptree ldaptree.o ldaputils_config.o \
 *             ldaputils_config_opts.o ldaputils_ldap.o
 *
 *  Libtool Build:
 *     export CFLAGS='-DPROGRAM_NAME="ldaptree" -Wall -I../include'
 *     libtool --mode=compile --tag=CC gcc ${CFLAGS} -c ldaptree.c
 *     libtool --mode=compile --tag=CC gcc ${CFLAGS} -c ldaputils_config.c
 *     libtool --mode=compile --tag=CC gcc ${CFLAGS} -c ldaputils_config_opts.c
 *     libtool --mode=compile --tag=CC gcc ${CFLAGS} -c ldaputils_ldap.c
 *     libtool --mode=link    --tag=CC gcc ${CFLAGS} -lldap -o ldaptree \
 *             ldaptree.lo ldaputils_config.lo ldaputils_config_opts.lo \
 *             ldaputils_ldap.lo
 *
 *  Libtool Clean:
 *     libtool --mode=clean rm -f ldaptree.lo ldaputils_config.lo \
 *             ldaputils_config_opts.lo ldaputils_ldap.lo ldaptree
 */
#define _LDAP_UTILS_SRC_LDAP2CSV 1


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
#define PROGRAM_NAME "ldaptree"
#endif

#define MY_SHORT_OPTIONS LDAPUTILS_OPTIONS_COMMON LDAPUTILS_OPTIONS_SEARCH "o:"


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
   LDAPUtils   * lud;
   char        * basedn;
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
   printf("Usage: %s [options] [filter] ...\n", PROGRAM_NAME);
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
   int                    err;
   MyConfig             * cnf;
   LDAPMessage          * res;
   LDAPUtilsEntry      ** entries;
   const char * const   * components;
   size_t                 components_len;

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

   // performs LDAP search
   if ((err = ldaputils_search(cnf->lud, &res)) != LDAP_SUCCESS)
   {
      fprintf(stderr, "%s: ldaputils_search(): %s\n", cnf->lud->prog_name, ldap_err2string(err));
      my_unbind(cnf);
      return(1);
   };

   // retrieve entries
   if ((entries = ldaputils_get_entries(cnf->lud->ld, res, NULL)) == NULL)
   {
      fprintf(stderr, "%s: ldaputils_get_entries(): out of virtual memory\n", cnf->lud->prog_name);
      my_unbind(cnf);
      return(1);
   };

   // sort entries
   ldaputils_entries_sort(entries, ldaputils_cmp_entrydn);


size_t x;
size_t y;
for(x = 0; ((entries[x])); x++)
{
   components = ldaputils_get_dn_components(entries[x], &components_len);
   printf("dn: %s", components[0]);
   for(y = 1; ((components[y])); y++)
      printf(",%s", components[y]);
   printf("\n");
};

   //// prints values
   //if ((err = my_results(cnf, res)) != LDAP_SUCCESS)
   //{
   //   my_unbind(cnf);
   //   return(1);
   //};
   
   ldap_msgfree(res);
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
      {"help",          no_argument, 0, '9'},
      {"verbose",       no_argument, 0, 'v'},
      {"version",       no_argument, 0, 'V'},
      {NULL,            0,           0, 0  }
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

   // loops through args
   option_index = 0;
   while((c = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1)
   {
      switch(ldaputils_cmdargs(cnf->lud, c, optarg))
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

   // checks for required arguments
   if (argc > (optind+1))
   {
      fprintf(stderr, "%s: unknown argument \"%s\"\n", PROGRAM_NAME, argv[optind+1]);
      fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
      my_unbind(cnf);
      return(1);
   };

   // saves filter
   cnf->lud->filter = "(objectclass=*)";
   if (argc == (optind+1))
      cnf->lud->filter = argv[optind];

   // configures LDAP attributes to return in results
   if (!(cnf->lud->attrs = (char **) malloc(sizeof(char *) * 2)))
   {
      fprintf(stderr, "%s: out of virtual memory\n", PROGRAM_NAME);
      my_unbind(cnf);
      return(1);
   };
   cnf->lud->attrs[0] = NULL;
   cnf->lud->attrs[1] = NULL;
   //if ((cnf->lud->attrs[0] = strdup("structuralObjectClass")) == NULL)
   if ((cnf->lud->attrs[0] = strdup("dn")) == NULL)
   {
      fprintf(stderr, "%s: out of virtual memory\n", PROGRAM_NAME);
      my_unbind(cnf);
      return(1);
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

   free(cnf);

   return;
}

/* end of source file */
