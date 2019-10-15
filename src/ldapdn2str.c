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
 *  @file src/ldaptree.c display LDAP tree structure
 */
/*
 *  Simple Build:
 *     export CFLAGS='-DPROGRAM_NAME="ldaptree" -Wall -I../include'
 *     gcc ${CFLAGS} -c ldapdn.c
 *     gcc ${CFLAGS} -lldap -llber -o ldapdn ldapdn.o ldaputils.a
 *
 *  Libtool Build:
 *     export CFLAGS='-DPROGRAM_NAME="ldapdn" -Wall -I../include'
 *     libtool --mode=compile --tag=CC gcc ${CFLAGS} -c ldapdn.c
 *     libtool --mode=link    --tag=CC gcc ${CFLAGS} -lldap -llber -o ldapdn \
 *             ldapdn.lo ldaputils.a
 *
 *  Libtool Clean:
 *     libtool --mode=clean rm -f ldapdn.lo ldapdn
 */
#define _LDAP_UTILS_SRC_LDAPDN2STR 1


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


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Definitions
#endif

#ifndef PROGRAM_NAME
#define PROGRAM_NAME "ldapdn2str"
#endif

#define MY_SHORT_OPTIONS "hV"


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Datatypes
#endif

enum my_format
{
   MY_FORMAT_DN     = 0x01,
   MY_FORMAT_RDN    = 0x02,
   MY_FORMAT_UFN    = 0x03,
   MY_FORMAT_ADC    = 0x04,
   MY_FORMAT_DCE    = 0x05,
   MY_FORMAT_IDN    = 0x06,
};
typedef enum my_format MyFormat;


/* configuration union */
typedef struct my_config MyConfig;
struct my_config
{
   LDAPUtils          * lud;
   MyFormat             type;
   LDAPDN               dn;
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
   printf("Usage: %s [options] dn\n", PROGRAM_NAME);
   ldaputils_usage_common(MY_SHORT_OPTIONS);
   printf("  --dn                      print distinguished name\n");
   printf("  --rdn                     print relative distinguished name\n");
   printf("  --ufn                     user friendly name of DN\n");
   printf("  --adc                     Active Directory canonical name\n");
   printf("  --dce                     DCE-style DN\n");
   printf("  --idn                     inverted DN\n");
   printf("\nReport bugs to <%s>.\n", PACKAGE_BUGREPORT);
   return;
}


/// main statement
/// @param[in] argc   number of arguments
/// @param[in] argv   array of arguments
int main(int argc, char * argv[])
{
   int                    err;
   int                    i;
   int                    len;
   char                 * str;
   char                ** edn;
   MyConfig             * cnf;

   cnf = NULL;

   // initializes resources and parses CLI arguments
   if ((err = my_config(argc, argv, &cnf)) != 0)
      return(1);
   if (!(cnf))
      return(0);

   switch(cnf->type)
   {
      case MY_FORMAT_ADC:
      ldap_dn2str(cnf->dn, &str, LDAP_DN_FORMAT_AD_CANONICAL);
      printf("%s\n", str);
      ldap_memfree(str);
      break;

      case MY_FORMAT_DCE:
      ldap_dn2str(cnf->dn, &str, LDAP_DN_FORMAT_DCE);
      printf("%s\n", str);
      ldap_memfree(str);
      break;

      case MY_FORMAT_UFN:
      ldap_dn2str(cnf->dn, &str, LDAP_DN_FORMAT_UFN);
      printf("%s\n", str);
      ldap_memfree(str);
      break;

      case MY_FORMAT_RDN:
      ldap_dn2str(cnf->dn, &str, LDAP_DN_FORMAT_LDAPV3);
      edn = ldap_explode_dn(str, 0);
      printf("%s\n", edn[0]);
      ldap_value_free(edn);
      ldap_memfree(str);
      break;

      case MY_FORMAT_IDN:
      ldap_dn2str(cnf->dn, &str, LDAP_DN_FORMAT_LDAPV3);
      edn = ldap_explode_dn(str, 0);
      for(len = 0; ((edn[len])); len++);
      printf("%s", edn[len-1]);
      for(i = len-1; i > 0; i--)
         printf(",%s", edn[i-1]);
      printf("\n");
      ldap_value_free(edn);
      ldap_memfree(str);
      break;

      default:
      ldap_dn2str(cnf->dn, &str, LDAP_DN_FORMAT_LDAPV3);
      printf("%s\n", str);
      ldap_memfree(str);
      break;
   };

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
      {"help",          no_argument,       0, 'h'},
      {"verbose",       no_argument,       0, 'v'},
      {"version",       no_argument,       0, 'V'},
      {"dn",            no_argument,       0, '9'},
      {"rdn",           no_argument,       0, '8'},
      {"ufn",           no_argument,       0, '7'},
      {"adc",           no_argument,       0, '6'},
      {"dce",           no_argument,       0, '5'},
      {"idn",           no_argument,       0, '4'},
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

         case '9':
         cnf->type = MY_FORMAT_DN;
         break;

         case '8':
         cnf->type = MY_FORMAT_RDN;
         break;

         case '7':
         cnf->type = MY_FORMAT_UFN;
         break;

         case '6':
         cnf->type = MY_FORMAT_ADC;
         break;

         case '5':
         cnf->type = MY_FORMAT_DCE;
         break;

         case '4':
         cnf->type = MY_FORMAT_IDN;
         break;

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

   // saves filter
   if (argc < (optind+1))
   {
      fprintf(stderr, "%s: missing required argument\n", PROGRAM_NAME);
      fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
      my_unbind(cnf);
      return(1);
   };
   if (argc > (optind+1))
   {
      fprintf(stderr, "%s: unknown argument `%s'\n", PROGRAM_NAME, argv[optind+1]);
      fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
      my_unbind(cnf);
      return(1);
   };

   // parses DN
   if ((err = ldap_str2dn(argv[optind], &cnf->dn, LDAP_DN_FORMAT_LDAPV3|LDAP_DN_PEDANTIC)))
   {
      fprintf(stderr, "%s: error processing DN with ldap_str2dn()\n", PROGRAM_NAME);
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

   if ((cnf->dn))
      ldap_dnfree(cnf->dn);

   free(cnf);

   return;
}

/* end of source file */
