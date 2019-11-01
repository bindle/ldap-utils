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
 *  @file src/ldap2json.c export LDAP data to JSON format
 */
/*
 *  Simple Build:
 *     export CFLAGS='-DPROGRAM_NAME="ldap2json" -Wall -I../include'
 *     gcc ${CFLAGS} -c ldap2json.c
 *     gcc ${CFLAGS} -lldap -o ldap2json ldap2json.o ../lib/libldaputils.a
 *
 *  Libtool Build:
 *     export CFLAGS='-DPROGRAM_NAME="ldap2json" -Wall -I../include'
 *     libtool --mode=compile --tag=CC gcc ${CFLAGS} -c ldap2json.c
 *     libtool --mode=link    --tag=CC gcc ${CFLAGS} -lldap -o ldap2json \
 *             ldap2json.lo ../lib/libldaputils.a
 *
 *  Libtool Clean:
 *     libtool --mode=clean rm -f ldap2json.lo ldap2json
 */
#define _LDAP_UTILS_SRC_LDAP2JSON 1


///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

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
#pragma mark - Definitions

#ifndef PROGRAM_NAME
#define PROGRAM_NAME "ldap2json"
#endif

#define MY_SHORT_OPTIONS LDAPUTILS_OPTIONS_COMMON LDAPUTILS_OPTIONS_SEARCH "o:"


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#pragma mark - Datatypes

// configuration union
typedef struct my_config MyConfig;
struct my_config
{
   size_t        attrs_len;
   LDAPUtils   * lud;
   const char  * filter;
   const char  * prog_name;
   const char ** defvals;
   char          output[LDAPUTILS_OPT_LEN];
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

int my_results(MyConfig * cnf, LDAPMessage * res);

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
   printf("Usage: %s [options] [filter] attributes[:values]...\n", PROGRAM_NAME);
   ldaputils_usage_search(MY_SHORT_OPTIONS);
   ldaputils_usage_common(MY_SHORT_OPTIONS);
   printf("Special Attributes:\n");
   printf("  dn                        entry's DN\n");
   printf("  rdn                       entry's relative DN\n");
   printf("  ufn                       entry's User Friendly Name\n");
   printf("  adc                       entry's Active Directory canonical name\n");
   printf("  dce                       entry's DN in DCE-style\n");
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

   cnf = NULL;

   // initializes resources and parses CLI arguments
   if ((err = my_config(argc, argv, &cnf)) != 0)
      return(1);
   if (!(cnf))
      return(0);

   // starts TLS and binds to LDAP
   if ((err = ldaputils_bind_s(cnf->lud)) != LDAP_SUCCESS)
   {
      fprintf(stderr, "%s: ldap_sasl_bind_s(): %s\n", ldaputils_get_prog_name(cnf->lud), ldap_err2string(err));
      my_unbind(cnf);
      return(1);
   };

   // performs LDAP search
   if ((err = ldaputils_search(cnf->lud, &res)) != LDAP_SUCCESS)
   {
      fprintf(stderr, "%s: ldaputils_search(): %s\n", ldaputils_get_prog_name(cnf->lud), ldap_err2string(err));
      my_unbind(cnf);
      return(1);
   };

   // prints values
   if ((err = my_results(cnf, res)) != LDAP_SUCCESS)
   {
      my_unbind(cnf);
      return(1);
   };

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
   char     * str;
   MyConfig * cnf;

   static char   short_options[] = MY_SHORT_OPTIONS;
   static struct option long_options[] =
   {
      {"help",          no_argument, 0, 'h'},
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

   cnf->prog_name = ldaputils_get_prog_name(cnf->lud);

   // checks for required arguments
   if (argc < (optind+1))
   {
      fprintf(stderr, "%s: missing required arguments\n", cnf->prog_name);
      fprintf(stderr, "Try `%s --help' for more information.\n", cnf->prog_name);
      my_unbind(cnf);
      return(1);
   };

   // saves filter
   cnf->lud->filter = "(objectclass=*)";
   if ((index(argv[optind], '=')) != NULL)
   {
      cnf->lud->filter = argv[optind];
      optind++;
   };

   // configures LDAP attributes to return in results
   cnf->attrs_len = (size_t)(argc-optind);
   if (!(cnf->lud->attrs = (char **) malloc(sizeof(char *) * (cnf->attrs_len+1))))
   {
      fprintf(stderr, "%s: out of virtual memory\n", cnf->prog_name);
      my_unbind(cnf);
      return(1);
   };
   bzero(cnf->lud->attrs, sizeof(char *) * (cnf->attrs_len+1));
   if (!(cnf->defvals = (const char **) malloc(sizeof(char *) * (cnf->attrs_len+1))))
   {
      fprintf(stderr, "%s: out of virtual memory\n", cnf->prog_name);
      my_unbind(cnf);
      return(1);
   };
   bzero(cnf->defvals, sizeof(char *) * (cnf->attrs_len+1));
   for(c = 0; c < (argc-optind); c++)
   {
      cnf->lud->attrs[c] = argv[optind+c];
      if ((str = index(argv[optind+c], ':')) != NULL)
      {
         str[0] = '\0';
         cnf->defvals[c] = &str[1];
      };
   };
   cnf->lud->attrs[c] = NULL;
   cnf->defvals[c]    = NULL;

   // reads password
   if ((err = ldaputils_pass(cnf->lud)) != 0)
   {
      my_unbind(cnf);
      return(1);
   };

   *cnfp = cnf;

   return(0);
}


// prints results
int my_results(MyConfig * cnf, LDAPMessage * res)
{
   int               x;
   int               y;
   char            * dnstr;
   char            * dn;
   char           ** dns;
   char            * delim;
   LDAPMessage     * msg;
   char           ** vals;
   LDAP            * ld;
   BerElement      * ber;
   char            * attr;

   assert(cnf != NULL);
   assert(res != NULL);

   ld      = ldaputils_get_ld(cnf->lud);

   // sorts entries
   if ((cnf->lud->sortattr))
      ldap_sort_entries(ld, &res, cnf->lud->sortattr, strcasecmp);

   // print header
   printf("[\n");

   // loops through entries
   msg = ldap_first_entry(ld, res);
   while ((msg))
   {
      // retrieve first attribute
      attr = ldap_first_attribute(ld, msg, &ber);

      // retrieve DN and make CSV safe
      if ((dn = ldap_get_dn(ld, msg)) == NULL)
      {
         fprintf(stderr, "%s: malloc(): out of virtual memory\n", cnf->prog_name);
         return(LDAP_NO_MEMORY);
      };
      delim = dn;
      while((delim = index(delim, '"')) != NULL)
         delim[0] = '\'';

      // start entry
      if ((dns = ldap_explode_dn(dn, 0)) == NULL)
      {
         fprintf(stderr, "%s: ldap_explode_dn(): out of virtual memory\n", cnf->prog_name);
         return(LDAP_NO_MEMORY);
      };
      printf("   {\n");

      // loop through psuedo attributes
      for(x = 0; (cnf->lud->attrs[x] != NULL); x++)
      {
         if (strcasecmp("dn", cnf->lud->attrs[x]) == 0)
            printf("      \"dn\": \"%s\"", dn);
         else if (strcasecmp("rdn", cnf->lud->attrs[x]) == 0)
            printf("      \"rdn\": \"%s\"", dns[0]);
         else if (strcasecmp("ufn", cnf->lud->attrs[x]) == 0)
         {
            if ((dnstr = ldap_dn2ufn(dn)) == NULL)
            {
               fprintf(stderr, "%s: ldap_dn2ufn(): out of virtual memory\n", cnf->prog_name);
               return(LDAP_NO_MEMORY);
            };
            printf("      \"ufn\": \"%s\"", dnstr);
            ldap_memfree(dnstr);
         }
         else if (strcasecmp("dce", cnf->lud->attrs[x]) == 0)
         {
            if ((dnstr = ldap_dn2dcedn(dn)) == NULL)
            {
               fprintf(stderr, "%s: ldap_dn2dcedn(): out of virtual memory\n", cnf->prog_name);
               return(LDAP_NO_MEMORY);
            };
            printf("      \"dce\": \"%s\"", dnstr);
            ldap_memfree(dnstr);
         }
         else if (strcasecmp("adc", cnf->lud->attrs[x]) == 0)
         {
            if ((dnstr = ldap_dn2ad_canonical(dn)) == NULL)
            {
               fprintf(stderr, "%s: ldap_dn2ad_canonical(): out of virtual memory\n", cnf->prog_name);
               return(LDAP_NO_MEMORY);
            };
            printf("      \"adc\": \"%s\"", dnstr);
            ldap_memfree(dnstr);
         }
         else
         {
            if ((vals = ldap_get_values(ld, msg, cnf->lud->attrs[x])) != NULL)
            {
               ldap_value_free(vals);
               continue;
            };
            if (cnf->defvals[x] == NULL)
               continue;
            printf("      \"%s\": \"%s\"", cnf->lud->attrs[x], cnf->defvals[x]);
         };

         if ( ((cnf->lud->attrs[x+1])) || ((attr)) )
            printf(",\n");
         else
            printf("\n");
      };

      ldap_value_free(dns);
      ldap_memfree(dn);

      // loop through attributes
      while ((attr))
      {
         // retrieves values
         if ((vals = ldap_get_values(ld, msg, attr)) == NULL)
         {
            for(x = 0; ( ((cnf->lud->attrs[x])) && (!(strcasecmp(attr, cnf->lud->attrs[x])))); x++);
            if ((cnf->defvals[x]))
                printf("      \"%s\": \"%s\"", attr, cnf->defvals[x]);
            else
               printf("      \"%s\": null", attr);
         }
         else if (vals[1] == NULL)
         {
            printf("      \"%s\": \"%s\"", attr, vals[0]);
            ldap_value_free(vals);
         }
         else
         {
            printf("      \"%s\": [", attr);
            for(y = 0; (y < ldap_count_values(vals)); y++)
            {
               if (y > 0)
                  printf(", \"%s\"", vals[y]);
               else
                  printf(" \"%s\"", vals[y]);
            };
            printf(" ]");
            ldap_value_free(vals);
         };
         if ((attr = ldap_next_attribute(ld, msg, ber)) == NULL)
            printf("\n");
         else
            printf(",\n");
      };
      ber_free(ber, 0);

      // retrieves next entry
      if ((msg = ldap_next_entry(ld, msg)) == NULL)
         printf("   }\n");
      else
         printf("   },\n");
   };

   printf("]\n");

   return(LDAP_SUCCESS);
}


// fress resources
void my_unbind(MyConfig * cnf)
{
   assert(cnf != NULL);

   if ((cnf->lud))
      ldaputils_unbind(cnf->lud);

   if ((cnf->defvals))
      free(cnf->defvals);

   free(cnf);

   return;
}

/* end of source file */
