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
 *  @file src/ldap2csv.c export LDAP data to CSV file
 */
/*
 *  Simple Build:
 *     export CFLAGS='-DPROGRAM_NAME="ldap2csv" -Wall -I../include'
 *     gcc ${CFLAGS} -c ldap2csv.c
 *     gcc ${CFLAGS} -lldap -o ldap2csv ldap2csv.o ../lib/libldaputils.a
 *
 *  Libtool Build:
 *     export CFLAGS='-DPROGRAM_NAME="ldap2csv" -Wall -I../include'
 *     libtool --mode=compile --tag=CC gcc ${CFLAGS} -c ldap2csv.c
 *     libtool --mode=link    --tag=CC gcc ${CFLAGS} -lldap -o ldap2csv \
 *             ldap2csv.lo ../lib/libldaputils.a
 *
 *  Libtool Clean:
 *     libtool --mode=clean rm -f ldap2csv.lo ldap2csv
 */
#define _LDAP_UTILS_SRC_LDAP2CSV 1
#undef __LDAPUTILS_PMARK


///////////////
//           //
//  Headers  //
//           //
///////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Headers
#endif

#include <ldaputils_compat.h>

#ifdef HAVE_CONFIG_H
#   include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <getopt.h>
#include <assert.h>

#ifdef USE_LDAP_DEPRECATED
#   define LDAP_DEPRECATED 1
#endif
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
#define PROGRAM_NAME "ldap2csv"
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
   LDAPSchema  * lsd;
   const char  * filter;
   const char  * prog_name;
   const char ** defvals;
   const char ** titles;
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
   printf("Usage: %s [options] [filter] attributes[:values[:title]]...\n", PROGRAM_NAME);
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
   int                    x;
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

   // fetches schema
   if ( ((err = ldapschema_fetch(cnf->lsd, cnf->lud->ld)) != LDAP_SUCCESS) && (err != LDAPSCHEMA_SCHEMA_ERROR) )
   {
      fprintf(stderr, "%s: ldapschema_fetch(): %s\n", cnf->lud->prog_name, ldapschema_err2string(err));
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

   // prints attribute names
   printf("\"%s\"", cnf->titles[0]);
   for(x = 1; ((cnf->titles[x])); x++)
      printf(",\"%s\"", cnf->titles[x]);
   printf("\n");

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
   size_t     len;
   size_t     size;

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

   cnf->prog_name = ldaputils_get_prog_name(cnf->lud);

   // saves filter
   if (argc > optind)
   {
      cnf->lud->filter = "(objectclass=*)";
      if ((strchr(argv[optind], '=')) != NULL)
      {
         cnf->lud->filter = argv[optind];
         optind++;
      };
   };

   // checks for required arguments
   if (argc < (optind+1))
   {
      fprintf(stderr, "%s: missing required arguments\n", cnf->prog_name);
      fprintf(stderr, "Try `%s --help' for more information.\n", cnf->prog_name);
      my_unbind(cnf);
      return(1);
   };

   // configures LDAP attributes to return in results
   len  = (size_t)(argc - optind) + 1;
   size = sizeof(char *) * len;
   if (!(cnf->lud->attrs = (char **) malloc(size)))
   {
      fprintf(stderr, "%s: out of virtual memory\n", cnf->prog_name);
      my_unbind(cnf);
      return(1);
   };
   memset(cnf->lud->attrs, 0, size);
   if (!(cnf->defvals = (const char **) malloc(size)))
   {
      fprintf(stderr, "%s: out of virtual memory\n", cnf->prog_name);
      my_unbind(cnf);
      return(1);
   };
   memset(cnf->defvals, 0, size);
   if (!(cnf->titles = (const char **) malloc(size)))
   {
      fprintf(stderr, "%s: out of virtual memory\n", cnf->prog_name);
      my_unbind(cnf);
      return(1);
   };
   memset(cnf->titles, 0, size);
   for(c = 0; c < (argc-optind); c++)
   {
      cnf->lud->attrs[c] = argv[optind+c];
      cnf->defvals[c]    = "";
      cnf->titles[c]     = argv[optind+c];
      if ((str = strchr(argv[optind+c], ':')) != NULL)
      {
         str[0] = '\0';
         cnf->defvals[c] = &str[1];
         if ((str = strchr(&str[1], ':')) != NULL)
         {
            str[0] = '\0';
            cnf->titles[c] = &str[1];
         };
      };
   };
   cnf->lud->attrs[c] = NULL;
   cnf->defvals[c]    = NULL;
   cnf->titles[c]     = NULL;

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
   void            * ptr;
   char            * buff;
   size_t            bufflen;
   char            * dn;
   char           ** dns;
   char            * dnstr;
   char            * delim;
   LDAPMessage     * msg;
   struct berval  ** vals;
   LDAP            * ld;
   LDAPSchemaAttributeType * attr;
   char           ** names;

   assert(cnf != NULL);
   assert(res != NULL);

   ld      = ldaputils_get_ld(cnf->lud);

   // initialize buffer
   bufflen = 32;
   if ((buff = malloc(bufflen)) == NULL)
   {
      fprintf(stderr, "%s: malloc(): out of virtual memory\n", cnf->prog_name);
      return(LDAP_NO_MEMORY);
   };

   // sorts entries
#ifdef USE_LDAP_DEPRECATED
   if ((cnf->lud->sortattr))
      ldap_sort_entries(ld, &res, cnf->lud->sortattr, strcasecmp);
#endif

   // loops through entries
   msg = ldap_first_entry(ld, res);
   while ((msg))
   {
      printf("\"");

      // retrieve DN and make CSV safe
      if ((dn = ldap_get_dn(ld, msg)) == NULL)
      {
         fprintf(stderr, "%s: malloc(): out of virtual memory\n", cnf->prog_name);
         free(buff);
         return(LDAP_NO_MEMORY);
      };
      delim = dn;
      while((delim = strchr(delim, '"')) != NULL)
         delim[0] = '\'';

      // loop through attributes
      for(x = 0; (cnf->lud->attrs[x] != NULL); x++)
      {
         // print delimiter
         if (x > 0)
            printf("\",\"");

         // prints dn if specified
         if (strcasecmp("dn", cnf->lud->attrs[x]) == 0)
         {
            printf("%s", dn);
            continue;
         };

         // print RDN
         if (strcasecmp("rdn", cnf->lud->attrs[x]) == 0)
         {
            if ((dns = ldap_explode_dn(dn, 0)) == NULL)
            {
               fprintf(stderr, "%s: ldap_explode_dn(): out of virtual memory\n", cnf->prog_name);
               free(buff);
               return(LDAP_NO_MEMORY);
            };
            printf("%s", dns[0]);
            ldaputils_value_free(dns);
            continue;
         };

         // print DN in UFN format
         if (strcasecmp("ufn", cnf->lud->attrs[x]) == 0)
         {
            if ((dnstr = ldap_dn2ufn(dn)) == NULL)
            {
               fprintf(stderr, "%s: ldap_dn2ufn(): out of virtual memory\n", cnf->prog_name);
               free(buff);
               return(LDAP_NO_MEMORY);
            };
            printf("%s", dnstr);
            ldap_memfree(dnstr);
            continue;
         };

         // print DN in DCE format
         if (strcasecmp("dce", cnf->lud->attrs[x]) == 0)
         {
            if ((dnstr = ldap_dn2dcedn(dn)) == NULL)
            {
               fprintf(stderr, "%s: ldap_dn2dcedn(): out of virtual memory\n", cnf->prog_name);
               free(buff);
               return(LDAP_NO_MEMORY);
            };
            printf("%s", dnstr);
            ldap_memfree(dnstr);
            continue;
         };

         // print DN in AD canonical format
         if (strcasecmp("adc", cnf->lud->attrs[x]) == 0)
         {
            if ((dnstr = ldap_dn2ad_canonical(dn)) == NULL)
            {
               fprintf(stderr, "%s: ldap_dn2ad_canonical(): out of virtual memory\n", cnf->prog_name);
               free(buff);
               return(LDAP_NO_MEMORY);
            };
            printf("%s", dnstr);
            ldap_memfree(dnstr);
            continue;
         };

         // retrieves values
         names = NULL;
         vals  = NULL;
         if ((attr = ldapschema_find_attributetype(cnf->lsd, cnf->lud->attrs[x])) != NULL)
            ldapschema_get_info_attributetype(cnf->lsd, attr, LDAPSCHEMA_FLD_NAME, &names);
         for(y = 0; (((names)) && ((names[y])) && (!(vals))); y++)
            vals = ldap_get_values_len(ld, msg, names[y]);
         if (!(vals))
            vals = ldap_get_values_len(ld, msg, cnf->lud->attrs[x]);
         if (!(vals))
         {
            printf("%s", cnf->defvals[x]);
            continue;
         };

         // processes values
         for(y = 0; (y < ldap_count_values_len(vals)); y++)
         {
            // adjusts size of buffer
            if (bufflen < (vals[y]->bv_len + 1))
            {
               bufflen = vals[y]->bv_len + 1;
               if ((ptr = realloc(buff, bufflen)) == NULL)
               {
                  fprintf(stderr, "%s: realloc(): out of virtual memory\n", cnf->prog_name);
                  free(buff);
                  return(LDAP_NO_MEMORY);
               };
               buff = ptr;
            };

            // copies value into buffer
            memcpy(buff, vals[y]->bv_val, vals[y]->bv_len);
            buff[vals[y]->bv_len] = '\0';

            // replace double quotation character with single quotation character
            delim = buff;
            while((delim = strchr(delim, '"')) != NULL)
               delim[0] = '\'';
            delim = buff;
            while((delim = strchr(delim, '|')) != NULL)
               delim[0] = ':';

            // print value
            if (y > 0)
               printf("|%s", buff);
            else
               printf("%s", buff);
         };
         ldap_value_free_len(vals);
      };
      printf("\"\n");

      // frees DN
      ldap_memfree(dn);

      // retrieves next entry
      msg = ldap_next_entry(ld, msg);
   };

   free(buff);

   return(LDAP_SUCCESS);
}


// fress resources
void my_unbind(MyConfig * cnf)
{
   assert(cnf != NULL);

   if ((cnf->lsd))
      ldapschema_free(cnf->lsd);

   if ((cnf->lud))
      ldaputils_unbind(cnf->lud);

   if ((cnf->defvals))
      free(cnf->defvals);

   if ((cnf->titles))
      free(cnf->titles);

   free(cnf);

   return;
}

/* end of source file */
