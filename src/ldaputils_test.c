/*
 *  LDAP Utilities
 *  Copyright (c) 2008 David M. Syzdek <ldap-utils-project@syzdek.net>.
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
/*
 *  src/ldaputils_test.c - simple program for testing common functions
 */
/*
 *  Simple Build:
 *     gcc -Wall -c ldaputils_test.c
 *     gcc -Wall -c ldaputils_common.c
 *     gcc -Wall -o ldaputils_test ldaputils_test.o ldaputils_common.o
 *
 *  Libtool Build:
 *     libtool --mode=compile gcc -Wall -g -O2 -I../include -c ldaputils_test.c
 *     libtool --mode=compile gcc -Wall -g -O2 -I../include -c ldaputils_common.c
 *     libtool --mode=link    gcc -Wall -g -O2 -L../lib -o ldaputils_test \
 *             ldaputils_test.o ldaputils_common.o
 *
 *  Libtool Clean:
 *     libtool --mode=clean rm -f ldaputils_test.lo ldaputils_common.lo ldaputils_test
 */
#define _LDAP_UTILS_SRC_LDAPUTILS_TEST 1

///////////////
//           //
//  Headers  //
//           //
///////////////

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "ldaputils_common.h"

//////////////////
//              //
//  Prototypes  //
//              //
//////////////////

/* main statement */
int main PARAMS((int argc, char * argv[]));

/* parses config */
MyCommonConfig * my_cmdline PARAMS((int argc, char *argv[]));

/////////////////
//             //
//  Functions  //
//             //
/////////////////

/* main statement */
int main(int argc, char * argv[])
{
   MyCommonConfig * cnf;

#ifdef HAVE_GETTEXT
   setlocale (LC_ALL, ""); 
   bindtextdomain (PACKAGE, LOCALEDIR); 
   textdomain (PACKAGE);
#endif

   if (!(cnf = my_cmdline(argc, argv)))
      return(1);

   printf("\nLDAP skip init: %i", cnf->noinit);
   printf("\nLDAP host:      ");
   if (cnf->host)
      printf("%s", cnf->host);
   printf("\nLDAP port:      ");
   if (cnf->port)
      printf("%i", cnf->port);
   printf("\nLDAP URI:       ");
   if (cnf->uri)
      printf("%s", cnf->uri);
   printf("\nLDAP basedn:    ");
   if (cnf->basedn)
      printf("%s", cnf->basedn);
   printf("\nLDAP binddn:    ");
   if (cnf->binddn)
      printf("%s", cnf->binddn);
   printf("\nLDAP bindpw:    ");
   if (cnf->bindpw)
      printf("%s", cnf->bindpw);
   printf("\nLDAP version:   ");
   if (cnf->version)
      printf("%i", cnf->version);
   printf("\nLDAP sizelimit: %i", cnf->sizelimit);
   printf("\nLDAP timelimit: %i", cnf->timelimit);

   printf("\n");

   my_common_config_free(cnf);
   free(cnf);

   return(0);
}

/* parses config */
MyCommonConfig * my_cmdline(int argc, char *argv[])
{
   /* declares local vars */
   int        c;
   int        option_index;
   MyCommonConfig * cnf;

   static char   short_options[] = MY_COMMON_OPTIONS;
   static struct option long_options[] =
   {
      {"help",          no_argument, 0, 'u'},
      {"verbose",       no_argument, 0, 'v'},
      {"version",       no_argument, 0, 'V'},
      {NULL,            0,           0, 0  }
   };

   /* allocates memory */
   if (!(cnf = (MyCommonConfig *) malloc(sizeof(MyCommonConfig))))
   {
      fprintf(stderr, _("%s: out of virtual memory\n"), PROGRAM_NAME);
      return(NULL);
   };
   memset(cnf, 0, sizeof(MyCommonConfig));

   /* parses environment variables */
   if (my_common_environment(cnf))
   {
      my_common_config_free(cnf);
      free(cnf);
      return(NULL);
   };

   /* processes config */
   if (my_common_config(cnf))
   {
      my_common_config_free(cnf);
      free(cnf);
      return(NULL);
   };

   /* sets variables */
   option_index = 0;

   /* loops through args */
   while((c = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1)
   {
      if (my_common_cmdargs(cnf, (int)c, optarg))
      {
         my_common_config_free(cnf);
         free(cnf);
         return(NULL);
      };
   };

   /* ends function */
   return(cnf);
}

/* end of source file */
