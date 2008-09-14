/*
 *  $Id$
 */
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
/**
 *  @file src/ldap2csv.c export LDAP data to CSV file
 */
/*
 *  Simple Build:
 *     gcc -Wall -c ldap2csv.c
 *     gcc -Wall -o ldap2csv ldap2csv.o
 *
 *  Libtool Build:
 *     libtool --mode=compile gcc -Wall -g -O2 -I../include -c ldap2csv.c
 *     libtool --mode=link    gcc -Wall -g -O2 -L../lib -o ldap2csv \
 *             ldap2csv.o
 *
 *  Libtool Clean:
 *     libtool --mode=clean rm -f ldap2csv.lo ldap2csv
 */
#define _LDAP_UTILS_SRC_LDAP2CSV 1


///////////////
//           //
//  Headers  //
//           //
///////////////

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <getopt.h>

#include "ldaputils_common.h"

///////////////////
//               //
//  Definitions  //
//               //
///////////////////

#ifndef PROGRAM_NAME
#define PROGRAM_NAME "ldap2csv"
#endif


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////

/* configuration union */
typedef struct my_config MyConfig;
struct my_config
{
   LdapUtilsConfig   common;
   int               scope;
   const char      * basedn;
   const char      * filter;
};


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////

// main statement
int main PARAMS((int argc, char * argv[]));

// parses configuration
MyConfig * my_config PARAMS((int argc, char * argv[]));

// frees local config
void my_free_config PARAMS((MyConfig * cnf));


/////////////////
//             //
//  Functions  //
//             //
/////////////////

/// prints program usage and exits
void ldaputils_usage(void)
{
   printf(_("Usage: %s [options] [filter [attributes...]]\n"), PROGRAM_NAME);
   ldaputils_search_usage();
   ldaputils_common_usage();
   printf(_("Report bugs to <%s>.\n"), PACKAGE_BUGREPORT);
   return;
}


/// main statement
/// @param[in] argc   number of arguments
/// @param[in] argv   array of arguments
int main(int argc, char * argv[])
{
   MyConfig * cnf;

#ifdef HAVE_GETTEXT
   setlocale (LC_ALL, ""); 
   bindtextdomain (PACKAGE, LOCALEDIR); 
   textdomain (PACKAGE);
#endif

   if (!(cnf = my_config(argc, argv)))
      return(1);

   /* generates new config file */
   //if (my_gen_config(cnf))
   //  return(1);

   /* prints message */
   //my_write_config(cnf);

   /* frees memory */
   ldaputils_common_config_free((LdapUtilsConfig *)cnf);
   free(cnf);

   /* ends function */
   return(0);
}


/// parses configuration
/// @param[in] argc   number of arguments
/// @param[in] argv   array of arguments
MyConfig * my_config(int argc, char * argv[])
{
   int        c;
   int        option_index;
   //char     * ptr;
   MyConfig * cnf;
if (!(argc))
   printf("%s blah\n", argv[0]);
   
   static char   short_options[] = MY_COMMON_OPTIONS "f:l";
   static struct option long_options[] =
   {
      {"help",          no_argument, 0, 'u'},
      {"verbose",       no_argument, 0, 'v'},
      {"version",       no_argument, 0, 'V'},
      {NULL,            0,           0, 0  }
   };
   
   option_index = 0;
   
   // allocates memory for configuration
   if (!(cnf = (MyConfig *) malloc(sizeof(MyConfig))))
   {
      fprintf(stderr, _("%s: out of virtual memory\n"), PROGRAM_NAME);
      return(NULL);
   };
   memset(cnf, 0, sizeof(MyConfig));
   
   // loops through args
   while((c = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1)
   {
      switch(c)
      {
         case -1:       /* no more arguments */
         case 0:        /* long options toggles */
            break;
         default:
            if (ldaputils_common_cmdargs((LdapUtilsConfig *)cnf, (int)c, optarg))
            {
               my_free_config(cnf);
               free(cnf);
               return(NULL);
            };
         break;
      };
   };

   return(cnf);
}


/// frees local config
/// @param[in] cnf  reference to configuration struct
void my_free_config(MyConfig * cnf)
{
   free(cnf);
   return;
}


/* end of source file */
