/*
 *  LDAP Utilities
 *  Copyright (c) 2008 David M. Syzdek <david@syzdek.net>.
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

#include "ldaputils_config.h"
#include "ldaputils_ldap.h"

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
   char              output[LDAPUTILS_OPT_LEN];
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
int my_config PARAMS((int argc, char * argv[], MyConfig ** cnfp));


/////////////////
//             //
//  Functions  //
//             //
/////////////////

/// prints program usage and exits
void ldaputils_usage(void)
{
   printf(_("Usage: %s [options] filter attributes...\n"), PROGRAM_NAME);
   ldaputils_usage_search();
   ldaputils_usage_common();
   printf(_("\nReport bugs to <%s>.\n"), PACKAGE_BUGREPORT);
   return;
}


/// main statement
/// @param[in] argc   number of arguments
/// @param[in] argv   array of arguments
int main(int argc, char * argv[])
{
   int           rc;
   LDAP        * ld;
   MyConfig    * cnf;
   LDAPMessage * res;
   LDAPMessage * entry;

#ifdef HAVE_GETTEXT
   setlocale (LC_ALL, ""); 
   bindtextdomain (PACKAGE, LOCALEDIR); 
   textdomain (PACKAGE);
#endif

   if ((my_config(argc, argv, &cnf)))
      return(1);
   if (!(cnf))
      return(0);
   
   if (!(ld = ldaputils_initialize((LdapUtilsConfig *)cnf)))
   {
      ldaputils_config_free((LdapUtilsConfig *)cnf);
      free(cnf);
      return(1);
   };

   if ((ldaputils_search(ld, (LdapUtilsConfig *)cnf)))
   {
      ldaputils_config_free((LdapUtilsConfig *)cnf);
      free(cnf);
      return(1);
   };
   
   while((rc = ldap_result(ld, LDAP_RES_ANY, LDAP_MSG_ONE, NULL, &res)) > 0)
   {
      entry = ldap_first_entry(ld, res);
      printf("dn: %s\n", ldap_get_dn(ld, entry));
   };
   
   ldap_unbind_ext_s(ld, NULL, NULL);
   ldaputils_config_free((LdapUtilsConfig *)cnf);
   free(cnf);

   return(0);
}


/// parses configuration
/// @param[in] argc   number of arguments
/// @param[in] argv   array of arguments
/// @param[in] cnfp   reference to configuration pointer
int my_config(int argc, char * argv[], MyConfig ** cnfp)
{
   int        c;
   int        option_index;
   MyConfig * cnf;
   
   static char   short_options[] = LDAPUTILS_OPTIONS_COMMON LDAPUTILS_OPTIONS_SEARCH "o:";
   static struct option long_options[] =
   {
      {_("help"),          no_argument, 0, '9'},
      {_("verbose"),       no_argument, 0, 'v'},
      {_("version"),       no_argument, 0, 'V'},
      {NULL,               0,           0, 0  }
   };
   
   option_index = 0;
   *cnfp        = NULL;
   
   if (!(cnf = (MyConfig *) malloc(sizeof(MyConfig))))
   {
      fprintf(stderr, _("%s: out of virtual memory\n"), PROGRAM_NAME);
      return(1);
   };
   memset(cnf, 0, sizeof(MyConfig));
   
   while((c = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1)
   {
      switch(ldaputils_cmdargs((LdapUtilsConfig *) cnf, c, optarg))
      {
         case -2: return(0); // shared option exit without error
         case -1: break;     // no more arguments 
         case 0:  break;     // long options toggles
         case 1:  return(1); // shared option error
         case '?':           // argument error
            fprintf(stderr, _("Try `%s --help' for more information.\n"), PROGRAM_NAME);
            return(1);
         default:
            fprintf(stderr, _("%s: unrecognized option `--%c'\n"), PROGRAM_NAME, c);
            fprintf(stderr, _("Try `%s --help' for more information.\n"), PROGRAM_NAME);
            return(1);
      };
   };
   
   if (argc < (optind+2))
   {
      fprintf(stderr, _("%s: missing required arguments\n"), PROGRAM_NAME);
      fprintf(stderr, _("Try `%s --help' for more information.\n"), PROGRAM_NAME);
      return(1);
   };
   
   cnf->filter = argv[optind];

   // configures LDAP attributes to return in results
   if (!(cnf->common.attrs = (char **) malloc(sizeof(char *) * (argc-optind))))
   {
      fprintf(stderr, _("%s: out of virtual memory\n"), PROGRAM_NAME);
      return(1);
   };
   for(c = 0; c < (argc-optind-1); c++)
      cnf->common.attrs[c] = argv[optind+1+c];
   cnf->common.attrs[c] = '\0';
   
   *cnfp = cnf;

   return(0);
}


/* end of source file */
