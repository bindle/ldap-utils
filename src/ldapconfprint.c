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

///////////////////
//               //
//  Definitions  //
//               //
///////////////////

#ifndef PROGRAM_NAME
#define PROGRAM_NAME "ldapconfprint"
#endif

#define MY_SHORT_OPTIONS LDAPUTILS_OPTIONS_COMMON LDAPUTILS_OPTIONS_SEARCH "o:"


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////

// main statement
int main PARAMS((int argc, char * argv[]));

// parses configuration
int my_config PARAMS((int argc, char * argv[], LdapUtilsConfig ** cnfp));


/////////////////
//             //
//  Functions  //
//             //
/////////////////

/// prints program usage and exits
void ldaputils_usage(void)
{
   printf(_("Usage: %s [options] filter attributes...\n"), PROGRAM_NAME);
   ldaputils_usage_search(MY_SHORT_OPTIONS);
   ldaputils_usage_common(MY_SHORT_OPTIONS);
   printf(_("\nReport bugs to <%s>.\n"), PACKAGE_BUGREPORT);
   return;
}


/// main statement
/// @param[in] argc   number of arguments
/// @param[in] argv   array of arguments
int main(int argc, char * argv[])
{
   LdapUtilsConfig * cnf;

#ifdef HAVE_GETTEXT
   setlocale (LC_ALL, ""); 
   bindtextdomain (PACKAGE, LOCALEDIR); 
   textdomain (PACKAGE);
#endif

   if ((my_config(argc, argv, &cnf)))
      return(1);
   if (!(cnf))
      return(0);

   ldaputils_config_print(cnf);

   ldaputils_config_free((LdapUtilsConfig *)cnf);

   return(0);
}


/// parses configuration
/// @param[in] argc   number of arguments
/// @param[in] argv   array of arguments
int my_config(int argc, char * argv[], LdapUtilsConfig ** cnfp)
{ 
   int               c;
   int               option_index;
   LdapUtilsConfig * cnf;
   
   static char   short_options[] = MY_SHORT_OPTIONS;
   static struct option long_options[] =
   {
      {"help",          no_argument, 0, '9'},
      {"verbose",       no_argument, 0, 'v'},
      {"version",       no_argument, 0, 'V'},
      {NULL,            0,           0, 0  }
   };
   
   option_index = 0;
   *cnfp        = NULL;
   
   // allocates memory for configuration
   if (!(cnf = (LdapUtilsConfig *) malloc(sizeof(LdapUtilsConfig))))
   {
      fprintf(stderr, _("%s: out of virtual memory\n"), PROGRAM_NAME);
      return(1);
   };
   memset(cnf, 0, sizeof(LdapUtilsConfig));
   
   ldaputils_config_init((LdapUtilsConfig *) cnf);
   
   // loops through args
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
   if (!(cnf->attrs = (char **) malloc(sizeof(char *) * (argc-optind))))
   {
      fprintf(stderr, _("%s: out of virtual memory\n"), PROGRAM_NAME);
      return(1);
   };
   for(c = 0; c < (argc-optind-1); c++)
      cnf->attrs[c] = argv[optind+1+c];
   cnf->attrs[c] = NULL;   
   
   *cnfp = cnf;

   return(0);
}

/* end of source file */
