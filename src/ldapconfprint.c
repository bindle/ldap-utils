/*
 *  LDAP Utilities
 *  Copyright (C) 2012 Bindle Binaries <syzdek@bindlebinaries.com>.
 *
 *  @BINDLE_BINARIES_BSD_LICENSE_START@
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are
 *  met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Bindle Binaries nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 *  IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 *  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 *  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL BINDLE BINARIES BE LIABLE FOR
 *  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 *  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 *  SUCH DAMAGE.
 *
 *  @BINDLE_BINARIES_BSD_LICENSE_END@
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
