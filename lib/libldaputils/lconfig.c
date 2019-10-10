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
 *
 *  @BINDLE_BINARIES_BSD_LICENSE_END@
 */
/**
 *  @file src/ldaputils_config.c contains shared functions and variables
 */
#define _LIB_LIBLDAPUTILS_LCONFIG_C 1
#include "lconfig.h"

///////////////
//           //
//  Headers  //
//           //
///////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Headers
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <stdlib.h>
#include <fcntl.h>
#include <assert.h>

#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif
#ifdef HAVE_SGTTY_H
#include <sgtty.h>
#endif

#include "lpasswd.h"


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Functions
#endif

/// parses LDAP command line arguments
/// @param[in] lud
/// @param[in] c
/// @param[in] arg
int ldaputils_cmdargs(LDAPUtils * lud, int c, const char * arg)
{
   int     rc;
   int     valint;
   char  * endptr;

   /* checks argument */
   switch(c)
   {
      case -1:       /* no more arguments */
      case 0:        /* long options toggles */
      return(c);
         
      // Common Options
      case '9':
      ldaputils_usage();
      return(-2);

      case 'c':
      lud->continuous++;
      return(0);

      case 'd':
      valint = (int)strtoll(arg, &endptr, 0);
      if ( (optarg == endptr) || (endptr[0] != '\0') )
      {
          fprintf(stderr, "%s: debug value\n", lud->prog_name);
          return(1);
      };
      if ((rc = ldap_set_option(lud->ld, LDAP_OPT_DEBUG_LEVEL, &valint)) != LDAP_SUCCESS)
      {
         fprintf(stderr, "%s: ldap_set_option(LDAP_OPT_DEBUG_LEVEL): %s\n", lud->prog_name, ldap_err2string(rc));
         return(1);
      };
      return(0);

      case 'D':
      lud->binddn = arg;
      return(0);

      case 'h':
      if ((rc = ldap_set_option(lud->ld, LDAP_OPT_HOST_NAME, arg)) != LDAP_SUCCESS)
      {
         fprintf(stderr, "%s: ldap_set_option(LDAP_OPT_HOST_NAME): %s\n", lud->prog_name, ldap_err2string(rc));
         return(1);
      };
      return(0);

      case 'H':
      if ((rc = ldap_set_option(lud->ld, LDAP_OPT_URI, arg)) != LDAP_SUCCESS)
      {
         fprintf(stderr, "%s: ldap_set_option(LDAP_OPT_URI): %s\n", lud->prog_name, ldap_err2string(rc));
         return(1);
      };
      return(0);

      case 'n':
      lud->dryrun++;
      return(0);

      case 'P':
      valint = atoi(arg);
      if ((rc = ldap_set_option(lud->ld, LDAP_OPT_PROTOCOL_VERSION, &valint)) != LDAP_SUCCESS)
         fprintf(stderr, "%s: ldap_set_option(LDAP_OPT_PROTOCOL_VERSION): %s\n", lud->prog_name, ldap_err2string(rc));
      return(0);

      case 'v':
      lud->verbose++;
      return(0);

      case 'V':
      ldaputils_version(lud->prog_name);
      return(-2);

      case 'w':
      if ( ((lud->passfile)) || ((lud->want_pass)) )
      {
         fprintf(stderr, "%s: -%c incompatible with -w\n",lud->prog_name, ((lud->passfile)) ? 'y' : 'W');
         return(1);
      };
      if ((lud->passwd.bv_val))
         free(lud->passwd.bv_val);
      if ((lud->passwd.bv_val = strdup(arg)) == NULL)
      {
         fprintf(stderr, "%s: out of virtual memory\n", lud->prog_name);
         return(1);
      };
      lud->passwd.bv_len = strlen(arg);
      return(0);

      case 'W':
      if ( ((lud->passfile)) || ((lud->passwd.bv_val)) )
      {
         fprintf(stderr, "%s: -%c incompatible with -W\n",lud->prog_name, ((lud->passfile)) ? 'y' : 'w');
         return(1);
      };
      lud->want_pass++;
      return(0);

      case 'x':
      lud->sasl_mech = (const char *)LDAP_SASL_SIMPLE;
      return(0);

      case 'y':
      if ( ((lud->want_pass)) || ((lud->passwd.bv_val)) )
      {
         fprintf(stderr, "%s: -%c incompatible with -y\n",lud->prog_name, ((lud->want_pass)) ? 'W' : 'w');
         return(1);
      };
      lud->passfile = arg;
      return(0);

      case 'Y':
      lud->sasl_mech = arg;
      return(0);

      case 'Z':
      lud->tls_req++;
      return(0);

      // search options
      case 'b':
      if ((rc = ldap_set_option(lud->ld, LDAP_OPT_DEFBASE, arg)) != LDAP_SUCCESS)
      {
         fprintf(stderr, "%s: ldap_set_option(LDAP_OPT_DEFBASE): %s\n", lud->prog_name, ldap_err2string(rc));
         return(1);
      };
      return(0);

      case 'l':
      valint = atoi(arg);
      if ((rc = ldap_set_option(lud->ld, LDAP_OPT_TIMELIMIT, &valint)) != LDAP_SUCCESS)
      {
         fprintf(stderr, "%s: ldap_set_option(LDAP_OPT_TIMELIMIT): %s\n", lud->prog_name, ldap_err2string(rc));
         return(1);
      };
      return(0);

      case 'L': // allows for compatibility with ldapsearch
      return(0);

      case 's':
      if (!(strcasecmp(arg, "sub")))
         lud->scope = LDAP_SCOPE_SUBTREE;
      else if (!(strcasecmp(arg, "one")))
         lud->scope = LDAP_SCOPE_SUBTREE;
      else if (!(strcasecmp(arg, "base")))
         lud->scope = LDAP_SCOPE_BASE;
      else if (!(strcasecmp(arg, "children")))
         lud->scope = LDAP_SCOPE_CHILDREN;
      else
      {
         fprintf(stderr, "%s: scope should be base, one, sub, or children\n", lud->prog_name);
         return(1);
      };
      return(0);

      case 'S':
      lud->sortattr = arg;
      return(0);

      case 'z':
      valint = atoi(arg);
      if ((rc = ldap_set_option(lud->ld, LDAP_OPT_SIZELIMIT, &valint)) != LDAP_SUCCESS)
      {
         fprintf(stderr, "%s: ldap_set_option(LDAP_OPT_SIZELIMIT): %s\n", lud->prog_name, ldap_err2string(rc));
         return(1);
      };
      return(0);

      default:
      return(c);
   };

   /* ends function */
   return(c);
}


/// prints configuration to stdout
/// @param[in] lud  reference to common configuration struct
void ldaputils_config_print(LDAPUtils * lud)
{
   int i;
   char str[256];

   printf("Common Options:\n");
   printf("   -c: continuous:   %i\n", lud->continuous);
   printf("   -D: bind DN:      %s\n", ldaputils_config_print_str(lud->binddn));
   //printf("   -h: LDAP host:    %s\n", ldaputils_config_print_str(lud->host));
   printf("   -H: LDAP URI:     %s\n", ldaputils_print_option_str(lud, LDAP_OPT_URI, str, sizeof(str)));
   printf("   -n: dry run:      %i\n", lud->dryrun);
   //printf("   -P: LDAP port:    %i\n", lud->port);
   //printf("   -P: LDAP version: %i\n", lud->version);
   printf("   -v: verbose mode: %i\n", lud->verbose);
   printf("   -x: sasl mech:    %s\n", ldaputils_config_print_str(lud->sasl_mech));
   printf("   -w: bind pass:    %s\n", ldaputils_config_print_str(lud->passwd.bv_val));
   printf("   -Z: require TLS:  %i\n", lud->tls_req);
   printf("Search Options:\n");
   //printf("   -b: basedn:       %s\n", ldaputils_config_print_str(lud->basedn));
   printf("   -l: time limit:   %i\n", -1);
   printf("   -s: scope:        %i\n", lud->scope);
   printf("   -S: sort by:      %s\n", ldaputils_config_print_str(lud->sortattr));
   printf("   -z: size limit:   %i\n", -1);
   printf("       filter:       %s\n", lud->filter);
   if ((lud->attrs))
   {
      printf("       attributes:   %s\n", lud->attrs[0]);
      for(i = 1; lud->attrs[i]; i++)
         printf("                     %s\n", lud->attrs[i]);
   }
   else
   {
      printf("       attributes:   n/a\n");
   };
   return;
}


/// prints string to stdout
char * ldaputils_print_option_str(LDAPUtils * lud, int option, char * str, size_t size)
{
   char * val;

   val = NULL;
   ldap_get_option(lud->ld, option, &str);
   if ((str))
   {
      snprintf(str, size, "%s", val);
      ldap_memfree(str);
   }
   else
   {
      snprintf(str, size, "(null)");
   };

   return(str);
}


/// prints string to stdout
const char * ldaputils_config_print_str(const char * str)
{
   if (str)
      return(str);
   return("(null)");
}


const char * ldaputils_get_prog_name(LDAPUtils * lud)
{
   assert(lud != NULL);
   return(lud->prog_name);
}


LDAP * ldaputils_get_ld(LDAPUtils * lud)
{
   assert(lud != NULL);
   return(lud->ld);
}


const char * const * ldaputils_get_attribute_list(LDAPUtils * lud)
{
   assert(lud != NULL);
   return((const char * const *)lud->attrs);
}


/// displays usage for common options
/// @param[in] short_options  list of usage options
void ldaputils_usage_common(const char * short_options)
{
   unsigned pos;
   // TRANSLATORS: The following strings provide usage for common command
   // line arguments. Usage for program specific arguments is provided in
   // anothoer section. These strings are displayed if the program is
   // passed `--help' on the command line.
   printf("Common options:\n");
   for(pos = 0; pos < strlen(short_options); pos++)
   {
      switch(short_options[pos])
      {
         case 'c': printf("  -c                continuous operation mode (do not stop on errors)\n"); break;
         case 'd': printf("  -d level          set LDAP debug level to `level'\n"); break;
         case 'D': printf("  -D binddn         bind DN\n"); break;
         //case 'h': printf("  -h host           LDAP server\n"); break;
         case 'H': printf("  -H URI            LDAP Uniform Resource Identifier(s)\n"); break;
         case 'n': printf("  -n                show what would be done but don't actually do it\n"); break;
         //case 'p': printf("  -p port           port on LDAP server\n"); break;
         case 'v': printf("  -v, --verbose     run in verbose mode\n"); break;
         case 'V': printf("  -V, --version     print version number and exit\n"); break;
         case 'w': printf("  -w, passwd        bind password (for simple authentication)\n"); break;
         case 'W': printf("  -W                prompt for bind password\n"); break;
         case 'x': printf("  -x                simple authentication\n"); break;
         case 'y': printf("  -y file           read password from file\n"); break;
         case 'Y': printf("  -Y mech           SASL mechanism\n"); break;
         case 'Z': printf("  -Z[Z]             issue StartTLS, multiple options require TLS to be successful\n"); break;
         case '9': printf("  --help            print this help and exit\n"); break;
         default: break;
      };
   };
   return;
}


/// displays search usage for search options
/// @param[in] short_options  list of usage options
void ldaputils_usage_search(const char * short_options)
{
   unsigned pos;
   // TRANSLATORS: The following strings provide usage for search command
   // line arguments. Usage for program specific arguments is provided in
   // anothoer section. These strings are displayed if the program is
   // passed `--help' on the command line.
   printf("Search options:\n");
   for(pos = 0; pos < strlen(short_options); pos++)
   {
      switch(short_options[pos])
      {
         case 'b': printf("  -b basedn         base dn for search\n"); break;
         case 'l': printf("  -l limit          time limit (in seconds) for search\n"); break;
         case 's': printf("  -s scope          one of base, one, or sub (search scope)\n"); break;
         case 'S': printf("  -S attr           sort results by attribute `attr'\n"); break;
         case 'z': printf("  -z limit          size limit for search\n"); break;
         default: break;
      };
   };
   return;
}


/// displays usage
void ldaputils_version(const char * prog_name)
{
   // TRANSLATORS: The following strings provide version and copyright
   // information if the program is passed --version on the command line.
   // The three strings referenced are: PROGRAM_NAME, PACKAGE_NAME,
   // PACKAGE_VERSION.
   printf("%s (%s) %s\n"
         "Copyright (C) 2008 David M. Syzdek.\n"
         "This is free software; see the source for copying conditions.  There is NO\n"
         "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n"
      , prog_name, PACKAGE_NAME, PACKAGE_VERSION
   );
   return;
}

/* end of source file */
