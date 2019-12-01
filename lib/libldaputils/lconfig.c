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
 *  @file lib/libldaputils/lconfig.c contains configuration functions and variables
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


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Prototypes
#endif

// prints string to stdout
const char * ldaputils_config_print_str(const char * str);
void ldaputils_param_print(const char * key, const char * val);
void ldaputils_param_int(LDAPUtils * lud, const char * key, int ival);
void ldaputils_param_option_str(LDAPUtils * lud, const char * key, int option);
void ldaputils_param_option_strlist(LDAPUtils * lud, const char * key, int option);
void ldaputils_param_option_int(LDAPUtils * lud, const char * key, int option);
void ldaputils_param_option_time(LDAPUtils * lud, const char * key, int option);
void ldaputils_param_option_bool(LDAPUtils * lud, const char * key, int option);


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Functions
#endif

/// parses LDAP command line arguments
/// @param[in]  lud           reference to LDAP utiles descriptor
/// @param[in]  c             getopt option
/// @param[in]  arg           getopt argument
///
/// @return    If successfull, returns 0.  If an unknown option, returns the
///            option value for processing by the program.
int ldaputils_getopt(LDAPUtils * lud, int c, const char * arg)
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
      ldaputils_usage();
      return(-2);

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
      lud->silent++;
      return(0);

      case 's':
      if (!(strcasecmp(arg, "sub")))
         lud->scope = LDAP_SCOPE_SUBTREE;
      else if (!(strcasecmp(arg, "one")))
         lud->scope = LDAP_SCOPE_ONE;
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
      break;
   };

   /* ends function */
   return(c);
}


/// prints configuration to stdout
/// @param[in] lud  reference to common configuration struct
void ldaputils_params(LDAPUtils * lud)
{
   int          i;
   const char * str;

   printf("Miscellaneous:\n");
   ldaputils_param_int(lud, "Continuous:",              lud->continuous);
   ldaputils_param_int(lud, "Dry Run:",                 lud->dryrun);
   ldaputils_param_int(lud, "Verbose:",                 lud->verbose);
   printf("\n");

   printf("LDAP Host:\n");
   ldaputils_param_option_str(lud, "URI:",              LDAP_OPT_URI);
   ldaputils_param_option_str(lud, "Hostname:",         LDAP_OPT_HOST_NAME);
   ldaputils_param_option_int(lud, "Protocol Version:", LDAP_OPT_PROTOCOL_VERSION);
   ldaputils_param_option_int(lud, "Debug Level:",      LDAP_OPT_DEBUG_LEVEL);
   ldaputils_param_option_time(lud, "Network Timeout:", LDAP_OPT_NETWORK_TIMEOUT);
   ldaputils_param_option_bool(lud,  "Restart:",        LDAP_OPT_RESTART);
   ldaputils_param_print(          "Bind DN:",             lud->binddn);
   printf("\n");

   printf("LDAP TCP Options:\n");
   ldaputils_param_option_int(lud, "Keepalive Idle:",    LDAP_OPT_X_KEEPALIVE_IDLE);
   ldaputils_param_option_int(lud, "Keepalive Probes:",  LDAP_OPT_X_KEEPALIVE_PROBES);
   ldaputils_param_option_int(lud, "Keepalive Interval:",  LDAP_OPT_X_KEEPALIVE_INTERVAL);
   printf("\n");

   printf("LDAP TLS Options:\n");
   switch (lud->tls_req)
   {
      case 0:  str = "none";    break;
      case 1:  str = "try";     break;
      case 2:  str = "require"; break;
      default: str = "unknown"; break;
   };
   ldaputils_param_print(          "TLS:",             str);
   ldaputils_param_option_int(lud, "TLS Minimum Version:",           LDAP_OPT_X_TLS_PROTOCOL_MIN);
   ldaputils_param_option_str(lud, "TLS CA Certificates Directory:", LDAP_OPT_X_TLS_CACERTDIR);
   ldaputils_param_option_str(lud, "TLS CA Certificate:",            LDAP_OPT_X_TLS_CACERTFILE);
   if (ldap_get_option(lud->ld, LDAP_OPT_X_TLS_REQUIRE_CERT, &i) == LDAP_SUCCESS)
   {
      switch(i)
      {
         case LDAP_OPT_X_TLS_NEVER:  str = "never"; break;
         case LDAP_OPT_X_TLS_HARD:   str = "hard"; break;
         case LDAP_OPT_X_TLS_DEMAND: str = "demand"; break;
         case LDAP_OPT_X_TLS_ALLOW:  str = "allow"; break;
         case LDAP_OPT_X_TLS_TRY:    str = "try"; break;
         default:                    str = "unknown"; break;
      };
      ldaputils_param_print(       "TLS Peer Check:",     str);
   };
   ldaputils_param_option_str(lud, "TLS DH File:",                   LDAP_OPT_X_TLS_DHFILE);
   ldaputils_param_option_str(lud, "TLS Key File:",              LDAP_OPT_X_TLS_KEYFILE);
   ldaputils_param_option_str(lud, "TLS Random File:",              LDAP_OPT_X_TLS_RANDOM_FILE);
   if (ldap_get_option(lud->ld, LDAP_OPT_X_TLS_CRLCHECK, &i) == LDAP_SUCCESS)
   {
      switch(i)
      {
         case LDAP_OPT_X_TLS_CRL_NONE: str = "none"; break;
         case LDAP_OPT_X_TLS_CRL_PEER: str = "peer"; break;
         case LDAP_OPT_X_TLS_CRL_ALL:  str = "all"; break;
         default:                      str = "unknown"; break;
      };
      ldaputils_param_print(       "TLS CRL Check:",     str);
   };
   ldaputils_param_option_str(lud, "CRL File:",                  LDAP_OPT_X_TLS_CRLFILE);
   ldaputils_param_option_str(lud, "Host Certificate:",          LDAP_OPT_X_TLS_CERTFILE);
   ldaputils_param_option_strlist(lud, "Cipher Suite:",          LDAP_OPT_X_TLS_CIPHER_SUITE);
   printf("\n");

   printf("SASL:\n");
   ldaputils_param_option_str(lud,  "SASL Username:",       LDAP_OPT_X_SASL_USERNAME);
   ldaputils_param_option_str(lud,  "SASL Realm:",          LDAP_OPT_X_SASL_REALM);
   ldaputils_param_option_str(lud,  "SASL Mechanism:",      LDAP_OPT_X_SASL_MECH);
   ldaputils_param_option_str(lud,  "SASL Authentication:", LDAP_OPT_X_SASL_AUTHCID);
   ldaputils_param_option_bool(lud, "SASL NOCANON Flag:",   LDAP_OPT_X_SASL_NOCANON);
   ldaputils_param_option_strlist(lud, "SASL Mechanism List:", LDAP_OPT_X_SASL_MECHLIST);
   printf("\n");

   printf("LDAP Operations:\n");
   ldaputils_param_option_time(lud, "Operation Timeout:", LDAP_OPT_TIMEOUT);
   printf("\n");

   printf("LDAP Search:\n");
   ldaputils_param_option_str(lud, "Base DN:",          LDAP_OPT_DEFBASE);
   ldaputils_param_print(          "Filter:",           lud->filter);
   switch(lud->scope)
   {
      case LDAP_SCOPE_BASE: str = "base"; break;
      case LDAP_SCOPE_ONE:  str = "one"; break;
      case LDAP_SCOPE_SUB:  str = "sub"; break;
      case LDAP_SCOPE_DEFAULT: str = "default"; break;
      default: str = "unknown"; break;
   };
   ldaputils_param_print(          "Search Scope:",     str);
   ldaputils_param_int(lud,        "Scope:",            lud->scope);
   ldaputils_param_print(          "Sort Attribute:",   lud->sortattr);
   ldaputils_param_option_int(lud, "Time Limit:",       LDAP_OPT_TIMELIMIT);
   ldaputils_param_option_int(lud, "Size Limit:",       LDAP_OPT_SIZELIMIT);
   ldaputils_param_option_int(lud, "Follow Referrals:", LDAP_OPT_REFERRALS);
   if (ldap_get_option(lud->ld, LDAP_OPT_DEREF, &i) == LDAP_SUCCESS)
   {
      switch(i)
      {
         case LDAP_DEREF_NEVER:      str = "never"; break;
         case LDAP_DEREF_SEARCHING:  str = "searching"; break;
         case LDAP_DEREF_FINDING:    str = "finding"; break;
         case LDAP_DEREF_ALWAYS:     str = "always"; break;
         default:                    str = "unknown"; break;
      };
      ldaputils_param_print(       "Dereferencing:",     str);
   };
   if ((lud->attrs))
   {
      ldaputils_param_print("Attributes:", lud->attrs[0]);
      for(i = 1; lud->attrs[i]; i++)
         ldaputils_param_print("", lud->attrs[i]);
   }
   else
   {
      ldaputils_param_print("Attributes:", "n/a");
   };
   printf("\n");

   return;
}


/// prints string to stdout
/// @param[in] key   name of value
/// @param[in] val   value of key
///
/// @see       ldaputils_param_int, ldaputils_param_option_bool
void ldaputils_param_print(const char * key, const char * val)
{
   if ((val))
      printf("   %-20s %s\n", key, val);
   return;
}


/// prints integer to stdout
/// @param[in] lud   reference to LDAP utilities struct
/// @param[in] key   name of value
/// @param[in] ival  value of key
///
/// @see       ldaputils_param_print, ldaputils_param_option_bool
void ldaputils_param_int(LDAPUtils * lud, const char * key, int ival)
{
   char val[16];

   assert(lud != NULL);

   ival = 0;
   snprintf(val, sizeof(val), "%i", ival);
   ldaputils_param_print(key, val);

   return;
}


/// prints boolean LDAP option to stdout
/// @param[in] lud      reference to LDAP utilities struct
/// @param[in] key      name of option
/// @param[in] option   LDAP option
///
/// @see       ldaputils_param_print, ldaputils_param_option_bool
void ldaputils_param_option_bool(LDAPUtils * lud, const char * key, int option)
{
   int  ival;

   assert(lud != NULL);

   ival = 0;
   ldap_get_option(lud->ld, option, &ival);
   if ((ival))
      ldaputils_param_print(key, "ON");
   else
      ldaputils_param_print(key, "OFF");

   return;
}


/// prints integer LDAP option to stdout
/// @param[in] lud      reference to LDAP utilities struct
/// @param[in] key      name of option
/// @param[in] option   LDAP option
///
/// @see       ldaputils_param_print, ldaputils_param_option_bool
void ldaputils_param_option_int(LDAPUtils * lud, const char * key, int option)
{
   int  ival;
   char val[16];

   assert(lud != NULL);

   ival = 0;
   ldap_get_option(lud->ld, option, &ival);
   snprintf(val, sizeof(val), "%i", ival);
   ldaputils_param_print(key, val);

   return;
}


/// prints string LDAP option to stdout
/// @param[in] lud      reference to LDAP utilities struct
/// @param[in] key      name of option
/// @param[in] option   LDAP option
///
/// @see       ldaputils_param_print, ldaputils_param_option_bool
void ldaputils_param_option_str(LDAPUtils * lud, const char * key, int option)
{
   char * val;

   assert(lud != NULL);

   val = NULL;
   ldap_get_option(lud->ld, option, &val);
   if ((val))
   {
      ldaputils_param_print(key, val);
      ldap_memfree(val);
   };

   return;
}


/// prints string list LDAP option to stdout
/// @param[in] lud      reference to LDAP utilities struct
/// @param[in] key      name of option
/// @param[in] option   LDAP option
///
/// @see       ldaputils_param_print, ldaputils_param_option_bool
void ldaputils_param_option_strlist(LDAPUtils * lud, const char * key, int option)
{
   int     i;
   char ** list;

   assert(lud != NULL);

   list = NULL;
   ldap_get_option(lud->ld, option, &list);
   if (!(list))
      return;

   ldaputils_param_print(key, list[0]);
   for(i = 1; ((list[i])); i++)
      ldaputils_param_print("", list[i]);

   return;
}


/// prints time LDAP option to stdout
/// @param[in] lud      reference to LDAP utilities struct
/// @param[in] key      name of option
/// @param[in] option   LDAP option
///
/// @see       ldaputils_param_print, ldaputils_param_option_bool
void ldaputils_param_option_time(LDAPUtils * lud, const char * key, int option)
{
   struct timeval * ival;
   char             val[64];

   assert(lud != NULL);

   ldap_get_option(lud->ld, option, &ival);
   snprintf(val, sizeof(val), "%li secs,  %i usecs", (long int) ival->tv_sec, (int) ival->tv_usec);
   ldap_memfree(ival);
   ldaputils_param_print(key, val);

   return;
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
         case 'c': printf("  -c                        continuous operation mode (do not stop on errors)\n"); break;
         case 'd': printf("  -d level                  set LDAP debug level to `level'\n"); break;
         case 'D': printf("  -D binddn                 bind DN\n"); break;
         case 'h': printf("  -h, --help                print this help and exit\n"); break;
         case 'H': printf("  -H URI                    LDAP Uniform Resource Identifier(s)\n"); break;
         case 'n': printf("  -n                        show what would be done but don't actually do it\n"); break;
         //case 'p': printf("  -p port                  port on LDAP server\n"); break;
         case 'v': printf("  -v, --verbose             run in verbose mode\n"); break;
         case 'V': printf("  -V, --version             print version number and exit\n"); break;
         case 'w': printf("  -w, passwd                bind password (for simple authentication)\n"); break;
         case 'W': printf("  -W                        prompt for bind password\n"); break;
         case 'x': printf("  -x                        simple authentication\n"); break;
         case 'y': printf("  -y file                   read password from file\n"); break;
         case 'Y': printf("  -Y mech                   SASL mechanism\n"); break;
         case 'Z': printf("  -Z[Z]                     issue StartTLS, multiple options require TLS\n"); break;
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
         case 'b': printf("  -b basedn                 base dn for search\n"); break;
         case 'l': printf("  -l limit                  time limit (in seconds) for search\n"); break;
         case 'L': printf("  -LL                       disables comments\n"); break;
         case 's': printf("  -s scope                  one of base, one, or sub (search scope)\n"); break;
         case 'S': printf("  -S attr                   sort results by attribute `attr'\n"); break;
         case 'z': printf("  -z limit                  size limit for search\n"); break;
         default: break;
      };
   };
   return;
}


/// displays usage
/// @param[in] prog_name   name of running program
///
/// @see       ldaputils_param_print, ldaputils_param_option_bool
void ldaputils_version(const char * prog_name)
{
   printf("%s (%s) %s\n", prog_name, PACKAGE_NAME, PACKAGE_VERSION);
   printf("%s\n", PACKAGE_COPYRIGHT);
   return;
}

/* end of source file */
