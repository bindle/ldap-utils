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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <stdlib.h>
#include <fcntl.h>

#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif


/////////////////
//             //
//  Functions  //
//             //
/////////////////

/// removes newlines and carriage returns
/// @param[in] str
char * ldaputils_chomp(char * str)
{
   char * idx;

   if (!(str))
      return(NULL);

   if ((idx = strchr(str, '\n')))
      idx[0] = '\0';
   if ((idx = strchr(str, '\r')))
      idx[0] = '\0';

   return(str);
}


/// parses LDAP command line arguments
/// @param[in] cnf
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
      lud->host = arg;
      return(0);

      case 'H':
      if ((rc = ldap_set_option(lud->ld, LDAP_OPT_URI, &arg)) != LDAP_SUCCESS)
      {
         fprintf(stderr, "%s: ldap_set_option(LDAP_OPT_URI): %s\n", lud->prog_name, ldap_err2string(rc));
         return(1);
      };
      return(0);

      case 'n':
      lud->dryrun++;
      return(0);

      case 'p':
      lud->port = atoi(arg);
      return(0);

      case 'P':
      lud->version = atoi(arg);
      return(0);

      case 'v':
      lud->verbose++;
      return(0);

      case 'V':
      ldaputils_version(lud->prog_name);
      return(-2);

      case 'w':
      strncpy(lud->bindpw, arg, LDAPUTILS_OPT_LEN);
      return(0);

      case 'W':
      lud->passfile = "-";
      return(0);

      case 'y':
      lud->passfile = arg;
      return(0);

      // search options
      case 'b':
      lud->basedn = arg;
      return(0);

      case 'l':
      valint = atoi(arg);
      if ((rc = ldap_set_option(lud->ld, LDAP_OPT_TIMELIMIT, &valint)) != LDAP_SUCCESS)
      {
         fprintf(stderr, "%s: ldap_set_option(LDAP_OPT_TIMELIMIT): %s\n", lud->prog_name, ldap_err2string(rc));
         return(1);
      };
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
         fprintf(stderr, "%s: scope should be base, one, or sub\n", lud->prog_name);
         return(1);
      };
      return(0);

      case 'S':
      lud->sortattr = arg;
      return(0);

      case 'Z':
      lud->tls_req++;
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


/// frees common config
/// @param[in] cnf
void ldaputils_config_free(LDAPUtils * lud)
{
   int    i;

   if (!(lud))
      return;

   if ((lud->ld))
      ldap_unbind(lud->ld);

   if ((lud->attrs))
   {
      for(i = 0; ((lud->attrs[i])); i++)
         free(lud->attrs[i]);
      free(lud->attrs);
   };

   free(lud);

   return;
}


/// prints configuration to stdout
/// @param[in] cnf  reference to common configuration struct
void ldaputils_config_print(LDAPUtils * lud)
{
   int i;
   printf("Common Options:\n");
   printf("   -c: continuous:   %i\n", lud->continuous);
   printf("   -D: bind DN:      %s\n", ldaputils_config_print_str(lud->binddn));
   printf("   -h: LDAP host:    %s\n", ldaputils_config_print_str(lud->host));
   printf("   -H: LDAP URI:     %s\n", "n/a");
   printf("   -n: dry run:      %i\n", lud->dryrun);
   printf("   -P: LDAP port:    %i\n", lud->port);
   printf("   -P: LDAP version: %i\n", lud->version);
   printf("   -v: verbose mode: %i\n", lud->verbose);
   printf("   -w: bind pass:    %s\n", ldaputils_config_print_str(lud->bindpw));
   printf("Search Options:\n");
   printf("   -b: basedn:       %s\n", ldaputils_config_print_str(lud->basedn));
   printf("   -l: time limit:   %i\n", -1);
   printf("   -s: scope:        %i\n", lud->scope);
   printf("   -S: sort by:      %s\n", ldaputils_config_print_str(lud->sortattr));
   printf("   -z: size limit:   %i\n", -1);
   printf("       filter:       %s\n", lud->filter);
   printf("       attributes:\n");
   for(i = 0; lud->attrs[i]; i++)
      printf("                     %s\n", lud->attrs[i]);
   return;
}


/// prints string to stdout
const char * ldaputils_config_print_str(const char * str)
{
   if (str)
      return(str);
   return("(null)");
}


/// getpass() replacement -- SUSV 2 deprecated getpass()
/// @param[in] prompt
/// @param[in] buff
/// @param[in] len
int ldaputils_getpass(const char * prompt, char * buff, size_t size)
{
   /* declares local vars */
   ssize_t        len;
#ifdef HAVE_TERMIOS_H
   struct termios old;
   struct termios new;
#endif

   /* clears memory and flusses buffer */
   memset(buff, 0, size);

   /* prompts for password */
   if (prompt)
      fprintf(stderr, "%s", prompt);
   fflush(stdout);

   /* disables ECHO */
#ifdef HAVE_TERMIOS_H
   if(tcgetattr(STDIN_FILENO, &old) == -1)
      return(1);
   new          = old;
   new.c_lflag &= ~ECHO;
   if(tcsetattr(STDIN_FILENO, TCSAFLUSH, &new))
      return(1);
#endif

   /* reads buffer */
   if ((len = read(STDIN_FILENO, buff, size-1)) == -1)
      return(1);
   buff[len] = '\0';
   ldaputils_chomp(buff);
   
   /* restores previous terminal */
#ifdef HAVE_TERMIOS_H
   if(tcsetattr(STDIN_FILENO, TCSAFLUSH, &old))
      return(1);
#endif

   /* prints newline */
   printf("\n");

   /* ends function */
   return(0);
}


/// retrieves password from file
/// @param[in] file  file containing the password
/// @param[in] buff  pointer to buffer for password
/// @param[in] len   length of the buffer
int ldaputils_passfile(LDAPUtils * lud, const char * file, char * buff,
   size_t size)
{
   int         fd;
   ssize_t     len;
   struct stat sb;

   if (!(strcmp("-", file)))
      return(ldaputils_getpass("Enter LDAP Password: ", buff, size));
   
   if ((stat(file, &sb)) == -1)
   {
      fprintf(stderr, "%s: %s: %s\n", lud->prog_name, file, strerror(errno));
      return(1);
   };
   if (sb.st_mode & 0066)
      // TRANSLATORS: The following string provides an error message if the
      // file which contains the password has insecure file permissions. The
      // string arguments are the name of the program and the name of the file.
      fprintf(stderr, "%s: Password file %s is publicly readable/writeable\n", lud->prog_name, file);
   
   if ((fd = open(file, O_RDONLY)) == -1)
   {
      fprintf(stderr, "%s: %s: %s\n", lud->prog_name, file, strerror(errno));
      return(1);
   };
   
   if ((len = read(fd, buff,size-1)) == -1)
   {
      fprintf(stderr, "%s: %s: %s\n", lud->prog_name, file, strerror(errno));
      return(1);
   };
   buff[len] = '\0';
   
   close(fd);
   
   return(0);
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
         case 'h': printf("  -h host           LDAP server\n"); break;
         case 'H': printf("  -H URI            LDAP Uniform Resource Identifier(s)\n"); break;
         case 'n': printf("  -n                show what would be done but don't actually do it\n"); break;
         case 'p': printf("  -p port           port on LDAP server\n"); break;
         case 'v': printf("  -v, --verbose     run in verbose mode\n"); break;
         case 'V': printf("  -V, --version     print version number and exit\n"); break;
         case 'w': printf("  -w, passwd        bind password (for simple authentication)\n"); break;
         case 'W': printf("  -W                prompt for bind password\n"); break;
         case 'y': printf("  -y file           read password from file\n"); break;
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
