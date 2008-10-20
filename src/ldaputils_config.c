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
 *  @file src/ldaputils_config.c contains shared functions and variables
 */
#define _LDAP_UTILS_SRC_LDAPUTILS_CONFIG_C 1
#include "ldaputils_config.h"

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
#include <fcntl.h>

#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif

#include "ldaputils_config_opts.h"


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
int ldaputils_cmdargs(LdapUtilsConfig * cnf, int c, const char * arg)
{
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
         return(ldaputils_config_set_continuous(cnf));
      case 'C':
         return(ldaputils_config_set_referrals(cnf));
      case 'd':
         return(ldaputils_config_set_debug(cnf, arg));
      case 'D':
         return(ldaputils_config_set_binddn(cnf, arg));
      case 'h':
         return(ldaputils_config_set_host(cnf, arg));
      case 'H':
         return(ldaputils_config_set_uri(cnf, arg));
      case 'n':
         return(ldaputils_config_set_dryrun(cnf));
      case 'p':
         return(ldaputils_config_set_port(cnf, arg));
      case 'P':
         return(ldaputils_config_set_version(cnf, arg));
      case 'v':
         return(ldaputils_config_set_verbose(cnf));
      case 'V':
         ldaputils_version();
         return(-2);
      case 'w':
         return(ldaputils_config_set_bindpw(cnf, arg));
      case 'W':
         return(ldaputils_config_set_bindpw_prompt(cnf));
      case 'y':
         return(ldaputils_config_set_bindpw_file(cnf, arg));

      // search options
      case 'b':
         return(ldaputils_config_set_basedn(cnf, arg));
      case 'l':
         return(ldaputils_config_set_timelimit(cnf, arg));
      case 's':
         return(ldaputils_config_set_scope(cnf, arg));
      case 'S':
         return(ldaputils_config_set_sortattr(cnf, arg));
      case 'z':
         return(ldaputils_config_set_sizelimit(cnf, arg));

      default:
         return(c);
   };

   /* ends function */
   return(c);
}


/// frees common config
/// @param[in] cnf
void ldaputils_config_free(LdapUtilsConfig * cnf)
{
   if (!(cnf))
      return;

   if (cnf->ludp)
      ldap_free_urldesc(cnf->ludp);
   cnf->ludp = NULL;

   return;
}


/// initializes the common config
/// @param[in] cnf  reference to common configuration struct
void ldaputils_config_init(LdapUtilsConfig * cnf)
{
   memset(cnf, 0, sizeof(LdapUtilsConfig));
   cnf->referrals  = 0;
   cnf->scope      = LDAP_SCOPE_SUBTREE;
   return;
}


/// prints configuration to stdout
/// @param[in] cnf  reference to common configuration struct
void ldaputils_config_print(LdapUtilsConfig * cnf)
{
   int i;
   printf("Common Options:\n");
   printf("   -c: continuous:   %i\n", cnf->continuous);
   printf("   -C: referrals:    %i\n", cnf->referrals);
   printf("   -d: debug level:  %i\n", cnf->debug);
   printf("   -D: bind DN:      %s\n", ldaputils_config_print_str(cnf->binddn));
   printf("   -h: LDAP host:    %s\n", ldaputils_config_print_str(cnf->host));
   printf("   -H: LDAP URI:     %s\n", ldaputils_config_print_str(cnf->uri));
   printf("   -n: dry run:      %i\n", cnf->dryrun);
   printf("   -P: LDAP port:    %i\n", cnf->port);
   printf("   -P: LDAP version: %i\n", cnf->version);
   printf("   -v: verbose mode: %i\n", cnf->verbose);
   printf("   -w: bind pass:    %s\n", ldaputils_config_print_str(cnf->bindpw));
   printf("Search Options:\n");
   printf("   -b: basedn:       %s\n", ldaputils_config_print_str(cnf->basedn));
   printf("   -l: time limit:   %i\n", cnf->timelimit);
   printf("   -s: scope:        %i\n", cnf->scope);
   printf("   -S: sort by:      %s\n", ldaputils_config_print_str(cnf->sortattr));
   printf("   -z: size limit:   %i\n", cnf->sizelimit);
   printf("       filter:       %s\n", cnf->filter);
   printf("       attributes:\n");
   for(i = 0; cnf->attrs[i]; i++)
      printf("                     %s\n", cnf->attrs[i]);
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
      printf("%s", prompt);
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
int ldaputils_passfile(const char * file, char * buff, size_t size)
{
   int         fd;
   ssize_t     len;
   struct stat sb;
   
   if ((stat(file, &sb)) == -1)
   {
      fprintf(stderr, "%s: %s: %s\n", PROGRAM_NAME, file, strerror(errno));
      return(1);
   };
   if (sb.st_mode & 0066)
      // TRANSLATORS: The following string provides an error message if the
      // file which contains the password has insecure file permissions. The
      // string arguments are the name of the program and the name of the file.
      fprintf(stderr, _("%s: Password file %s is publicly readable/writeable\n"), PROGRAM_NAME, file);
   
   if ((fd = open(file, O_RDONLY)) == -1)
   {
      fprintf(stderr, "%s: %s: %s\n", PROGRAM_NAME, file, strerror(errno));
      return(1);
   };
   
   if ((len = read(fd, buff,size-1)) == -1)
   {
      fprintf(stderr, "%s: %s: %s\n", PROGRAM_NAME, file, strerror(errno));
      return(1);
   };
   buff[len] = '\0';
   
   close(fd);
   
   return(0);
}


/// displays usage for common options
void ldaputils_usage_common(void)
{
   // TRANSLATORS: The following strings provide usage for common command
   // line arguments. Usage for program specific arguments is provided in
   // anothoer section. These strings are displayed if the program is
   // passed `--help' on the command line.
   printf(_("Common options:\n"
         "  -c                continuous operation mode (do not stop on errors)\n"
         "  -C                chase referrals (anonymously)\n"
         "  -d level          set LDAP debug level to `level'\n"
         "  -D binddn         bind DN\n"
         "  -h host           LDAP server\n"
         "  -H URI            LDAP Uniform Resource Identifier(s)\n"
         "  -n                show what would be done but don't actually do it\n"
         "  -p port           port on LDAP server\n"
         "  -v, --verbose     run in verbose mode\n"
         "  -V, --version     print version number and exit\n"
         "  -w, passwd        bind password (for simple authentication)\n"
         "  -W                prompt for bind password\n"
         "  -y file           read password from file\n"
         "  --help            print this help and exit\n"
      )
   );
   return;
}


/// displays search usage for search options
void ldaputils_usage_search(void)
{
   // TRANSLATORS: The following strings provide usage for search command
   // line arguments. Usage for program specific arguments is provided in
   // anothoer section. These strings are displayed if the program is
   // passed `--help' on the command line.
   printf(_("Search options:\n"
         "  -b basedn         base dn for search\n"
         "  -l limit          time limit (in seconds) for search\n"
         "  -s scope          one of base, one, or sub (search scope)\n"
         "  -S attr           sort results by attribute `attr'\n"
         "  -z limit          size limit for search\n"
      )
   );
   return;
}


/// displays usage
void ldaputils_version(void)
{
   // TRANSLATORS: The following strings provide version and copyright
   // information if the program is passed --version on the command line.
   // The three strings referenced are: PROGRAM_NAME, PACKAGE_NAME,
   // PACKAGE_VERSION.
   printf(_( "%s (%s) %s\n"
         "Written by David M. Syzdek.\n"
         "\n"
         "Copyright (C) 2008 David M. Syzdek.\n"
         "This is free software; see the source for copying conditions.  There is NO\n"
         "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n"
      ), PROGRAM_NAME, PACKAGE_NAME, PACKAGE_VERSION
   );
   return;
}

/* end of source file */
