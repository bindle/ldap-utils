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
/*
 *  src/ldaputils_common.c - contains shared functions and variables
 */
#define _LDAP_UTILS_SRC_LDAPUTILS_COMMON_C 1
#include "ldaputils_common.h"

///////////////
//           //
//  Headers  //
//           //
///////////////

#include <inttypes.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

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
char * chomp(char * str)
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
int ldaputils_common_cmdargs(LdapUtilsConfig * cnf, int c, const char * arg)
{
   /* checks argument */
   switch(c)
   {
//      case 'c':
//         cnf->common_opts |= MY_COMMON_OPT_CONTINUOUS;
//         return(0);
//      case 'C':
//         cnf->common_opts |= MY_COMMON_OPT_REFERRALS;
//         return(0);
//      case 'D':
//         if (ldaputils_common_config_setopt(cnf, "binddn", arg))
//            return(1);
//         return(0);
//      case 'h':
//         if (ldaputils_common_config_setopt(cnf, "host", arg))
//            return(1);
//         return(0);
//      case 'H':
//         if (ldaputils_common_config_setopt(cnf, "uri", arg))
//            return(1);
//         return(0);
      case 'p':
         cnf->port = atol(arg);
         return(0);
      case 'P':
         cnf->version = atol(arg);
         return(0);
//      case 'u':
//         ldaputils_usage();
//         break;
//      case 'v':
//         cnf->common_opts |= MY_COMMON_OPT_VERBOSE;
//         return(0);
//      case 'V':
//         ldaputils_common_version();
//         return(1);
      case 'w':
         strncpy(cnf->bindpw, arg, MY_OPT_LEN);
         return(0);
      case 'W':
         ldaputils_common_getpass("Enter LDAP Password: ", cnf->bindpw, MY_OPT_LEN);
         return(0);
      case 'x':
         cnf->common_opts |= MY_COMMON_OPT_SIMPLEAUTH;
         return(0);
//      case 'y':
//         return(0);
//      case 'Z':
//         return(0);
      case '?':
         fprintf(stderr, _("Try `%s -h' for more information.\n"), PROGRAM_NAME);
         return(1);
      default:
         fprintf(stderr, _("%s: unrecognized option `--%c'\n"), PROGRAM_NAME, c);
         fprintf(stderr, _("Try `%s -h' for more information.\n"), PROGRAM_NAME);
         return(1);
   };

   /* ends function */
   return(0);
}


///// parses LDAP config file
///// @param[in] cnf
//int ldaputils_common_config(MyCommonConfig * cnf)
//{
//   /* declares local vars */
//   int          i;
//   char         buff[MY_BUFF_LEN];
//   const char * conf[] =
//   {
//      // %c => expands to ${LDAPCONF}
//      // %h => expands to ${HOME}
//      // %r => expands to ${LDAPRC}
//      SYSCONFDIR "/openldap/ldap.conf",
//      SYSCONFDIR "/ldap/ldap.conf",
//      SYSCONFDIR "/ldap.conf",
//      "%c",
//      "%h/.ldaprc",
//      "%h/ldaprc",
//      "%h/%r",
//      "%w/ldaprc",
//      "ldaprc",
//      "%r",
//      NULL
//   };
//
//   /* checks for LDAPNOINIT */
//   if (cnf->noinit)
//      return(0);
//
//   /* parses configuration files */
//   for(i = 0; conf[i]; i++)
//   {
//      if (ldaputils_common_config_name(cnf, buff, MY_BUFF_LEN, conf[i]))
//         continue;
//      ldaputils_common_config_parse(cnf, buff);
//   };
//
//   /* ends function */
//   return(0);
//}


/// frees common config
/// @param[in] cnf
void ldaputils_common_config_free(LdapUtilsConfig * cnf)
{
   if (!(cnf))
      return;
   if (cnf->ludp)
      ldap_free_urldesc(cnf->ludp);

   return;
}


///// generates file name from format string
///// @param[in] cnf
///// @param[in] str
///// @param[in] str_len
//int ldaputils_common_config_name(MyCommonConfig * cnf, char * str, unsigned str_len,
//	const char * fmt)
//{
//   /* declares local vars */
//   const char * tmp;
//   unsigned str_pos;
//   unsigned fmt_pos;
//   unsigned fmt_len;
//   unsigned tmp_len;
//
//   /* initialize variables */
//   str_pos = 0;
//   fmt_pos = 0;
//   fmt_len = strlen(fmt);
//
//   /* checks args */
//   if (!(cnf))
//      return(1);
//
//   /* loops through format string */
//   for(fmt_pos = 0; fmt_pos < fmt_len; fmt_pos++)
//   {
//      if (fmt[fmt_pos] == '%')
//      {
//         fmt_pos++;
//         switch(fmt[fmt_pos])
//         {
//            case 'c':
//               if (!(tmp = cnf->ldapconf))
//                  return(1);
//               break;
//            case 'h':
//               if (!(tmp = cnf->home))
//                  return(1);
//               break;
//            case 'r':
//               if (!(tmp = cnf->ldaprc))
//                  return(1);
//               break;
//            case 'w':
//               if (!(tmp = cnf->homepath))
//                  return(1);
//               break;
//            default:
//               return(1);
//         };
//         if ((str_pos + (tmp_len = strlen(tmp))) >= str_len)
//            return(1);
//         strcpy(&str[str_pos], tmp);
//         str_pos += tmp_len;
//      }
//      else
//      {
//         str[str_pos] = fmt[fmt_pos];
//         str_pos++;
//       };
//      if ((str_pos + 1) >= str_len)
//         return(1);
//   };
//
//   /* terminates string */
//   str[str_pos] = '\0';
//
//   /* ends function */
//   return(0);
//}


///// break config file into lines and then options
///// @param[in] cnf
///// @param[in] name
//int ldaputils_common_config_parse(MyCommonConfig * cnf, const char * name)
//{
//   /* declares local vars */
//   int         fd;
//   int         len;	// length of current buffer segment
//   int         bsize;	// length of current buffer segment
//   int         line;	// line number of configuration file
//   int         pos;	// current position within buffer
//   int         eol;	// position within buffer of current EOL
//   int         optend;  // points to end of option name
//   int         valend;  // points to end of value
//   int         buffend;	// end of buffer
//   char        quotes;	// set to quote type if processing quoted string
//   char        buff[MY_BUFF_LEN];
//   char * opt;
//   char * val;
//
//   /* open file for reading */
//   if ((fd = open(name, O_RDONLY)) == -1)
//   {
//      fprintf(stderr, "file: %s\n", name);
//      perror(PROGRAM_NAME ": open()");
//      return(1);
//   };
//
//   /* prints debug statements */
//   if (cnf->common_opts & MY_COMMON_OPT_DEBUG)
//      fprintf(stderr, _("%s: processing config file: %s\n"), PROGRAM_NAME, name);
//
//   /* initialize variables */
//   pos    = 0;
//   line   = 0;
//   bsize  = MY_BUFF_LEN-1;
//
//   /* loops through file */
//   do
//   {
//      /* read next part of file */
//      if ((len = read(fd, &buff[pos], (unsigned)bsize)) == -1)
//         return(0);
//      buffend       = len + pos;
//      buff[buffend] = '\0';
//
//      /* set initial values for buffer parsing */
//      pos       = 0;
//      eol       = 0;
//
//      /* loops through buffer */
//      while(pos < buffend)
//      {
//         /* initialize variables for this line */
//         opt = NULL;
//         val = NULL;
//         optend = 0;
//         valend = 0;
//         quotes = 0;
//
//         /* processes one line of data */
//         do {
//            switch(buff[pos])
//            {
//               case '#':
//                  for(; ((buff[pos] != '\n') && (buff[pos])); pos++);
//                  if (buff[pos] != '\n')
//                     break;
//               case '\n':
//                  line++;
//                  eol = pos;
//                  buff[pos] = '\0';
//               case '\'':
//               case '\"':
//                  if (!(quotes))
//                     quotes = buff[pos];
//                  else if (quotes == buff[pos])
//                     quotes = 0;
//               case ' ':
//               case '\t':
//                  if ((opt) && (!(optend)) && (!(quotes)))
//                     optend = pos;
//                  if ((val) && (!(valend)) && (!(quotes)))
//                     valend = pos;
//                  break;
//               default:
//                  if (!(opt))
//                    opt = &buff[pos];
//                  else if ((!(val)) && (optend))
//                     val = &buff[pos];
//                  break;
//            };
//            pos++;
//         } while ((buff[pos-1]) && (buff[pos]));
//
//         /* processes arguments if found */
//         if ((valend))
//         {
//            buff[optend] = '\0';
//            buff[valend] = '\0';
//            if (ldaputils_common_config_setopt(cnf, opt, val))
//               return(1);
//         };
//      };
//
//      /* shift end of buffer to beginning of buffer */
//      for(pos = 0; pos < (buffend - eol - 1); pos++)
//         buff[pos] = buff[pos+eol+1];
//      buff[pos] = '\0';
//      bsize = MY_BUFF_LEN - (buffend - eol) -1;
//   } while (len > 0);
//
//   /* close file */
//   close(fd);
//
//   /* ends function */
//   return(0);
//}


///// parses LDAP config file
///// @param[in] cnf
///// @param[in] opt
//int ldaputils_common_config_setopt(MyCommonConfig * cnf, const char * opt,
//        const char * arg)
//{
//   if (!(strcasecmp(opt, "base")))
//   {
//      if (cnf->basedn)
//         free(cnf->basedn);
//      if (!(cnf->basedn = strdup(arg)))
//      {
//         fprintf(stderr, _("%s: out of virtual memory\n"), PROGRAM_NAME);
//         return(1);
//      };
//   };
//
//   if (!(strcasecmp(opt, "binddn")))
//   {
//      if (cnf->binddn)
//         free(cnf->binddn);
//      if (!(cnf->binddn = strdup(arg)))
//      {
//         fprintf(stderr, _("%s: out of virtual memory\n"), PROGRAM_NAME);
//         return(1);
//      };
//   };
//
//   if (!(strcasecmp(opt, "host")))
//   {
//      if (cnf->host)
//         free(cnf->host);
//      if (!(cnf->host = strdup(arg)))
//      {
//         fprintf(stderr, _("%s: out of virtual memory\n"), PROGRAM_NAME);
//         return(1);
//      };
//   };
//
//   if (!(strcasecmp(opt, "port")))
//      cnf->port = atol(arg);
//
//   if (!(strcasecmp(opt, "sizelimit")))
//      cnf->sizelimit = atol(arg);
//
//   if (!(strcasecmp(opt, "timelimit")))
//      cnf->timelimit = atol(arg);
//
//   if (!(strcasecmp(opt, "uri")))
//   {
//      if (cnf->uri)
//         free(cnf->uri);
//      if (!(cnf->uri = strdup(arg)))
//      {
//         fprintf(stderr, _("%s: out of virtual memory\n"), PROGRAM_NAME);
//         return(1);
//      };
//   };
//
//   return(0);
//}


///// processes environment variables
///// @param[in] cnf
//int ldaputils_common_environment(MyCommonConfig * cnf)
//{
//   char * tmp;
//
//   /* processes LDAPNOINIT */
//   if ((tmp = getenv("LDAPNOINIT")))
//   {
//      cnf->noinit = 1;
//      return(0);
//   };
//
//   /* processes HOME */
//   cnf->home = getenv("HOME");
//
//   /* processes HOME */
//   cnf->homepath = getenv("HOMEPATH");
//
//   /* processes LDAPBASE */
//   if ((tmp = getenv("LDAPBASE")))
//      if (!(cnf->basedn = strdup(tmp)))
//      {
//         fprintf(stderr, _("%s: out of virtual memory\n"), PROGRAM_NAME);
//         return(1);
//      };
//
//   /* processes LDAPBINDDN */
//   if ((tmp = getenv("LDAPBINDDN")))
//      if (!(cnf->binddn = strdup(tmp)))
//      {
//         fprintf(stderr, _("%s: out of virtual memory\n"), PROGRAM_NAME);
//         return(1);
//      };
//
//   /* processes LDAPCONF */
//   cnf->ldapconf = getenv("LDAPCONF");
//
//   /* processes LDAPDEBUG */
//   if ((tmp = getenv("LDAPDEBUG")))
//      cnf->common_opts |= MY_COMMON_OPT_DEBUG;
//
//   /* processes LDAPDEREF */
//
//   /* processes LDAPHOST */
//   if ((tmp = getenv("LDAPHOST")))
//      if (!(cnf->host = strdup(tmp)))
//      {
//         fprintf(stderr, _("%s: out of virtual memory\n"), PROGRAM_NAME);
//         return(1);
//      };
//
//   /* processes LDAPPORT */
//   if ((tmp = getenv("LDAPPORT")))
//      cnf->port = atol(tmp);
//
//   /* processes LDAPRC */
//   cnf->ldaprc = getenv("LDAPRC");
//
//   /* processes LDAPREFERRALS */
//
//   /* processes LDAPSIZELIMIT */
//   if ((tmp = getenv("LDAPSIZELIMIT")))
//      cnf->sizelimit = atol(tmp);
//
//   /* processes LDAPTIMELIMIT */
//   if ((tmp = getenv("LDAPTIMELIMIT")))
//      cnf->timelimit = atol(tmp);
//
//   /* processes LDAPURI */
//   if ((tmp = getenv("LDAPURI")))
//      if (!(cnf->uri = strdup(tmp)))
//      {
//         fprintf(stderr, _("%s: out of virtual memory\n"), PROGRAM_NAME);
//         return(1);
//      };
//
//   return(0);
//}


/// getpass() replacement -- SUSV 2 deprecated getpass()
/// @param[in] prompt
/// @param[in] buff
/// @param[in] len
int ldaputils_common_getpass(const char * prompt, char * buff, ssize_t len)
{
   /* declares local vars */
   //int len;
   //char tmp_pass[MY_GETPASS_LEN];
#ifdef HAVE_TERMIOS_H
   struct termios old;
   struct termios new;
#endif

   /* clears memory and flusses buffer */
   memset(buff, 0, len);

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
   if ((len = read(STDIN_FILENO, buff, len-1)) == -1)
      return(1);
   buff[len] = '\0';
   chomp(buff);

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


/// displays usage
void ldaputils_common_usage(void)
{
   /* TRANSLATORS: The following strings provide usage for common command */
   /* line arguments. Usage for program specific arguments is provided in  */
   /* anothoer section. These strings are displayed if the program is */
   /* passed `--help' on the command line. */
   printf(_("Common options:\n"
         "  -c                continuous operation mode (do not stop on errors)\n"
         "  -C                chase referrals (anonymously)\n"
         "  -d level          set LDAP debug level to `level'\n"
         "  -D binddn         bind DN\n"
         "  -h host           LDAP server\n"
         "  -H URI            LDAP Uniform Resource Identifier(s)\n"
         "  -p port           port on LDAP server\n"
         "  -P version        protocol version (default: 3)\n"
         "  -v, --verbose     run in verbose mode\n"
         "      --help        print this help and exit\n"
         "  -V, --version     print version number and exit\n"
         "  -w, passwd        bind password (for simple authentication)\n"
         "  -W                prompt for bind password\n"
         "  -x                Simple authentication\n"
         "  -y file           Read password from file\n"
         "  -Z                Start TLS request (-ZZ to require successful response)\n"
         "\n"
      )
   );
   return;
}


/// displays usage
void ldaputils_common_version(void)
{
   /* TRANSLATORS: The following strings provide version and copyright */
   /* information if the program is passed --version on the command line. */
   /* The three strings referenced are: PROGRAM_NAME, PACKAGE_NAME, */
   /* PACKAGE_VERSION. */
   printf( _( "%s (%s) %s\n"
         "Written by David M. Syzdek.\n"
         "\n"
         "Copyright (C) 2008 David M. Syzdek.\n"
         "This is free software; see the source for copying conditions.  There is NO\n"
         "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n"
      ), PROGRAM_NAME, PACKAGE_NAME, PACKAGE_VERSION
   );
   return;
}


/// displays search usage
void ldaputils_search_usage(void)
{
   /* TRANSLATORS: The following strings provide usage for common command */
   /* line arguments. Usage for program specific arguments is provided in  */
   /* anothoer section. These strings are displayed if the program is */
   /* passed `--help' on the command line. */
   printf(_("Search options:\n"
         "  -b basedn         base dn for search\n"
         "  -l limit          time limit (in seconds) for search\n"
         "  -s scope          one of base, one, or sub (search scope)\n"
         "  -S attr           sort results by attribute `attr'\n"
         "  -u                include User Friendly entry names in output\n"
         "  -z limit          size limit for search\n"
      )
   );
   return;
}




/* end of source file */
