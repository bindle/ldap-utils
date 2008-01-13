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

/////////////////
//             //
//  Functions  //
//             //
/////////////////

/* parses LDAP config file */
int my_common_config(MyCommonConfig * cnf)
{
   /* declares local vars */
   int          i;
   int          fd;
   char         buff[MY_BUFF_LEN];
   const char * conf[] =
   {
      // %c => expands to ${LDAPCONF}
      // %h => expands to ${HOME}
      // %r => expands to ${LDAPRC}
      SYSCONFDIR "/openldap/ldap.conf",
      SYSCONFDIR "/ldap/ldap.conf",
      SYSCONFDIR "/ldap.conf",
      "%c",
      "%h/.ldaprc",
      "%h/ldaprc",
      "%h/%r",
      "ldaprc",
      "%r",
      NULL
   };

   /* checks for LDAPNOINIT */
   if (cnf->noinit)
      return(0);

   /* parses configuration files */
   for(i = 0; conf[i]; i++)
   {
      if (my_common_config_name(cnf, buff, MY_BUFF_LEN, conf[i]))
         continue;
      if ((fd = open(buff, O_RDONLY)) == -1)
         continue;
      if (cnf->common_opts & MY_COMMON_OPT_DEBUG)
         fprintf(stderr, _("%s: processing config file: %s\n"), PROGRAM_NAME, buff);
      my_common_config_parse(cnf, fd);
      close(fd);
   };

   /* ends function */
   return(0);
}


/* generates file name from format string */
int my_common_config_name(MyCommonConfig * cnf, char * str, unsigned str_len,
	const char * fmt)
{
   /* declares local vars */
   const char * tmp;
   unsigned str_pos;
   unsigned fmt_pos;
   unsigned fmt_len;
   unsigned tmp_len;

   /* initialize variables */
   str_pos = 0;
   fmt_pos = 0;
   fmt_len = strlen(fmt);

   /* loops through format string */
   for(fmt_pos = 0; fmt_pos < fmt_len; fmt_pos++)
   {
      if (fmt[fmt_pos] == '%')
      {
         fmt_pos++;
         switch(fmt[fmt_pos])
         {
            case 'c':
               if (!(tmp = cnf->ldapconf))
                  return(1);
               break;
            case 'h':
               if (!(tmp = cnf->home))
                  return(1);
               break;
            case 'r':
               if (!(tmp = cnf->ldaprc))
                  return(1);
               break;
            default:
               return(1);
         };
         if ((str_pos + (tmp_len = strlen(tmp))) >= str_len)
            return(1);
         strcpy(&str[str_pos], tmp);
         str_pos += tmp_len;
      }
      else
      {
         str[str_pos] = fmt[fmt_pos];
         str_pos++;
       };
      if ((str_pos + 1) >= str_len)
         return(1);
   };

   /* terminates string */
   str[str_pos] = '\0';

   /* ends function */
   return(0);
}


/* frees common config */
void my_common_config_free(MyCommonConfig * cnf)
{
   if (cnf->basedn)
      free(cnf->basedn);

   if (cnf->binddn)
      free(cnf->binddn);

   if (cnf->bindpw)
      free(cnf->bindpw);

   if (cnf->host)
      free(cnf->host);

   if (cnf->uri)
      free(cnf->uri);

   return;
}

/* parses LDAP config file */
int my_common_config_parse(MyCommonConfig * cnf, int fd)
{
   /* declares local vars */
   //int         comment;
   int         len;
   int         line;
   //int         i;
   //char      * opt;
   //char      * val;
   int         pos;
   char        buff[MY_BUFF_LEN];
if (!(cnf))
   return(0);

   /* loops through file */
   do
   {
      /* read next part of file */
      if ((len = read(fd, buff, MY_BUFF_LEN-1)) == -1)
         return(0);
      buff[len] = '\0';

      /* loops through buffer */
      pos = 0;
      line = 0;
      while(buff[pos])
      {
         for(pos = pos; ((buff[pos]) && (buff[pos] != '\n')); pos++)
         {
            switch(buff[pos])
            {
               default:
                  break;
            };
         };
         buff[pos] = '\0';
         line++;
         pos++;
      };
   } while (len > 0);

printf("lines: %i\n", line);

   /* ends function */
   return(0);
}


/* parses LDAP command line arguments */
int my_common_cmdargs(MyCommonConfig * cnf, int c, char * arg)
{
   /* checks argument */
   switch(c)
   {
      case 'c':
         cnf->common_opts |= MY_COMMON_OPT_CONTINUOUS;
         return(0);
      case 'C':
         cnf->common_opts |= MY_COMMON_OPT_REFERRALS;
         return(0);
      case 'D':
         if (cnf->binddn)
            free(cnf->binddn);
         if (!(cnf->binddn = strdup(arg)))
         {
            fprintf(stderr, _("%s: out of virtual memory\n"), PROGRAM_NAME);
            return(1);
         };
         return(0);
      case 'h':
         if (cnf->host)
            free(cnf->host);
         if (!(cnf->host = strdup(arg)))
         {
            fprintf(stderr, _("%s: out of virtual memory\n"), PROGRAM_NAME);
            return(1);
         };
         return(0);
      case 'H':
         if (cnf->uri)
            free(cnf->uri);
         if (!(cnf->uri = strdup(arg)))
         {
            fprintf(stderr, _("%s: out of virtual memory\n"), PROGRAM_NAME);
            return(1);
         };
         return(0);
      case 'p':
         cnf->port = atol(arg);
         return(0);
      case 'P':
         cnf->version = atol(arg);
         return(0);
      case 'u':
         my_common_usage();
         break;
      case 'v':
         cnf->common_opts |= MY_COMMON_OPT_VERBOSE;
         return(0);
      case 'V':
         my_common_version();
         return(1);
      case 'w':
         if (!(cnf->bindpw = strdup(arg)))
         {
            fprintf(stderr, _("%s: out of virtual memory\n"), PROGRAM_NAME);
            return(1);
         };
         return(0);
      case 'W':
         return(0);
      case 'x':
         cnf->common_opts |= MY_COMMON_OPT_SIMPLEAUTH;
         return(0);
      case 'y':
         return(0);
      case 'Z':
         return(0);
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


/* processes environment variables */
int my_common_environment(MyCommonConfig * cnf)
{
   char * tmp;

   /* processes LDAPNOINIT */
   if ((tmp = getenv("LDAPNOINIT")))
   {
      cnf->noinit = 1;
      return(0);
   };

   /* processes HOME */
   cnf->home = getenv("HOME");

   /* processes LDAPBASE */
   if ((tmp = getenv("LDAPBASE")))
      if (!(cnf->basedn = strdup(tmp)))
      {
         fprintf(stderr, _(PROGRAM_NAME ": out of virtual memory\n"));
         return(1);
      };

   /* processes LDAPBINDDN */
   if ((tmp = getenv("LDAPBINDDN")))
      if (!(cnf->binddn = strdup(tmp)))
      {
         fprintf(stderr, _(PROGRAM_NAME ": out of virtual memory\n"));
         return(1);
      };

   /* processes LDAPCONF */
   cnf->ldapconf = getenv("LDAPCONF");

   /* processes LDAPDEBUG */
   if ((tmp = getenv("LDAPDEBUG")))
      cnf->common_opts |= MY_COMMON_OPT_DEBUG;

   /* processes LDAPDEREF */

   /* processes LDAPHOST */
   if ((tmp = getenv("LDAPHOST")))
      if (!(cnf->host = strdup(tmp)))
      {
         fprintf(stderr, _(PROGRAM_NAME ": out of virtual memory\n"));
         return(1);
      };

   /* processes LDAPPORT */
   if ((tmp = getenv("LDAPPORT")))
      cnf->port = atol(tmp);

   /* processes LDAPRC */
   cnf->ldaprc = getenv("LDAPRC");

   /* processes LDAPREFERRALS */

   /* processes LDAPSIZELIMIT */
   if ((tmp = getenv("LDAPSIZELIMIT")))
      cnf->sizelimit = atol(tmp);

   /* processes LDAPTIMELIMIT */
   if ((tmp = getenv("LDAPTIMELIMIT")))
      cnf->timelimit = atol(tmp);

   /* processes LDAPURI */
   if ((tmp = getenv("LDAPURI")))
      if (!(cnf->uri = strdup(tmp)))
      {
         fprintf(stderr, _(PROGRAM_NAME ": out of virtual memory\n"));
         return(1);
      };

   return(0);
}


/* displays usage */
void my_common_usage(void)
{
   /* TRANSLATORS: The following strings provide usage for common command */
   /* line arguments. Usage for program specific arguments is provided in  */
   /* anothoer section. These strings are displayed if the program is */
   /* passed `--help' on the command line. */
   printf( _( "Common options:\n"
         "  -c                continuous operation mode (do not stop on errors)\n"
         "  -C                chase referrals (anonymously)\n"
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
         "Report bugs to <%s>.\n"
      ), PACKAGE_BUGREPORT
   );
   return;
}


/* displays usage */
void my_common_version(void)
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

/* end of source file */
