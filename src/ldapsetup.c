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
 *  src/ldapsetup.c - write net ldap configuration
 */
/*
 *  Simple Build:
 *     gcc -Wall -c ldapsetup.c
 *     gcc -Wall -c ldaputils_common.c
 *     gcc -Wall -o ldapsetup ldapsetup.o ldaputils_common.o
 *
 *  Libtool Build:
 *     libtool --mode=compile gcc -Wall -g -O2 -I../include -c ldapsetup.c
 *     libtool --mode=compile gcc -Wall -g -O2 -I../include -c ldaputils_common.c
 *     libtool --mode=link    gcc -Wall -g -O2 -L../lib -o ldapsetup \
 *             ldapsetup.o ldaputils_common.o
 *
 *  Libtool Clean:
 *     libtool --mode=clean rm -f ldapsetup.lo ldaputils_common.lo ldapsetup
 */
#define _LDAP_UTILS_SRC_LDAPSETUP 1

///////////////
//           //
//  Headers  //
//           //
///////////////

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef WIN32
#include <windows.h>
#endif

#include <inttypes.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <getopt.h>

#include "ldaputils_common.h"

/////////////////
//             //
//  Datatypes  //
//             //
/////////////////

/* configuration union */
typedef struct my_config
{
   uint8_t CommonConfig[sizeof(MyCommonConfig)];
   int          list;
   char * file;
} MyConfig;


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////

/* removes new lines and carrage returns */
void chomp PARAMS((char * str));

/* main statement */
int main PARAMS((int argc, char * argv[]));

/* parses config */
MyConfig * my_cmdline PARAMS((int argc, char *argv[]));

/* generates new config date from old file and user input */
int my_gen_config PARAMS((MyConfig * cnf));

/* prompts user for an int */
int my_read_int PARAMS((const char * prompt, int * nump));

/* prompts user for a string */
int my_read_str PARAMS((const char * prompt, char ** strp));

/* write new configuration file from generated data */
int my_write_config PARAMS((MyConfig * cnf));

/* write int to configuration file */
int my_write_int PARAMS((FILE * fs, const char * name, int val,
	const char * hint));

/* write string to configuration file */
int my_write_str PARAMS((FILE * fs, const char * name, const char * val,
	const char * hint));


/////////////////
//             //
//  Functions  //
//             //
/////////////////

/* removes new lines and carrage returns */
void chomp(char * str)
{
   char * ptr;
   if ((ptr = strchr(str, '\n')))
      ptr[0] = '\0';
   if ((ptr = strchr(str, '\r')))
      ptr[0] = '\0';
   return;
}


/* main statement */
int main(int argc, char * argv[])
{
   MyConfig * cnf;

#ifdef HAVE_GETTEXT
   setlocale (LC_ALL, ""); 
   bindtextdomain (PACKAGE, LOCALEDIR); 
   textdomain (PACKAGE);
#endif

   if (!(cnf = my_cmdline(argc, argv)))
      return(1);

   /* generates new config file */
   if (my_gen_config(cnf))
     return(1);

   /* prints message */
   my_write_config(cnf);

   /* frees memory */
   my_common_config_free((MyCommonConfig *)cnf);
   free(cnf);

   /* ends function */
   return(0);
}


/* parses config */
MyConfig * my_cmdline(int argc, char *argv[])
{
   /* declares local vars */
   int        c;
   int        option_index;
   char     * ptr;
   MyConfig * cnf;

   static char   short_options[] = MY_COMMON_OPTIONS "f:l";
   static struct option long_options[] =
   {
      {"help",          no_argument, 0, 'u'},
      {"verbose",       no_argument, 0, 'v'},
      {"version",       no_argument, 0, 'V'},
      {NULL,            0,           0, 0  }
   };

   /* allocates memory */
   if (!(cnf = (MyConfig *) malloc(sizeof(MyConfig))))
   {
      fprintf(stderr, _("%s: out of virtual memory\n"), PROGRAM_NAME);
      return(NULL);
   };
   memset(cnf, 0, sizeof(MyConfig));

   /* retrieve home directory */
   ((MyCommonConfig *)(cnf))->home = getenv("HOME");

   /* sets variables */
   option_index = 0;

   /* loops through args */
   while((c = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1)
   {
      switch(c)
      {
         case 'f':
            if (!(cnf->file = strdup(optarg)))
            {
               my_common_config_free((MyCommonConfig *)cnf);
               free(cnf);
               return(NULL);
            };
            break;
         case 'l':
            cnf->list = 1;
            break;
         case 'u':
            fprintf(stderr, _("Usage: %s [OPTIONS]\n"), PROGRAM_NAME);
            fprintf(stderr, _("Setup options:\n"));
            fprintf(stderr, _("  -f file           configuration file to generate\n"));
            fprintf(stderr, _("  -l                display current configuration\n"));
            my_common_usage();
            my_common_config_free((MyCommonConfig *)cnf);
            free(cnf);
            return(NULL);
         default:
            if (my_common_cmdargs((MyCommonConfig *)cnf, (int)c, optarg))
            {
               my_common_config_free((MyCommonConfig *)cnf);
               free(cnf);
               return(NULL);
            };
         break;
      };
   };

   /* applies defaults */
   if (!(cnf->file))
   {
      if (!(ptr = (char *) malloc(1024)))
      {
         fprintf(stderr, _("%s: out of virtual memory\n"), PROGRAM_NAME);
         return(NULL);
      };
      memset(ptr, 0, 1024);
      if (my_common_config_name((MyCommonConfig *)cnf, ptr, 1024, "%h/.ldaprc"))
      {
         if (!(cnf->file = strdup("ldaprc")))
         {
            my_common_config_free((MyCommonConfig *)cnf);
            free(cnf);
            return(NULL);
         };
      }
      else
         cnf->file = ptr;
   };

   /* ends function */
   return(cnf);
}


/* generates new config from old file and user input */
int my_gen_config(MyConfig * cnf)
{
   /* declares local vars */
   MyCommonConfig * ccnf;

   /* initialize variables */
   ccnf = (MyCommonConfig *) cnf->CommonConfig;

   /* print greeting */
   printf("%s (%s) %s\n", PROGRAM_NAME, PACKAGE_NAME, PACKAGE_VERSION);
   printf(_("Press \"Enter\" to accept default values.\n"));

   /* prompt for config file to generate */
   if (my_read_str(_("Configuration file"), &cnf->file))
      return(1);
   if (!(cnf->file))
   {
      fprintf(stderr, "%s: must specify configuration file\n", PROGRAM_NAME);
      return(1);
   };

   /* parses config file for existing values */
   if (my_common_config_parse(ccnf, cnf->file))
      return(1);

   /* prompts for URI */
   if (my_read_str(_("URI"), &ccnf->uri))
      return(1);

   /* prompts for base DN */
   if (my_read_str(_("base DN"), &ccnf->basedn))
      return(1);

   ///* prompts for bind DN */
   //if (my_read_str(_("bind DN"), &ccnf->binddn))
   //   return(1);

   ///* prompts for bind password */
   //if (my_read_str(_("bind password"), &ccnf->bindpw))
   //   return(1);

   /* prompts for host */
   if (!(ccnf->uri))
      if (my_read_str(_("host"), &ccnf->host))
         return(1);

   /* prompts for port */
   if (!(ccnf->uri))
      if (my_read_int(_("port"), &ccnf->port))
         return(1);

   ///* prompts for REFERRALS */
   //if (my_read_str(_("Refferrals"), &ccnf->refferrals))
   //   return(1);

   /* prompts for size limit */
   if (my_read_int(_("sizelimit"), &ccnf->sizelimit))
      return(1);

   /* prompts for time limit */
   if (my_read_int(_("timelimit"), &ccnf->timelimit))
      return(1);

   /* ends function */
   return(0);
}


/* reads and replaces an int */
int my_read_int(const char * prompt, int * nump)
{
   int  len;
   char buff[MY_BUFF_LEN];

   buff[MY_BUFF_LEN-1] = '\0';

   if (!(nump))
      return(0);

   /* displays prompts */
   if (*nump)
      printf("%s [%i]: ", prompt, *nump);
   else
      printf("%s: ", prompt);
   fflush(stdout);

   /* read user input */
   if ((len = read(STDIN_FILENO, buff, MY_BUFF_LEN-1)) == -1)
   {
      perror(PROGRAM_NAME ": read()");
      return(1);
   };
   chomp(buff);

   if (!(strlen(buff)))
      return(0);

   if (!(strcmp(buff, "\"\"")))
   {
      *nump = 0;
      return(0);
   };
   *nump = atol(buff);

   return(0);
}


/* reads and replaces a string */
int my_read_str(const char * prompt, char ** strp)
{
   int  len;
   char buff[MY_BUFF_LEN];

   buff[MY_BUFF_LEN-1] = '\0';

   if (!(strp))
      return(0);

   /* displays prompts */
   if (*strp)
      printf("%s [%s]: ", prompt, *strp);
   else
      printf("%s: ", prompt);
   fflush(stdout);

   /* read user input */
   if ((len = read(STDIN_FILENO, buff, MY_BUFF_LEN-1)) == -1)
   {
      perror(PROGRAM_NAME ": read()");
      return(1);
   };
   chomp(buff);

   if (!(strlen(buff)))
      return(0);

   if (!(strcmp(buff, "\"\"")))
   {
      if (*strp)
         free(*strp);
      *strp = NULL;
      return(0);
   };

   if (*strp)
      free(*strp);
   if (!(*strp = strdup(buff)))
   {
      fprintf(stderr, "%s: out of virtual memory\n", PROGRAM_NAME);
      return(1);
   };

   return(0);
}


/* write new configuration file */
int my_write_config(MyConfig * cnf)
{
   FILE      * fs;
   char        timestr[MY_BUFF_LEN];
   time_t      t = time(NULL);
   struct tm * tm = localtime(&t);
   MyCommonConfig * ccnf;

   strftime(timestr, MY_BUFF_LEN-1, "%a %b %d %T %Z %Y", tm);
   ccnf = (MyCommonConfig *) cnf->CommonConfig;

   if (!(fs = fopen(cnf->file, "w")))
   {
      perror(PROGRAM_NAME ": fopen()");
      return(1);
   };

   fprintf(fs, "# LDAP client configuration file.\n");
   fprintf(fs, "# %s\n", cnf->file);
   fprintf(fs, "# Created on %s\n", timestr);
   fprintf(fs, "# Created with ldapsetup.\n");
   fprintf(fs, "\n");

   my_write_str(fs, "URI", ccnf->uri, "ldap[s]://[name[:port]] ...");
   my_write_str(fs, "BASE", ccnf->basedn, "base");
   my_write_str(fs, "BINDDN", ccnf->binddn, "dn");
   my_write_str(fs, "HOST", ccnf->host, "name[:port] ...");
   my_write_int(fs, "PORT", ccnf->port, "port");
   my_write_str(fs, "REFERRALS", NULL, "on/true/yes/off/false/no");
   my_write_int(fs, "SIZELIMIT", ccnf->sizelimit, "integer");
   my_write_int(fs, "TIMELIMIT", ccnf->timelimit, "integer");
   my_write_str(fs, "DEREF", NULL, "when");

   fprintf(fs, "\n");
   fprintf(fs, "# end of ldap configuration\n");

   fclose(fs);

   return(0);
}


/* write int to configuration file */
int my_write_int(FILE * fs, const char * name, int val, const char * hint)
{
   if (val)
      fprintf(fs, "%s %i\n", name, val);
   else
      fprintf(fs, "#%s <%s>\n", name, hint);
   return(0);
}


/* write string to configuration file */
int my_write_str(FILE * fs, const char * name, const char * val,
        const char * hint)
{
   if (val)
      fprintf(fs, "%s \"%s\"\n", name, val);
   else
      fprintf(fs, "#%s <%s>\n", name, hint);
   return(0);
}

/* end of source file */
