/*
 *  LDAP Utilities
 *  Copyright (C) 2019 David M. Syzdek <david@syzdek.net>.
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
 *  @file lib/libldapschema/oidspectool/oidspectool.c creates compilation of
 *  OID specifications
 */
/*
 *  Simple Build:
 *     export CFLAGS='-DPROGRAM_NAME="oidspectool" -Wall -I../include'
 *     yacc -d          oidspecparser.y
 *     mv   -f  y.tab.c oidspecparser.c
 *     mv       y.tab.h oidspecparser.h
 *     lex  -t          oidspeclexer.l > oidspeclexer.c
 *     gcc ${CFLAGS} -c oidspectool.c
 *     gcc ${CFLAGS} -c oidspecparser.c
 *     gcc ${CFLAGS} -c oidspeclexer.c
 *     gcc ${CFLAGS} -o oidspectool -ll oidspectool.o oidspecparser.o \
 *         oidspeclexer.o
 *
 *  Libtool Build:
 *     export CFLAGS='-DPROGRAM_NAME="oidspectool" -Wall -I../include'
 *     yacc -d          oidspecparser.y
 *     mv   -f  y.tab.c oidspecparser.c
 *     mv       y.tab.h oidspecparser.h
 *     lex  -t          oidspeclexer.l > oidspeclexer.c
 *     libtool --mode=compile --tag=CC gcc ${CFLAGS} -c oidspectool.c
 *     libtool --mode=compile --tag=CC gcc ${CFLAGS} -c oidspecparser.c
 *     libtool --mode=compile --tag=CC gcc ${CFLAGS} -c oidspeclexer.c
 *     libtool --mode=link    --tag=CC gcc ${CFLAGS} -o oidspectool -ll \
 *         oidspectool.o oidspecparser.o oidspeclexer.o
 *
 *  Libtool Clean:
 *     libtool --mode=clean rm -f oidspectool.lo oidspecparser.lo \
 *         oidspeclexer.lo oidspectool
 */
#define _LDAP_UTILS_LIB_LIBLDAPSCHEMA_OIDSPECTOOL 1

///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

#define _GNU_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <getopt.h>
#include <assert.h>
#include <dirent.h>
#include <sys/stat.h>

#define LDAP_DEPRECATED 1
#include <ldap.h>

#include "oidspecparser.h"


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#pragma mark - Definitions

#ifndef PROGRAM_NAME
#define PROGRAM_NAME "oidspectool"
#endif
#ifndef PACKAGE_NAME
#define PACKAGE_NAME "LDAP Utilities"
#endif
#ifndef PACKAGE_VERSION
#define PACKAGE_VERSION ""
#endif
#ifndef PACKAGE_NAME
#define PACKAGE_NAME "LDAP Utilities"
#endif


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#pragma mark - Datatypes

struct my_config
{
   int            dryrun;
   int            makefile;
   const char   * output;
   int            verbose;
};

typedef struct my_config MyConfig;


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

extern int errno;


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

// main statement
int main(int argc, char * argv[]);

int my_extensions(const char * nam, const char * ext);

// process spec files
int my_process_file(MyConfig * cnf, const char * file);

// process path for spec files
int my_process_path(MyConfig * cnf, const char * path);

// prints program usage and exits
void my_usage(void);

// displays version information
void my_version(void);

int oidspectool_parse(FILE *);
int yyparse (void);
void yyrestart (FILE *input_file);


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

/// main statement
/// @param[in] argc   number of arguments
/// @param[in] argv   array of arguments
int main(int argc, char * argv[])
{
   int            c;
   int            err;
   int            opt_index;
   MyConfig       config;

   static char          short_options[]   = "hmno:vV";
   static struct option long_options[]    =
   {
      {"help",          no_argument, 0, 'h'},
      {"makefile",      no_argument, 0, 'm'},
      {"dryrun",        no_argument, 0, 'n'},
      {"verbose",       no_argument, 0, 'v'},
      {"version",       no_argument, 0, 'V'},
      {NULL,            0,           0, 0  }
   };

   bzero(&config, sizeof(config));

   // loops through args
   while((c = getopt_long(argc, argv, short_options, long_options, &opt_index)) != -1)
   {
      switch(c)
      {
         case -1:       /* no more arguments */
         case 0:        /* long options toggles */
         break;

         case 'h':
         my_usage();
         return(0);

         case 'm':
         config.makefile++;
         break;

         case 'n':
         config.dryrun++;
         break;

         case 'o':
         config.output = optarg;
         break;

         case 'V':
         my_version();
         return(0);

         case 'v':
         config.verbose++;
         break;

         // argument error
         case '?':
         fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
         return(1);

         // unknown argument error
         default:
         fprintf(stderr, "%s: unrecognized option `--%c'\n", PROGRAM_NAME, c);
         fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
         return(1);
      };
   };
   if ((argc - optind) < 1)
   {
      fprintf(stderr, "%s: missing required argument\n", PROGRAM_NAME);
      fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
      return(1);
   };


   // loops through files
   while ((argc - optind))
   {
      if ((err = my_process_path(&config, argv[optind])) != 0)
         return(err);
      optind++;
   };


   return(err);
}


int my_extensions(const char * nam, const char * ext)
{
   size_t namlen = strlen(nam);
   size_t extlen = strlen(ext);
   if (namlen < extlen)
      return(1);
   return(strcasecmp(ext, &nam[namlen-extlen]));
}


/// process spec files
int my_process_file(MyConfig * cnf, const char * file)
{
   FILE   * fs;
   int      err;

   // open file for parsing
   if ((cnf->verbose))
      printf("opening %s ...\n", file);
   if ((fs = fopen(file, "r")) == NULL)
   {
      fprintf(stderr, "%s: %s: %s\n", PROGRAM_NAME, file, strerror(errno));
      return(1);
   };

   yyrestart(fs);
   err = yyparse();

   // close file
   fclose(fs);

   return(err);
}


/// process path for spec files
int my_process_path(MyConfig * cnf, const char * path)
{
   DIR                * dir;
   struct dirent      * dp;
   struct stat          sb;
   int                  err;
   char                 filename[512];

   // check type of file
   if ((err = stat(path, &sb)) == -1)
   {
      fprintf(stderr, "%s: %s: %s\n", PROGRAM_NAME, path, strerror(errno));
      return(1);
   };
   switch(sb.st_mode & S_IFMT)
   {
      case S_IFREG: return(my_process_file(cnf, path));
      case S_IFDIR: break;
      default:
      fprintf(stderr, "%s: %s: not a regular file or directory\n", PROGRAM_NAME, path);
      return(1);
      break;
   };

   // open directory
   if ((dir = opendir(path)) == NULL)
   {
      fprintf(stderr, "%s: %s: %s\n", PROGRAM_NAME, path, strerror(errno));
      return(1);
   };

   // read directory
   while((dp = readdir(dir)) != NULL)
   {
      // skip hidden files
      if (dp->d_name[0] == '.')
         continue;

      // build path
      snprintf(filename, sizeof(filename), "%s/%s", path, dp->d_name);

      // stat files
      if ((err = stat(filename, &sb)) == -1)
      {
         fprintf(stderr, "%s: %s: %s\n", PROGRAM_NAME, filename, strerror(errno));
         return(1);
      };
      if ((sb.st_mode & S_IFMT) != S_IFREG)
         continue;

      // check for supported file extensions
      if ( ((my_extensions(filename, ".oidspec"))) && ((my_extensions(filename, ".oidspec.c"))) )
         continue;

      // parse file
      if ((err = my_process_file(cnf, filename)) != 0)
         return(err);
   };

   // close directory
   closedir(dir);

   return(0);
}


/// prints program usage and exits
void my_usage(void)
{
   printf("Usage: %s [options] [file ...]\n", PROGRAM_NAME);
   printf("       %s [options] [dir ...]\n", PROGRAM_NAME);
   printf("Options:\n");
   printf("  -h, --help                print this help and exit\n");
   printf("  -m, --makefile            output makefile include instead of C source\n");
   printf("  -n, --dryrun              show what would be done, but do nothing\n");
   printf("  -o file                   output file\n");
   printf("  -v, --verbose             run in verbose mode\n");
   printf("  -V, --version             print version number and exit\n");
   printf("\n");
   return;
}


/// displays version information
void my_version(void)
{
   printf("%s (%s) %s\n", PROGRAM_NAME, PACKAGE_NAME, PACKAGE_VERSION);
#ifdef PACKAGE_COPYRIGHT
   printf("%s\n", PACKAGE_COPYRIGHT);
#endif
   return;
}

/* end of source file */
