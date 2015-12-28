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
 *  @file src/csv2ldif.c convert CSV file to LDIF
 */
/*
 *  Simple Build:
 *     export CFLAGS='-DPROGRAM_NAME="csv2ldif" -Wall -I../include'
 *     gcc ${CFLAGS} -c csv2ldif.c
 *     gcc ${CFLAGS} -c ldaputils_config.c
 *     gcc ${CFLAGS} -lldap -o csv2ldif csv2ldif.o ldaputils_config.o
 *
 *  Libtool Build:
 *     export CFLAGS='-DPROGRAM_NAME="csv2ldif" -Wall -I../include'
 *     libtool --mode=compile --tag=CC gcc ${CFLAGS} -c csv2ldif.c
 *     libtool --mode=compile --tag=CC gcc ${CFLAGS} -c ldaputils_config.c
 *     libtool --mode=compile --tag=CC gcc ${CFLAGS} -c ldaputils_config_opts.c
 *     libtool --mode=compile --tag=CC gcc ${CFLAGS} -c ldaputils_ldap.c
 *     libtool --mode=link    --tag=CC gcc ${CFLAGS} -lldap -o csv2ldif \
 *             csv2ldif.lo ldaputils_config.lo
 *
 *  Libtool Clean:
 *     libtool --mode=clean rm -f csv2ldif.lo ldaputils_config.lo \
 *             csv2ldif
 */
#define _LDAP_UTILS_SRC_CSV2LDIF 1


///////////////
//           //
//  Headers  //
//           //
///////////////

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>

#include "ldaputils_config.h"
#include "ldaputils_ldap.h"

///////////////////
//               //
//  Definitions  //
//               //
///////////////////

#ifndef PROGRAM_NAME
#define PROGRAM_NAME "csv2ldif"
#endif


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////

/* configuration union */
typedef struct my_config MyConfig;
struct my_config
{
   int           verbosity;
   int           extra_count;
   char        ** extra;
   const char  * fmt;
   const char  * file;
};


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////

// main statement
int main PARAMS((int argc, char * argv[]));

// converts buffer into an array of lines
char ** my_buff2lines PARAMS((char * buff, int * countp));

// parses configuration
int my_config PARAMS((int argc, char * argv[], MyConfig * cnf, int * codep));

// reads file into buffer
char * my_file2buff PARAMS((MyConfig * cnf));

// splits line into fields
char ** my_linesfields PARAMS((char * line, int * countp));


/////////////////
//             //
//  Functions  //
//             //
/////////////////

/// prints program usage and exits
void ldaputils_usage(void)
{
   // TRANSLATORS: The following strings provide usage for common command
   // line arguments. Usage for program specific arguments is provided in
   // anothoer section. These strings are displayed if the program is
   // passed `--help' on the command line.
   printf("Usage: %s [options] filter attributes...\n"
         "  -a name:value     additional attribute name/value pair to include\n"
         "  -b fmt            DN format for LDAP records\n"
         "  -f file           CSV file to convert\n"
         "  -h, --help        print this help and exit\n"
         "  -v, --verbose     run in verbose mode\n"
         "  -V, --version     print version number and exit\n"
         "\nReport bugs to <%s>.\n"
      , PROGRAM_NAME, PACKAGE_BUGREPORT
   );
   return;
}


/// main statement
/// @param[in] argc   number of arguments
/// @param[in] argv   array of arguments
int main(int argc, char * argv[])
{
   int         i;
   int         code;
   int         line_count;
   char      * buff;
   char     ** lines;
   MyConfig    cnf;

   if ((my_config(argc, argv, &cnf, &code)))
      return(code);

   if (!(buff = my_file2buff(&cnf)))
      return(1);

   if (!(lines = my_buff2lines(buff, &line_count)))
      return(1);

//for(i = 0; i < cnf.extra_count; i++)
//   printf("%s\n", cnf.extra[i]);
for(i = 0; i < line_count; i++)
   printf("%s\n", lines[i]);

   free(lines);
   free(buff);
   free(cnf.extra);
   
   return(0);
}


/// converts buffer into an array of lines
/// @param[in]  buff    buffer to parse into array of lines
/// @param[out] countp  saves number of lines found
char ** my_buff2lines(char * buff, int * countp)
{
   int        i;
   char    ** lines;
   void     * ptr;
   size_t     len;
   size_t     size;
   //ssize_t    count;
   ssize_t    max_count;

   *countp   = 0;
   max_count = 100;

   size = sizeof(char *) * (max_count + 1);
   if (!(lines = malloc(size)))
   {
      fprintf(stderr, "%s: out of virtual memory\n", PROGRAM_NAME);
      return(NULL);
   };
   memset(lines, 0, size);

   lines[0] = buff;

   for(len = 0; buff[len]; len++)
   {
      switch(buff[len])
      {
         case '\n':
            if (!(buff[len+1]))
               return(lines);
            (*countp)++;
            if (max_count <= *countp)
            {
               max_count += 100;
               size = sizeof(char *) * (max_count + 1);
               if (!(ptr = realloc(lines, size)))
               {
                  fprintf(stderr, "%s: out of virtual memory\n", PROGRAM_NAME);
                  return(NULL);
               };
               lines = ptr;
               for(i = *countp; i < (max_count+1); i++)
                  lines[i] = NULL;
            };
            lines[*countp] = &buff[len+1];
         case '\r':
            buff[len] = '\0';
         default:
            break;
      };
   };

   return(lines);
}


/// parses configuration
/// @param[in]  argc   number of arguments
/// @param[in]  argv   array of arguments
/// @param[in]  cnf    reference to configuration pointer
/// @param[out] codep  pointer to exit code
int my_config(int argc, char * argv[], MyConfig * cnf, int * codep)
{
   int     c;
   int     option_index;
   //char  * val;
   char ** ptr;
   
   static char   short_options[] = "a:b:f:hvV";
   static struct option long_options[] =
   {
      {"help",          no_argument, 0, 'h'},
      {"verbose",       no_argument, 0, 'v'},
      {"version",       no_argument, 0, 'V'},
      {NULL,            0,           0, 0  }
   };
   
   *codep       = 0;
   option_index = 0;
   memset(cnf, 0, sizeof(MyConfig));
   
   // loops through args
   while((c = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1)
   {
      switch(c)
      {
         case -1:     // no more arguments 
         case 0:      // long options toggles
            break;
         
         case 'a':
            cnf->extra_count++;
            if (!(ptr = realloc(cnf->extra, sizeof(char *) * cnf->extra_count)))
            {
               fprintf(stderr, "%s: out of virtual memory\n", PROGRAM_NAME);
               *codep = 1;
               return(1);
            };
            cnf->extra = ptr;
            cnf->extra[cnf->extra_count - 1] = optarg;
            break;
         
         case 'b':
            cnf->fmt = optarg;
            break;

         case 'f':
            cnf->file = optarg;
            break;

         case 'h':
            ldaputils_usage();
            return(1);

         case 'v':
            cnf->verbosity++;
            break;

         case 'V':
            ldaputils_version(PROGRAM_NAME);
            return(1);

         case '?':           // argument error
            fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
            *codep = 1;
            return(1);

         default:
            fprintf(stderr, "%s: unrecognized option `--%c'\n", PROGRAM_NAME, c);
            fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
            *codep = 1;
            return(1);
      };
   };
   
   if (!(cnf->file))
   {
      fprintf(stderr, "%s: missing required arguments\n", PROGRAM_NAME);
      fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
      return(1);
   };
   
   return(0);
}


/// reads file into buffer
/// @param[in] cnf   pointer to configuration
char * my_file2buff(MyConfig * cnf)
{
   int           fd;
   char        * buff;
   ssize_t       len;
   struct stat   sb;

   if ((stat(cnf->file, &sb) == -1))
   {
      perror(PROGRAM_NAME ": stat()");
      return(NULL);
   };

   if (!(buff = malloc((size_t) sb.st_size+1)))
   {
      fprintf(stderr, PROGRAM_NAME ": out of virtual memory\n");
      return(NULL);
   };
   memset(buff, 0, (size_t) sb.st_size+1);

   if ((fd = open(cnf->file, O_RDONLY)) == -1)
   {
      perror(PROGRAM_NAME ": open()");
      free(buff);
      return(NULL);
   };

   if ((len = read(fd, buff, (size_t) sb.st_size)) == -1)
   {
      perror(PROGRAM_NAME ": read()");
      free(buff);
      return(NULL);
   };

   close(fd);

   return(buff);
}


/*
/// splits line into fields
/// @param[in]  line    line to parse into array of fields
/// @param[out] countp  saves number of lines found
char ** my_linesfields(char * line, int * countp)
{
   
}
*/

/* end of source file */
