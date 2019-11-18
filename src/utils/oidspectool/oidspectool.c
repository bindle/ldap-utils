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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

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

struct my_oidspec
{
   char     * filename;
   int        lineno;
   char    ** oid;
   char    ** name;
   char    ** desc;
   char    ** flags;
   char    ** type;
   char    ** class;
   char    ** def;
   char    ** abfn;
   char    ** re_posix;
   char    ** re_pcre;
   char    ** spec;
   char    ** spec_type;
   char    ** spec_name;
   char    ** spec_section;
   char    ** spec_source;
   char    ** spec_vendor;
};
typedef struct my_oidspec OIDSpec;


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

extern int errno;
extern int yylineno;

const char      * my_filename;
char           ** my_state_str;
OIDSpec         * current_oidspec;
OIDSpec        ** list;
size_t            list_len;


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

// main statement
int main(int argc, char * argv[]);

int my_add_oidspec(void);
int my_append(const char * str);
int my_commit(enum yytokentype type);
int my_commit_str(enum yytokentype type, const char * str);
int my_extensions(const char * nam, const char * ext);

void my_oidspec_free(OIDSpec * oidspec);
void my_oidspec_free_strs(char ** strs);
OIDSpec * my_oidspec_init(void);
int my_save(MyConfig * cnf, int argc, char **argv);
int my_save_oidspec(FILE * fs, OIDSpec * oidspec, size_t idx);
int my_save_oidspec_flgs(FILE * fs, const char * fld, char ** vals);
int my_save_oidspec_strs(FILE * fs, const char * fld, char ** vals);


// process spec files
int my_process_file(MyConfig * cnf, const char * file);

// process path for spec files
int my_process_path(MyConfig * cnf, const char * path);

// prints program usage and exits
void my_usage(void);

// displays version information
void my_version(void);

int oidspec_cmp( const void * p1, const void * p2 );

int yyparse (void);
void yyrestart (FILE *input_file);
void yyerror(char *s);


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
   if ( (!(config.dryrun)) && (!(config.output)) )
   {
      fprintf(stderr, "%s: missing required options `-o' or `-n'\n", PROGRAM_NAME);
      fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
      return(1);
   };

   // initialize global variables
   my_state_str   = NULL;
   list           = NULL;
   list_len       = 0;
   if ((current_oidspec = my_oidspec_init()) == NULL)
      return(2);
   if ((list = malloc(sizeof(OIDSpec *))) == NULL)
      return(2);
   list[0] = NULL;


   // loops through files
   while ((argc - optind))
   {
      if ((err = my_process_path(&config, argv[optind])) != 0)
         return(err);
      optind++;
   };


   // prints result
   if ((err = my_save(&config, argc, argv)) != 0)
      return(1);

   return(0);
}


int my_add_oidspec(void)
{
   size_t         pos;
   void         * ptr;

   // checks current OID spec
   if (!(current_oidspec->oid))
   {
      fprintf(stderr, "%s: %s: %i: spec missing .oid field\n", PROGRAM_NAME, my_filename, yylineno);
      return(1);
   };
   if (!(current_oidspec->type))
   {
      fprintf(stderr, "%s: %s: %i: spec missing .type field\n", PROGRAM_NAME, my_filename, yylineno);
      return(1);
   };

   // searches for duplicate (I know, I know, I am being lazy)
   for(pos = 0; pos < list_len; pos++)
   {
      if (!(strcasecmp(list[pos]->oid[0], current_oidspec->oid[0])))
      {
         fprintf(stderr, "%s: %s: %i: duplicate entry for %s\n", PROGRAM_NAME, my_filename, yylineno, list[pos]->oid[0]);
         fprintf(stderr, "%s: %s: %i: duplicate entry for %s\n", PROGRAM_NAME, list[pos]->filename, list[pos]->lineno, current_oidspec->oid[0]);
         exit(1);
      };
   };

   // saves file information
   current_oidspec->lineno = yylineno;
   if ((current_oidspec->filename = strdup(my_filename)) == NULL)
   {
      fprintf(stderr, "%s: out of virtual memory\n", PROGRAM_NAME);
      exit(EXIT_FAILURE);
   };

   // increase size of OID spec list
   if ((ptr = realloc(list, (sizeof(OIDSpec *)*(list_len+2)))) == NULL)
   {
      fprintf(stderr, "%s: out of virtual memory\n", PROGRAM_NAME);
      exit(EXIT_FAILURE);
   };
   list = ptr;
   list[list_len+0] = current_oidspec;
   list[list_len+1] = NULL;
   list_len++;

   // allocates next OID spec
   if ((current_oidspec = my_oidspec_init()) == NULL)
   {
      fprintf(stderr, "%s: out of virtual memory\n", PROGRAM_NAME);
      exit(EXIT_FAILURE);
   };

   return(0);
}


int my_append(const char * str)
{
   size_t      len;
   void      * ptr;

   assert(str != NULL);

   // increase size of array
   if ((my_state_str))
   {
      for(len = 0; ((my_state_str[len])); len++);
      if ((ptr = realloc(my_state_str, (sizeof(char *) * (len+2)))) == NULL)
      {
         fprintf(stderr, "%s: out of virtual memory\n", PROGRAM_NAME);
         exit(EXIT_FAILURE);
      };
   } else
   {
      len = 0;
      if ((ptr = malloc((sizeof(char *) * 2))) == NULL)
      {
         fprintf(stderr, "%s: out of virtual memory\n", PROGRAM_NAME);
         exit(EXIT_FAILURE);
      };
   };
   my_state_str         = ptr;
   my_state_str[len+0]  = NULL;
   my_state_str[len+1]  = NULL;

   // duplicate string
   if ((my_state_str[len] = strdup(str)) == NULL)
   {
      fprintf(stderr, "%s: out of virtual memory\n", PROGRAM_NAME);
      exit(EXIT_FAILURE);
   };

   return(0);
}


int my_commit(enum yytokentype type)
{
   const char      * name;
   char          *** vals;

   vals = NULL;
   switch(type)
   {
      case FLD_ABFN:           name = ".abnf";          vals = &current_oidspec->abfn;         break;
      case FLD_CLASS:          name = ".class";         vals = &current_oidspec->class;        break;
      case FLD_DEF:            name = ".def";           vals = &current_oidspec->def;          break;
      case FLD_DESC:           name = ".desc";          vals = &current_oidspec->desc;         break;
      case FLD_FLAGS:          name = ".flags";         vals = &current_oidspec->flags;        break;
      case FLD_NAME:           name = ".name";          vals = &current_oidspec->name;         break;
      case FLD_OID:            name = ".oid";           vals = &current_oidspec->oid;          break;
      case FLD_RE_POSIX:       name = ".re_posix";      vals = &current_oidspec->re_posix;     break;
      case FLD_RE_PCRE:        name = ".re_pcre";       vals = &current_oidspec->re_pcre;      break;
      case FLD_SPEC:           name = ".spec";          vals = &current_oidspec->spec;         break;
      case FLD_SPEC_NAME:      name = ".spec_name";     vals = &current_oidspec->spec_name;    break;
      case FLD_SPEC_SECTION:   name = ".spec_section";  vals = &current_oidspec->spec_section; break;
      case FLD_SPEC_SOURCE:    name = ".spec_source";   vals = &current_oidspec->spec_source;  break;
      case FLD_SPEC_TYPE:      name = ".spec_type";     vals = &current_oidspec->spec_type;    break;
      case FLD_SPEC_VENDOR:    name = ".spec_vendor";   vals = &current_oidspec->spec_vendor;  break;
      case FLD_TYPE:           name = ".type";          vals = &current_oidspec->type;         break;
      default:
      fprintf(stderr, "%s: %s: %i: encountered unknown token\n", PROGRAM_NAME, my_filename, yylineno);
      exit(1);
      break;
   };

   // saves values
   if ((*vals))
   {
      fprintf(stderr, "%s: %s: %i: duplicate %s field in spec\n", PROGRAM_NAME, my_filename, yylineno, name);
      exit(1);
   };
   *vals = my_state_str;
   my_state_str = NULL;

   return(0);
}


int my_commit_str(enum yytokentype type, const char * str)
{
   my_append(str);
   return(my_commit(type));
}


int my_extensions(const char * nam, const char * ext)
{
   size_t namlen = strlen(nam);
   size_t extlen = strlen(ext);
   if (namlen < extlen)
      return(1);
   return(strcasecmp(ext, &nam[namlen-extlen]));
}


void my_oidspec_free(OIDSpec * oidspec)
{
   if (!(oidspec))
      return;

   if ((oidspec->filename))
      free(oidspec->filename);

   my_oidspec_free_strs(oidspec->oid);
   my_oidspec_free_strs(oidspec->name);
   my_oidspec_free_strs(oidspec->desc);
   my_oidspec_free_strs(oidspec->flags);
   my_oidspec_free_strs(oidspec->type);
   my_oidspec_free_strs(oidspec->class);
   my_oidspec_free_strs(oidspec->def);
   my_oidspec_free_strs(oidspec->abfn);
   my_oidspec_free_strs(oidspec->re_posix);
   my_oidspec_free_strs(oidspec->re_pcre);
   my_oidspec_free_strs(oidspec->spec);
   my_oidspec_free_strs(oidspec->spec_type);
   my_oidspec_free_strs(oidspec->spec_name);
   my_oidspec_free_strs(oidspec->spec_section);
   my_oidspec_free_strs(oidspec->spec_source);
   my_oidspec_free_strs(oidspec->spec_vendor);

   free(oidspec);

   return;
}


void my_oidspec_free_strs(char ** strs)
{
   size_t pos;
   if (!(strs))
      return;
   for(pos = 0; ((strs[pos])); pos++)
      free(strs[pos]);
   free(strs);
   return;
}



OIDSpec * my_oidspec_init(void)
{
   OIDSpec * oidspec;

   if ((oidspec = malloc(sizeof(OIDSpec))) == NULL)
   {
      fprintf(stderr, "%s: out of virtual memory\n", PROGRAM_NAME);
      return(NULL);
   };
   bzero(oidspec, sizeof(OIDSpec));

   return(oidspec);
}

int my_save(MyConfig * cnf, int argc, char **argv)
{
   FILE         * fs;
   size_t         pos;
   char           buff[256];
   time_t         timer;
   struct tm    * tm_info;

   if ((cnf->dryrun))
      return(0);

   // open file for writing
   fs = stdout;
   if ( ((cnf->output)) && ((strcmp("-", cnf->output))) )
   {
      if ((fs = fopen(cnf->output, "w")) == NULL)
      {
         fprintf(stderr, "%s: fopen: %s: %s\n", PROGRAM_NAME, cnf->output, strerror(errno));
         return(1);
      };
   };

   // print header
   fprintf(fs, "//\n");
   time(&timer);
   tm_info = localtime(&timer);
   strftime(buff, sizeof(buff), "%Y-%m-%d %H:%M:%S", tm_info);
   fprintf(fs, "// Generated on:   %s\n", buff);
   fprintf(fs, "// Generated with:");
   for(pos = 0; pos < (size_t)argc; pos++)
      fprintf(fs, " %s", argv[pos]);
   fprintf(fs, "\n");
   fprintf(fs, "//\n");
   fprintf(fs, "\n");
   fprintf(fs, "#include <stdio.h>\n");
   fprintf(fs, "#include \"lspec.h\"\n");
   fprintf(fs, "\n");

   // sort OIDs
   qsort(list, list_len, sizeof(OIDSpec *), oidspec_cmp);

   // save OID specs
   for(pos = 0; pos < list_len; pos++)
      my_save_oidspec(stdout, list[pos], pos);

   // generate array
   fprintf(fs, "const size_t ldapschema_oidspecs_len = %zu;\n", list_len);
   fprintf(fs, "const struct ldapschema_spec * ldapschema_oidspecs[] =\n");
   fprintf(fs, "{\n");
   for(pos = 0; pos < list_len; pos++)
      fprintf(fs, "  &oidspec%zu, // %s\n", pos, list[pos]->oid[0]);
   fprintf(fs, "  NULL\n");
   fprintf(fs, "};\n");

   // closes file
   if (fs != stdout)
      fclose(fs);

   return(1);
}


int my_save_oidspec(FILE * fs, OIDSpec * oidspec, size_t idx)
{
   fprintf(fs, "// %s\n", oidspec->oid[0]);
   fprintf(fs, "// %s:%i\n", oidspec->filename, oidspec->lineno);
   fprintf(fs, "const struct ldapschema_spec oidspec%zu =\n", idx);
   fprintf(fs, "{\n");
   my_save_oidspec_strs(fs, ".oid",            oidspec->oid);
   my_save_oidspec_strs(fs, ".name",           oidspec->name);
   my_save_oidspec_strs(fs, ".desc",           oidspec->desc);
   my_save_oidspec_flgs(fs, ".flags",          oidspec->flags);
   my_save_oidspec_flgs(fs, ".type",           oidspec->type);
   my_save_oidspec_flgs(fs, ".class",          oidspec->class);
   my_save_oidspec_strs(fs, ".def",            oidspec->def);
   my_save_oidspec_strs(fs, ".abfn",           oidspec->abfn);
   my_save_oidspec_strs(fs, ".re_posix",       oidspec->re_posix);
   my_save_oidspec_strs(fs, ".re_pcre",        oidspec->re_pcre);
   my_save_oidspec_strs(fs, ".spec",           oidspec->spec);
   my_save_oidspec_strs(fs, ".spec_type",      oidspec->spec_type);
   my_save_oidspec_strs(fs, ".spec_name",      oidspec->spec_name);
   my_save_oidspec_strs(fs, ".spec_section",   oidspec->spec_section);
   my_save_oidspec_strs(fs, ".spec_source",    oidspec->spec_source);
   my_save_oidspec_strs(fs, ".spec_vendor",    oidspec->spec_vendor);
   my_save_oidspec_strs(fs, ".examples",       NULL);
   fprintf(fs, "};\n\n\n");

   return(0);
}


int my_save_oidspec_flgs(FILE * fs, const char * fld, char ** vals)
{
   size_t pos;

   fprintf(fs, "   %-15s =", fld);
   if ( (!(vals)) || (!(vals[0])) )
   {
      fprintf(fs, " 0,\n");
      return(0);
   };

   fprintf(fs, " %s", vals[0]);
   for(pos = 1; ((vals[pos])); pos++)
      fprintf(fs, "| %s", vals[pos]);
   fprintf(fs, ",\n");

   return(0);
}


int my_save_oidspec_strs(FILE * fs, const char * fld, char ** vals)
{
   size_t pos;

   fprintf(fs, "   %-15s =", fld);
   if ( (!(vals)) || (!(vals[0])) )
   {
      fprintf(fs, " NULL,\n");
      return(0);
   };

   fprintf(fs, " %s", vals[0]);
   for(pos = 1; ((vals[pos])); pos++)
      fprintf(fs, "\n%20s %s", "", vals[pos]);
   fprintf(fs, ",\n");

   return(0);
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

   my_filename = file;

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


int oidspec_cmp( const void * p1, const void * p2 )
{
   const OIDSpec * const * o1 = p1;
   const OIDSpec * const * o2 = p2;
   return(strcasecmp((*o1)->oid[0], (*o2)->oid[0]));
}


void yyerror (char *s)
{
   fprintf(stderr, "%s: %s: %i: %s\n", PROGRAM_NAME, my_filename, yylineno, s);
   return;
}

/* end of source file */
