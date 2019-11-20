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
#define _LDAP_UTILS_SRC_OIDSPECTOOL 1
#include "oidspectool.h"

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


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#pragma mark - Definitions


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#pragma mark - Datatypes

enum my_format
{
   OidSpecFormatHeader,
   OidSpecFormatMakefile,
   OidSpecFormatSource,
   OidSpecFormatUnknown,
};
typedef enum my_format MyFormat;


struct my_config
{
   int            dryrun;
   MyFormat       format;
   const char   * output;
   const char   * prune;
   const char   * name;
   const char   * type;
   const char  ** includes;
   char           NAME[256];
   int            verbose;
   int            sparse;
};
typedef struct my_config MyConfig;


struct my_oidspec
{
   char     * filename;
   int        lineno;
   char    ** oid;
   char    ** name;
   char    ** notes;
   char    ** desc;
   char    ** examples;
   char    ** flags;
   char    ** type;
   char    ** class;
   char    ** def;
   char    ** abnf;
   char    ** re_posix;
   char    ** re_pcre;
   char    ** spec;
   char    ** spec_type;
   char    ** spec_name;
   char    ** spec_section;
   char    ** spec_source;
   char    ** spec_text;
   char    ** spec_vendor;
};
typedef struct my_oidspec OIDSpec;


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

char           ** string_queue      = NULL;
const char      * cur_filename      = NULL;
OIDSpec         * cur_oidspec       = NULL;
OIDSpec        ** oidspeclist       = NULL;
size_t            oidspeclist_len   = 0;
char           ** filelist          = NULL;
size_t            filelist_len      = 0;


MyConfig cfg =
{
   .dryrun        = 0,
   .verbose       = 0,
   .sparse        = 0,
   .format        = OidSpecFormatUnknown,
   .output        = "-",
   .prune         = NULL,
   .name          = "ldapschema_oidspecs",
   .type          = "const struct ldapschema_spec",
};


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

// main statement
int main(int argc, char * argv[]);

// tests filename string for specified extension
int my_fs_filename_ext(const char * nam, const char * ext);

// process individual OID spec file
int my_fs_parsefile(const char * file);

// prunes string from path names
const char * my_fs_prunepath(const char * path);

// process path for OID spec files
int my_fs_scanpath(const char * path);

// free memory from OID specification
void my_oidspec_free(OIDSpec * oidspec);

// free array of strings
void my_oidspec_free_strs(char ** strs);

// allocate memory for OID specifications and initialize values
OIDSpec * my_oidspec_alloc(void);

// save list of OID specifications
int my_save(int argc, char **argv);

// save list of OID specifications as C header file
int my_save_header(FILE * fs);

// save list of OID spec files as Makefile include
int my_save_makefile(FILE * fs);

// save list of OID specifications as C source file
int my_save_source(FILE * fs);

// save individual OID specification
int my_save_source_oidspec(FILE * fs, OIDSpec * oidspec, size_t idx);

// save OID specification field as bit flags
int my_save_source_oidspec_flgs(FILE * fs, const char * fld, char ** vals);

// save OID specification field as const strings
int my_save_source_oidspec_strs(FILE * fs, const char * fld, char ** vals);

// prints program usage and exits
void my_usage(void);

// displays version information
void my_version(void);

// compares two OID specifications for sort order
int oidspec_cmp( const void * p1, const void * p2 );


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
   size_t         pos;
   void         * ptr;

   static char          short_options[]   = "C:hHMnN:o:p:sST:vV";
   static struct option long_options[]    =
   {
      {"include",       required_argument, 0, 'I'},
      {"name",          required_argument, 0, 'N'},
      {"output",        required_argument, 0, 'o'},
      {"prune",         required_argument, 0, 'p'},
      {"type",          required_argument, 0, 'T'},
      {"help",          no_argument,       0, 'h'},
      {"header",        no_argument,       0, 'H'},
      {"makefile",      no_argument,       0, 'M'},
      {"dryrun",        no_argument,       0, 'n'},
      {"source",        no_argument,       0, 'S'},
      {"sparse",        no_argument,       0, 's'},
      {"verbose",       no_argument,       0, 'v'},
      {"version",       no_argument,       0, 'V'},
      {NULL,            0,                 0, 0  }
   };

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

         case 'H':
         cfg.format = OidSpecFormatHeader;
         break;

         case 'I':
         for(pos = 0; ( ((cfg.includes)) && ((cfg.includes[pos])) ); pos++);
         if ((ptr = realloc(cfg.includes, (sizeof(char *)*(pos+2)))) == NULL)
         {
            fprintf(stderr, "%s: out of virtual memory\n", PROGRAM_NAME);
            return(1);
         };
         cfg.includes = ptr;
         if ((cfg.includes[pos] = strdup(optarg)) == NULL)
         {
            fprintf(stderr, "%s: out of virtual memory\n", PROGRAM_NAME);
            return(1);
         };
         cfg.includes[pos+1] = NULL;
         break;

         case 'M':
         cfg.format = OidSpecFormatMakefile;
         break;

         case 'n':
         cfg.dryrun++;
         break;

         case 'N':
         cfg.name = optarg;
         break;

         case 'o':
         cfg.output = optarg;
         break;

         case 'p':
         cfg.prune = optarg;
         break;

         case 's':
         cfg.sparse++;
         break;

         case 'S':
         cfg.format = OidSpecFormatSource;
         break;

         case 'T':
         cfg.type = optarg;
         break;

         case 'V':
         my_version();
         return(0);

         case 'v':
         cfg.verbose++;
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
   if ( (!(cfg.dryrun)) && (!(cfg.output)) )
   {
      fprintf(stderr, "%s: missing required options `-o' or `-n'\n", PROGRAM_NAME);
      fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
      return(1);
   };
   if ( (!(cfg.dryrun)) && (cfg.format == OidSpecFormatUnknown) )
   {
      fprintf(stderr, "%s: missing output format\n", PROGRAM_NAME);
      fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
      return(1);
   };

   // initialize global variables
   if ((cur_oidspec = my_oidspec_alloc()) == NULL)
      return(2);
   if ((oidspeclist = malloc(sizeof(OIDSpec *))) == NULL)
      return(2);
   oidspeclist[0] = NULL;
   if ((filelist = malloc(sizeof(char *))) == NULL)
      return(2);
   filelist[0] = NULL;
   strncpy(cfg.NAME, cfg.name, sizeof(cfg.NAME));
   for(pos = 0; ((cfg.NAME[pos])); pos++)
      if ( (cfg.NAME[pos] >= 'a') && (cfg.NAME[pos] <= 'z') )
         cfg.NAME[pos] = cfg.NAME[pos] - 'a' + 'A';

   // loops through files
   while ((argc - optind))
   {
      if ((err = my_fs_scanpath(argv[optind])) != 0)
         return(err);
      optind++;
   };


   // prints result
   if ((err = my_save(argc, argv)) != 0)
      return(1);
   if ((cfg.verbose))
   {
      printf("stats: %zu files parsed\n", filelist_len);
      printf("stats: %zu OID specifications indexed\n", oidspeclist_len);
   };

   return(0);
}


/// tests filename string for specified extension
/// @param[in] nam     file name
/// @param[in] ext     file extension
int my_fs_filename_ext(const char * nam, const char * ext)
{
   size_t namlen = strlen(nam);
   size_t extlen = strlen(ext);
   if (namlen < extlen)
      return(1);
   return(strcasecmp(ext, &nam[namlen-extlen]));
}


/// process individual OID spec file
/// @param[in] file   OID specification file to process
int my_fs_parsefile(const char * file)
{
   size_t   size;
   void   * ptr;
   FILE   * fs;
   int      err;

   // append file to file list
   size = sizeof(char *) * (filelist_len+2);
   if ((ptr = realloc(filelist, size)) == NULL)
   {
      fprintf(stderr, "%s: out of virtual memory\n", PROGRAM_NAME);
      return(1);
   };
   filelist = ptr;
   if ((filelist[filelist_len] = strdup(file)) == NULL)
   {
      fprintf(stderr, "%s: out of virtual memory\n", PROGRAM_NAME);
      return(1);
   };
   filelist_len++;
   filelist[filelist_len] = NULL;

   // open file for parsing
   if ((cfg.verbose))
      printf("parsing \"%s\" ...\n", file);
   if ((fs = fopen(file, "r")) == NULL)
   {
      fprintf(stderr, "%s: %s: %s\n", PROGRAM_NAME, file, strerror(errno));
      return(1);
   };

   cur_filename = file;

   yyrestart(fs);
   err = yyparse();

   // close file
   fclose(fs);

   return(err);
}


/// prunes string from path names
/// @param[in] path   file system path to process for OID specification files
const char * my_fs_prunepath(const char * path)
{
   size_t len;

   if (!(cfg.prune))
      return(path);

   len = strlen(cfg.prune);
   if (!(strncmp(cfg.prune, path, len)))
      return(&path[len]);

   return(path);
}


/// process path for spec files
/// @param[in] path   file system path to process for OID specification files
int my_fs_scanpath(const char * path)
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
      case S_IFREG: return(my_fs_parsefile(path));
      case S_IFDIR: break;
      default:
      fprintf(stderr, "%s: %s: not a regular file or directory\n", PROGRAM_NAME, path);
      return(1);
      break;
   };

   // open directory
   if ((cfg.verbose))
      printf("scanning \"%s\" ...\n", path);
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
      if ( ((my_fs_filename_ext(filename, ".oidspec"))) &&
           ((my_fs_filename_ext(filename, ".oidspec.c"))) )
         continue;

      // parse file
      if ((err = my_fs_parsefile(filename)) != 0)
         return(err);
   };

   // close directory
   closedir(dir);

   return(0);
}



/// allocate memory for OID specifications and initialize values
OIDSpec * my_oidspec_alloc(void)
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


/// free memory from OID specification
/// @param[in] oidspec    reference to OID specification memory
void my_oidspec_free(OIDSpec * oidspec)
{
   if (!(oidspec))
      return;

   if ((oidspec->filename))
      free(oidspec->filename);

   my_oidspec_free_strs(oidspec->oid);
   my_oidspec_free_strs(oidspec->name);
   my_oidspec_free_strs(oidspec->desc);
   my_oidspec_free_strs(oidspec->examples);
   my_oidspec_free_strs(oidspec->flags);
   my_oidspec_free_strs(oidspec->type);
   my_oidspec_free_strs(oidspec->class);
   my_oidspec_free_strs(oidspec->def);
   my_oidspec_free_strs(oidspec->abnf);
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


/// free array of strings
/// @param[in] strs    reference to array of strings
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


/// save list of OID specifications as C source file
/// @param[in] argc   number of arguments
/// @param[in] argv   array of arguments
int my_save(int argc, char **argv)
{
   FILE         * fs;
   size_t         pos;
   const char   * comment;
   char           buff[256];
   time_t         timer;
   struct tm    * tm_info;

   if ((cfg.dryrun))
      return(0);

   // open file for writing
   fs = stdout;
   if ( ((cfg.output)) && ((strcmp("-", cfg.output))) )
   {
      if ((cfg.verbose))
         printf("saving results to \"%s\" ...\n", cfg.output);
      if ((fs = fopen(cfg.output, "w")) == NULL)
      {
         fprintf(stderr, "%s: fopen: %s: %s\n", PROGRAM_NAME, cfg.output, strerror(errno));
         return(1);
      };
   };

   // prints file header
   if (cfg.format == OidSpecFormatMakefile)
      comment = "#";
   else
      comment = "//";
   fprintf(fs, "%s\n", comment);
   time(&timer);
   tm_info = localtime(&timer);
   strftime(buff, sizeof(buff), "%Y-%m-%d %H:%M:%S", tm_info);
   fprintf(fs, "%s Generated on:   %s\n", comment, buff);
   fprintf(fs, "%s Generated with: %s \\\n", comment, argv[0]);
   for(pos = 1; pos < ((size_t)(argc-1)); pos++)
      fprintf(fs, "%s                    %s \\\n", comment, argv[pos]);
   fprintf(fs, "%s                    %s\n", comment, argv[pos]);
   fprintf(fs, "\n");
   fprintf(fs, "%s\n", comment);

   switch(cfg.format)
   {
         case OidSpecFormatHeader:
         my_save_header(fs);
         break;

         case OidSpecFormatMakefile:
         my_save_makefile(fs);
         break;

         default:
         my_save_source(fs);
         break;
   };

   // closes file
   if (fs != stdout)
      fclose(fs);

   return(0);
}


/// save list of OID specifications as C header file
/// @param[in] fs     FILE stream of output file
int my_save_header(FILE * fs)
{
   size_t         pos;

   // print header
   fprintf(fs, "#ifndef _%s_H\n", cfg.NAME);
   fprintf(fs, "#define _%s_H 1\n", cfg.NAME);
   fprintf(fs, "\n");
   fprintf(fs, "#include <stdio.h>\n");
   for(pos = 0; ( ((cfg.includes)) && ((cfg.includes[pos])) ); pos++)
      fprintf(fs, "#include <%s>\n", cfg.includes[pos]);
   fprintf(fs, "\n");

   // save OID specs
   for(pos = 0; pos < oidspeclist_len; pos++)
      fprintf(fs, "extern %s %s%zu;\n", cfg.type, cfg.name, pos);
   fprintf(fs, "\n");
   fprintf(fs, "extern const size_t %s_len;\n", cfg.name);
   fprintf(fs, "extern %s * %s[];\n", cfg.type, cfg.name);
   fprintf(fs, "\n\n#endif /* end of header */\n");

   return(0);
}


/// save list of OID spec files as Makefile include
/// @param[in] fs     FILE stream of output file
int my_save_makefile(FILE * fs)
{
   size_t         pos;

   // save file list
   fprintf(fs, "\n");
   for(pos = 0; pos < filelist_len; pos++)
      fprintf(fs, "%s += %s\n", cfg.NAME, my_fs_prunepath(filelist[pos]));
   fprintf(fs, "\n\n# end of makefile include\n");

   return(0);
}


/// save list of OID specifications as C source file
/// @param[in] fs     FILE stream of output file
int my_save_source(FILE * fs)
{
   size_t         pos;

   // print header
   fprintf(fs, "#define _%s 1\n", cfg.NAME);
   fprintf(fs, "\n");
   fprintf(fs, "#include <stdio.h>\n");
   for(pos = 0; ( ((cfg.includes)) && ((cfg.includes[pos])) ); pos++)
      fprintf(fs, "#include <%s>\n", cfg.includes[pos]);
   fprintf(fs, "\n");

   // sort OIDs
   qsort(oidspeclist, oidspeclist_len, sizeof(OIDSpec *), oidspec_cmp);

   // save OID specs
   for(pos = 0; pos < oidspeclist_len; pos++)
      my_save_source_oidspec(fs, oidspeclist[pos], pos);

   // generate array
   fprintf(fs, "const size_t %s_len = %zu;\n", cfg.name, oidspeclist_len);
   fprintf(fs, "%s * %s[] =\n", cfg.type, cfg.name);
   fprintf(fs, "{\n");
   for(pos = 0; pos < oidspeclist_len; pos++)
      fprintf(fs, "  &%s%zu, // %s\n", cfg.name, pos, oidspeclist[pos]->oid[0]);
   fprintf(fs, "  NULL\n");
   fprintf(fs, "};\n");
   fprintf(fs, "\n");

   // prints footer
   fprintf(fs, "/* end of source */\n");

   return(0);
}


/// save individual OID specification
/// @param[in] fs         FILE stream of output file
/// @param[in] oidspec    OID specification to save
/// @param[in] idx        index or ID of OID specification
int my_save_source_oidspec(FILE * fs, OIDSpec * oidspec, size_t idx)
{
   size_t pos;

   fprintf(fs, "// %s\n", oidspec->oid[0]);
   fprintf(fs, "// %s:%i\n", my_fs_prunepath(oidspec->filename), oidspec->lineno);
   fprintf(fs, "%s %s%zu =\n", cfg.type, cfg.name, idx);
   fprintf(fs, "{\n");
   my_save_source_oidspec_strs(fs, ".oid",            oidspec->oid);
   my_save_source_oidspec_strs(fs, ".name",           oidspec->name);
   my_save_source_oidspec_strs(fs, ".desc",           oidspec->desc);
   my_save_source_oidspec_flgs(fs, ".flags",          oidspec->flags);
   my_save_source_oidspec_flgs(fs, ".type",           oidspec->type);
   my_save_source_oidspec_flgs(fs, ".class",          oidspec->class);
   my_save_source_oidspec_strs(fs, ".def",            oidspec->def);
   my_save_source_oidspec_strs(fs, ".abnf",           oidspec->abnf);
   my_save_source_oidspec_strs(fs, ".re_posix",       oidspec->re_posix);
   my_save_source_oidspec_strs(fs, ".re_pcre",        oidspec->re_pcre);
   my_save_source_oidspec_strs(fs, ".spec",           oidspec->spec);
   my_save_source_oidspec_strs(fs, ".spec_type",      oidspec->spec_type);
   my_save_source_oidspec_strs(fs, ".spec_name",      oidspec->spec_name);
   my_save_source_oidspec_strs(fs, ".spec_section",   oidspec->spec_section);
   my_save_source_oidspec_strs(fs, ".spec_source",    oidspec->spec_source);
   my_save_source_oidspec_strs(fs, ".spec_vendor",    oidspec->spec_vendor);
   my_save_source_oidspec_strs(fs, ".spec_text",      oidspec->spec_text);
   my_save_source_oidspec_strs(fs, ".notes",          oidspec->notes);
   if ((oidspec->examples))
   {
      fprintf(fs, "   %-15s = (const char *[])\n", ".examples");
      fprintf(fs, "%20s {\n", "");
      for(pos = 0; ((oidspec->examples[pos])); pos++)
         fprintf(fs, "%20s    %s,\n", "", oidspec->examples[pos]);
      fprintf(fs, "%20s    NULL,\n", "");
      fprintf(fs, "%20s },\n", "");
   } else if (!(cfg.sparse))
   {
      fprintf(fs, "   %-15s = NULL,\n", ".examples");
   };
   fprintf(fs, "};\n\n\n");

   return(0);
}


/// save OID specification field as bit flags
/// @param[in] fs     FILE stream of output file
/// @param[in] fld    name of field
/// @param[in] vals   array of values
int my_save_source_oidspec_flgs(FILE * fs, const char * fld, char ** vals)
{
   size_t pos;

   if ( (!(vals)) && ((cfg.sparse)) )
      return(0);

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


/// save OID specification field as const strings
/// @param[in] fs     FILE stream of output file
/// @param[in] fld    name of field
/// @param[in] vals   array of values
int my_save_source_oidspec_strs(FILE * fs, const char * fld, char ** vals)
{
   size_t pos;

   if ( (!(vals)) && ((cfg.sparse)) )
      return(0);

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


/// prints program usage and exits
void my_usage(void)
{
   printf("Usage: %s --source [OPTIONS] [path ...]\n", PROGRAM_NAME);
   printf("       %s --header [OPTIONS] [path ...]\n", PROGRAM_NAME);
   printf("       %s --makefile [OPTIONS] [path ...]\n", PROGRAM_NAME);
   printf("OPTIONS:\n");
   printf("  -h, --help                print this help and exit\n");
   printf("  -n, --dryrun              show what would be done, but do nothing\n");
   printf("  -o file                   output file (default: \"%s\")\n", cfg.output);
   printf("  -v, --verbose             run in verbose mode\n");
   printf("  -V, --version             print version number and exit\n");
   printf("  --include=header          add CPP #include in source and header (default: none)\n");
   printf("  --name=name               name of output variable(default: \"%s\")\n", cfg.name);
   printf("  --prune=str               prune string from saved filenames (default: none)\n");
   printf("  --sparse                  exclude fields with NULL or 0 values\n");
   printf("  --type=type               set output variable type(default: \"%s\")\n", cfg.type);
   printf("FORMATS:\n");
   printf("  --header                  output C header\n");
   printf("  --makefile                output makefile include\n");
   printf("  --source                  output C source\n");
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


/// append string to array of queued strings
/// @param[in] str     C string to append to queue
int my_yyappend(const char * str)
{
   size_t      len;
   void      * ptr;

   assert(str != NULL);

   // increase size of array
   if ((string_queue))
   {
      for(len = 0; ((string_queue[len])); len++);
      if ((ptr = realloc(string_queue, (sizeof(char *) * (len+2)))) == NULL)
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
   string_queue         = ptr;
   string_queue[len+0]  = NULL;
   string_queue[len+1]  = NULL;

   // duplicate string
   if ((string_queue[len] = strdup(str)) == NULL)
   {
      fprintf(stderr, "%s: out of virtual memory\n", PROGRAM_NAME);
      exit(EXIT_FAILURE);
   };

   return(0);
}


/// commits queued strings to field
/// @param[in] type    Yacc token of field
int my_yycommit(enum yytokentype type)
{
   const char      * name;
   char          *** vals;

   vals = NULL;
   switch(type)
   {
      case FLD_ABNF:           name = ".abnf";          vals = &cur_oidspec->abnf;         break;
      case FLD_CLASS:          name = ".class";         vals = &cur_oidspec->class;        break;
      case FLD_DEF:            name = ".def";           vals = &cur_oidspec->def;          break;
      case FLD_DESC:           name = ".desc";          vals = &cur_oidspec->desc;         break;
      case FLD_EXAMPLES:       name = ".examples";      vals = &cur_oidspec->examples;     break;
      case FLD_FLAGS:          name = ".flags";         vals = &cur_oidspec->flags;        break;
      case FLD_NAME:           name = ".name";          vals = &cur_oidspec->name;         break;
      case FLD_NOTES:          name = ".notes";         vals = &cur_oidspec->notes;        break;
      case FLD_OID:            name = ".oid";           vals = &cur_oidspec->oid;          break;
      case FLD_RE_POSIX:       name = ".re_posix";      vals = &cur_oidspec->re_posix;     break;
      case FLD_RE_PCRE:        name = ".re_pcre";       vals = &cur_oidspec->re_pcre;      break;
      case FLD_SPEC:           name = ".spec";          vals = &cur_oidspec->spec;         break;
      case FLD_SPEC_NAME:      name = ".spec_name";     vals = &cur_oidspec->spec_name;    break;
      case FLD_SPEC_SECTION:   name = ".spec_section";  vals = &cur_oidspec->spec_section; break;
      case FLD_SPEC_SOURCE:    name = ".spec_source";   vals = &cur_oidspec->spec_source;  break;
      case FLD_SPEC_TEXT:      name = ".spec_text";     vals = &cur_oidspec->spec_text;    break;
      case FLD_SPEC_TYPE:      name = ".spec_type";     vals = &cur_oidspec->spec_type;    break;
      case FLD_SPEC_VENDOR:    name = ".spec_vendor";   vals = &cur_oidspec->spec_vendor;  break;
      case FLD_TYPE:           name = ".type";          vals = &cur_oidspec->type;         break;
      default:
      fprintf(stderr, "%s: %s: %i: encountered unknown token\n", PROGRAM_NAME, cur_filename, yylineno);
      exit(1);
      break;
   };

   // saves values
   if ((*vals))
   {
      fprintf(stderr, "%s: %s: %i: duplicate %s field in spec\n", PROGRAM_NAME, cur_filename, yylineno, name);
      exit(1);
   };
   *vals = string_queue;
   string_queue = NULL;

   return(0);
}


/// validates OID spec and appends to list of OID specs
int my_yyoidspec(void)
{
   size_t         pos;
   void         * ptr;

   // checks current OID spec
   if (!(cur_oidspec->oid))
   {
      fprintf(stderr, "%s: %s: %i: spec missing .oid field\n", PROGRAM_NAME, cur_filename, yylineno);
      return(1);
   };
   if (!(cur_oidspec->type))
   {
      fprintf(stderr, "%s: %s: %i: spec missing .type field\n", PROGRAM_NAME, cur_filename, yylineno);
      return(1);
   };
   if (!(cur_oidspec->desc))
   {
      fprintf(stderr, "%s: %s: %i: spec missing .desc field\n", PROGRAM_NAME, cur_filename, yylineno);
      return(1);
   };
   if ((cfg.verbose))
      printf("adding %s (%s) ...\n", cur_oidspec->oid[0], cur_oidspec->desc[0]);

   // searches for duplicate (I know, I know, I am being lazy)
   for(pos = 0; pos < oidspeclist_len; pos++)
   {
      if (!(strcasecmp(oidspeclist[pos]->oid[0], cur_oidspec->oid[0])))
      {
         fprintf(stderr, "%s: %s: %i: duplicate entry for %s\n", PROGRAM_NAME, cur_filename, yylineno, oidspeclist[pos]->oid[0]);
         fprintf(stderr, "%s: %s: %i: duplicate entry for %s\n", PROGRAM_NAME, oidspeclist[pos]->filename, oidspeclist[pos]->lineno, cur_oidspec->oid[0]);
         exit(1);
      };
   };

   // saves file information
   cur_oidspec->lineno = yylineno;
   if ((cur_oidspec->filename = strdup(cur_filename)) == NULL)
   {
      fprintf(stderr, "%s: out of virtual memory\n", PROGRAM_NAME);
      exit(EXIT_FAILURE);
   };

   // increase size of OID spec list
   if ((ptr = realloc(oidspeclist, (sizeof(OIDSpec *)*(oidspeclist_len+2)))) == NULL)
   {
      fprintf(stderr, "%s: out of virtual memory\n", PROGRAM_NAME);
      exit(EXIT_FAILURE);
   };
   oidspeclist = ptr;
   oidspeclist[oidspeclist_len+0] = cur_oidspec;
   oidspeclist[oidspeclist_len+1] = NULL;
   oidspeclist_len++;

   // allocates next OID spec
   if ((cur_oidspec = my_oidspec_alloc()) == NULL)
   {
      fprintf(stderr, "%s: out of virtual memory\n", PROGRAM_NAME);
      exit(EXIT_FAILURE);
   };

   return(0);
}


/// appends string to array of queued strings then commits queue to field
/// @param[in] type    Yacc token of field
/// @param[in] str     C string to append to queue
int my_yysubmit(enum yytokentype type, const char * str)
{
   my_yyappend(str);
   return(my_yycommit(type));
}


/// compares two OID specifications for sort order
/// @param[in] p1   reference to first OID specification
/// @param[in] p2   reference to second OID specification
int oidspec_cmp( const void * p1, const void * p2 )
{
   const OIDSpec * const * o1 = p1;
   const OIDSpec * const * o2 = p2;
   return(strcasecmp((*o1)->oid[0], (*o2)->oid[0]));
}


void yyerror (char *s)
{
   fprintf(stderr, "%s: %s: %i: %s\n", PROGRAM_NAME, cur_filename, yylineno, s);
   return;
}

/* end of source file */
