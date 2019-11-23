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
 *  @file src/ldapschema.c display LDAP schema
 */
/*
 *  Simple Build:
 *     export CFLAGS='-DPROGRAM_NAME="ldapschema" -Wall -I../include'
 *     gcc ${CFLAGS} -c ldapschema.c
 *     gcc ${CFLAGS} -lldap -o ldapschema ldapschema.o
 *
 *  Libtool Build:
 *     export CFLAGS='-DPROGRAM_NAME="ldapschema" -Wall -I../include'
 *     libtool --mode=compile --tag=CC gcc ${CFLAGS} -c ldapschema.c
 *     libtool --mode=link    --tag=CC gcc ${CFLAGS} -lldap -o ldapschema \
 *             ldapschema.lo
 *
 *  Libtool Clean:
 *     libtool --mode=clean rm -f ldapschema.lo ldapschema
 */
#define _LDAP_UTILS_SRC_LDAPSCHEMA 1


///////////////
//           //
//  Headers  //
//           //
///////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Headers
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <getopt.h>
#include <assert.h>

#define LDAP_DEPRECATED 1
#include <ldap.h>
#include <ldaputils.h>
#include <ldapschema.h>


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Definitions
#endif

#ifndef PROGRAM_NAME
#define PROGRAM_NAME "ldaptree"
#endif

#define MY_SHORT_OPTIONS LDAPUTILS_OPTIONS_COMMON LDAPUTILS_OPTIONS_SEARCH "87:6:5:4:3"

#define MY_EXIT_SCHEMAERR     2

#define MY_OBJ_ATTR          0x01
#define MY_OBJ_SYNTAX        0x02
#define MY_OBJ_MATCHING      0x04
#define MY_OBJ_OBJCLS        0x08

#define MY_ACTION_LIST       1
#define MY_ACTION_LINT       2
#define MY_ACTION_DUMP       3


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Datatypes
#endif

/* configuration union */
typedef struct my_config MyConfig;
struct my_config
{
   LDAPUtils          * lud;
   LDAPSchema         * lsd;
   int                  action;
   uint64_t             types;
   char               ** args;
};


/////////////////
//             //
//  Variables  //
//             //
/////////////////

static struct
{
   const char *   type;
   uint64_t       flag;
   const char *   desc;
} my_obj_types[] =
{
   { "attributeTypes",  MY_OBJ_ATTR,     NULL },
   { "ldapSyntaxes",    MY_OBJ_SYNTAX,   NULL },
   { "matchingRules",   MY_OBJ_MATCHING, NULL },
   { "objectClasses",   MY_OBJ_OBJCLS,   NULL},
   { NULL, 0, NULL },
};


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Prototypes
#endif

// main statement
int main(int argc, char * argv[]);

// parses configuration
int my_config(int argc, char * argv[], MyConfig ** cnfp);

int my_run_details(MyConfig * cnf);
int my_run_dump(MyConfig * cnf);
int my_run_lint(MyConfig * cnf);
int my_run_list(MyConfig * cnf);

// fress resources
void my_unbind(MyConfig * cnf);


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Functions
#endif

/// prints program usage and exits
void ldaputils_usage(void)
{
   size_t idx;

   printf("Usage: %s [options] oid [oid ...]\n", PROGRAM_NAME);
   printf("       %s [options] --lint\n", PROGRAM_NAME);
   printf("       %s [options] --list\n", PROGRAM_NAME);
   printf("       %s [options] --dump\n", PROGRAM_NAME);
   ldaputils_usage_common(MY_SHORT_OPTIONS);
   printf("Schema options:\n");
   printf("  --dump                    list details of objects in schema\n");
   printf("  --lint                    display schema errors\n");
   printf("  --list                    list objects in schema\n");
   printf("  --type=type               restrict operations to specific object types\n");
   printf("Object types\n");
   for(idx = 0; ((my_obj_types[idx].type)); idx++)
   {
      if ((my_obj_types[idx].desc))
         printf("  %-25s %s\n", my_obj_types[idx].type, my_obj_types[idx].desc);
      else
         printf("  %s\n", my_obj_types[idx].type);
   }
   printf("\nReport bugs to <%s>.\n", PACKAGE_BUGREPORT);
   return;
}


/// main statement
/// @param[in] argc   number of arguments
/// @param[in] argv   array of arguments
int main(int argc, char * argv[])
{
   int                    err;
   MyConfig             * cnf;

   cnf = NULL;

   // initializes resources and parses CLI arguments
   if ((err = my_config(argc, argv, &cnf)) != 0)
      return(1);
   if (!(cnf))
      return(0);

   // starts TLS and binds to LDAP
   if ((err = ldaputils_bind_s(cnf->lud)) != LDAP_SUCCESS)
   {
      fprintf(stderr, "%s: ldap_sasl_bind_s(): %s\n", cnf->lud->prog_name, ldap_err2string(err));
      my_unbind(cnf);
      return(1);
   };

   // fetches schema
   if ( ((err = ldapschema_fetch(cnf->lsd, cnf->lud->ld)) != LDAP_SUCCESS) && (err != LDAPSCHEMA_SCHEMA_ERROR) )
   {
      fprintf(stderr, "%s: ldapschema_fetch(): %s\n", cnf->lud->prog_name, ldapschema_err2string(err));
      my_unbind(cnf);
      return(1);
   };

   // act as schema lint and exit
   switch(cnf->action)
   {
      case MY_ACTION_DUMP: err = my_run_dump(cnf);    break;
      case MY_ACTION_LINT: err = my_run_lint(cnf);    break;
      case MY_ACTION_LIST: err = my_run_list(cnf);    break;
      default:             err = my_run_details(cnf); break;
   };

   // frees resources
   my_unbind(cnf);

   return(err);
}


/// parses configuration
/// @param[in] argc   number of arguments
/// @param[in] argv   array of arguments
/// @param[in] cnfp   reference to configuration pointer
int my_config(int argc, char * argv[], MyConfig ** cnfp)
{
   int            c;
   int            err;
   int            option_index;
   MyConfig     * cnf;
   uint64_t       flag;
   int            i;
   size_t         idx;
   size_t         len;

   static char   short_options[] = MY_SHORT_OPTIONS "98:76";
   static struct option long_options[] =
   {
      {"schemalint",    no_argument,       0, '9'},
      {"lint",          no_argument,       0, '9'},
      {"type",          required_argument, 0, '8'},
      {"list",          no_argument,       0, '7'},
      {"dump",          no_argument,       0, '6'},
      {"help",          no_argument,       0, 'h'},
      {"verbose",       no_argument,       0, 'v'},
      {"version",       no_argument,       0, 'V'},
      {NULL,            0,                 0, 0  }
   };

   // allocates memory for configuration
   if (!(cnf = (MyConfig *) malloc(sizeof(MyConfig))))
   {
      fprintf(stderr, "%s: out of virtual memory\n", PROGRAM_NAME);
      return(1);
   };
   memset(cnf, 0, sizeof(MyConfig));

   // initialize ldap utilities
   if ((err = ldaputils_initialize(&cnf->lud, PROGRAM_NAME)) != LDAP_SUCCESS)
   {
      fprintf(stderr, "%s: ldaputils_initialize(): %s\n", PROGRAM_NAME, ldap_err2string(err));
      my_unbind(cnf);
      return(1);
   };

   // initialize ldap schema
   if ((err = ldapschema_initialize(&cnf->lsd)) != LDAP_SUCCESS)
   {
      fprintf(stderr, "%s: ldapschema_initialize(): %s\n", PROGRAM_NAME, ldapschema_err2string(err));
      my_unbind(cnf);
      return(1);
   };

   // loops through args
   option_index = 0;
   while((c = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1)
   {
      switch(ldaputils_getopt(cnf->lud, c, optarg))
      {
         // shared option exit without error
         case -2:
         my_unbind(cnf);
         return(0);

         // no more arguments
         case -1:
         break;

         // long options toggles
         case 0:
         break;

         // shared option error
         case 1:
         my_unbind(cnf);
         return(1);

         // --schemalint option
         case '9':
         if ((cnf->action))
         {
            fprintf(stderr, "%s: incompatible options `--schemalint', `--dump', and `--list'\n", PROGRAM_NAME);
            fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
            my_unbind(cnf);
            return(1);
         };
         cnf->action = MY_ACTION_LINT;
         break;

         // --type=type
         case '8':
         flag = 0;
         for(idx = 0; ((my_obj_types[idx].type)); idx++)
         {
            if ((strncasecmp(optarg, my_obj_types[idx].type, strlen(optarg))))
               continue;
            if ((flag))
            {
               fprintf(stderr, "%s: ambiguous type -- \"%s\"\n", PROGRAM_NAME, optarg);
               fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
               my_unbind(cnf);
               return(1);
            };
            flag = my_obj_types[idx].flag;
         };
         if (!(flag))
         {
            fprintf(stderr, "%s: unknown type -- \"%s\"\n", PROGRAM_NAME, optarg);
            fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
            my_unbind(cnf);
            return(1);
         };
         cnf->types |= flag;
         break;

         // --list
         case '7':
         if ((cnf->action))
         {
            fprintf(stderr, "%s: incompatible options `--schemalint', `--dump', and `--list'\n", PROGRAM_NAME);
            fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
            my_unbind(cnf);
            return(1);
         };
         cnf->action = MY_ACTION_LIST;
         break;

         // --dump option
         case '6':
         if ((cnf->action))
         {
            fprintf(stderr, "%s: incompatible options `--schemalint', `--dump', and `--list'\n", PROGRAM_NAME);
            fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
            my_unbind(cnf);
            return(1);
         };
         cnf->action = MY_ACTION_DUMP;
         break;

         // argument error
         case '?':
         fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
         my_unbind(cnf);
         return(1);

         // unknown argument error
         default:
         fprintf(stderr, "%s: unrecognized option `--%c'\n", PROGRAM_NAME, c);
         fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
         my_unbind(cnf);
         return(1);
      };
   };

   if ( (argc < (optind+1)) && (!(cnf->action)) )
   {
      fprintf(stderr, "%s: missing required options or arguments\n", PROGRAM_NAME);
      fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
      my_unbind(cnf);
      return(1);
   };
   if ( (argc > optind) && ((cnf->action)) )
   {
      fprintf(stderr, "%s: incompatible arguments `--list', `--dump', `--lint', and `%s'\n", PROGRAM_NAME, argv[optind]);
      fprintf(stderr, "Try `%s --help' for more information.\n", PROGRAM_NAME);
      my_unbind(cnf);
      return(1);
   };

   if (!(cnf->types))
      cnf->types = 0xffffffff;

   // copies arguments
   if (argc > optind)
   {
      len = (size_t)(argc-optind);
      if ((cnf->args = malloc(sizeof(char *)*(size_t)(len+2))) == NULL)
         return(1);
      bzero(cnf->args, (sizeof(char*)*(len+2)));

      for(i = 0; (argc > (optind+i)); i++)
         cnf->args[i] = argv[optind+i];
      cnf->args[i] = NULL;
   };

   // reads password
   if ((err = ldaputils_pass(cnf->lud)) != 0)
   {
      my_unbind(cnf);
      return(1);
   };

   *cnfp = cnf;

   return(0);
}


int my_run_details(MyConfig * cnf)
{
   size_t                     idx;
   LDAPSchemaSyntax         * syntax;
   LDAPSchemaAttributeType  * attr;
   LDAPSchemaAttributeType  * attrsup;
   LDAPSchemaObjectclass    * objcls;
   LDAPSchemaObjectclass    * objclssup;

   for(idx = 0; ((cnf->args[idx])); idx++)
   {
      // look for matching ldapSyntax
      if ((syntax = ldapschema_find_ldapsyntax(cnf->lsd, cnf->args[idx])) != NULL)
      {
         ldapschema_print_ldapsyntax(cnf->lsd, syntax);
         printf("\n\n");
      };

      // look for matching attributeType
      if ((attr = ldapschema_find_attributetype(cnf->lsd, cnf->args[idx])) != NULL)
      {
         ldapschema_print_attributetype(cnf->lsd, attr);
         ldapschema_get_info_attributetype(cnf->lsd, attr, LDAPSCHEMA_FLD_SUPERIOR, &attrsup);
         printf("\n\n");
         while ((attrsup))
         {
            attr = attrsup;
            ldapschema_print_attributetype(cnf->lsd, attr);
            ldapschema_get_info_attributetype(cnf->lsd, attr, LDAPSCHEMA_FLD_SUPERIOR, &attrsup);
            printf("\n\n");
         };
      };

      // look for matching attributeType
      if ((objcls = ldapschema_find_objectclass(cnf->lsd, cnf->args[idx])) != NULL)
      {
         ldapschema_print_objectclass(cnf->lsd, objcls);
         ldapschema_get_info_objectclass(cnf->lsd, objcls, LDAPSCHEMA_FLD_SUPERIOR, &objclssup);
         printf("\n\n");
         while ((objclssup))
         {
            objcls = objclssup;
            ldapschema_print_objectclass(cnf->lsd, objcls);
            ldapschema_get_info_objectclass(cnf->lsd, objcls, LDAPSCHEMA_FLD_SUPERIOR, &objclssup);
            printf("\n\n");
         };
      };
   };

   return(0);
}


int my_run_dump(MyConfig * cnf)
{
   if ((cnf->types & MY_OBJ_SYNTAX) != 0)
      ldapschema_print_ldapsyntaxes(cnf->lsd);

   if ((cnf->types & MY_OBJ_ATTR) != 0)
      ldapschema_print_attributetypes(cnf->lsd);

   if ((cnf->types & MY_OBJ_OBJCLS) != 0)
      ldapschema_print_objectclasses(cnf->lsd);

   return(0);
}



int my_run_lint(MyConfig * cnf)
{
   int         err;
   char     ** errs;
   size_t      pos;

   if ((err = ldapschema_errno(cnf->lsd)) == LDAPSCHEMA_SUCCESS)
   {
      printf("no schema errors detected\n");
      return(0);
   };

   if ((errs = ldapschema_schema_errors(cnf->lsd)) == NULL)
   {
      printf("unknown schema error detected\n");
      return(MY_EXIT_SCHEMAERR);
   };

   for(pos = 0; ((errs[pos])); pos++)
      printf("schema error %zu: %s\n", (pos+1), errs[pos]);
   ldapschema_value_free(errs);

   return(MY_EXIT_SCHEMAERR);
}


int my_run_list(MyConfig * cnf)
{
   size_t                              idx;
   LDAPSchemaCur                       cur;
   const LDAPSchemaAttributeType     * attr;
   const LDAPSchemaObjectclass       * objcls;
   const LDAPSchemaSyntax            * syntax;
   char                              * oid;
   char                              * desc;
   char                             ** names;

   if ((cnf->types & MY_OBJ_SYNTAX) != 0)
   {
      cur = NULL;
      syntax = ldapschema_first_ldapsyntax(cnf->lsd, &cur);
      while ((syntax))
      {
         ldapschema_get_info_ldapsyntax(cnf->lsd, syntax, LDAPSCHEMA_FLD_OID,  &oid);
         ldapschema_get_info_ldapsyntax(cnf->lsd, syntax, LDAPSCHEMA_FLD_DESC, &desc);
         printf("ldapsyntax: %s   DESC ( %s )\n", oid, desc);
         ldapschema_memfree(oid);
         ldapschema_memfree(desc);
         syntax = ldapschema_next_ldapsyntax(cnf->lsd, cur);
      };
      ldapschema_curfree(cur);
   };

   if ((cnf->types & MY_OBJ_ATTR) != 0)
   {
      cur = NULL;
      attr = ldapschema_first_attributetype(cnf->lsd, &cur);
      while ((attr))
      {
         ldapschema_get_info_attributetype(cnf->lsd, attr, LDAPSCHEMA_FLD_OID,  &oid);
         ldapschema_get_info_attributetype(cnf->lsd, attr, LDAPSCHEMA_FLD_NAME, &names);
         printf("attributeType: %s  NAME ( %s", oid, names[0]);
         for(idx = 1; ((names[idx])); idx++)
            printf(" $ %s", names[idx]);
         printf(" )\n");
         ldapschema_memfree(oid);
         ldapschema_memfree(names);
         attr = ldapschema_next_attributetype(cnf->lsd, cur);
      };
      ldapschema_curfree(cur);
   };

   if ((cnf->types & MY_OBJ_OBJCLS) != 0)
   {
      cur = NULL;
      objcls = ldapschema_first_objectclass(cnf->lsd, &cur);
      while ((objcls))
      {
         ldapschema_get_info_objectclass(cnf->lsd, objcls, LDAPSCHEMA_FLD_OID,  &oid);
         ldapschema_get_info_objectclass(cnf->lsd, objcls, LDAPSCHEMA_FLD_NAME, &names);
         printf("objectClass: %s  NAME ( %s", oid, names[0]);
         for(idx = 1; ((names[idx])); idx++)
            printf(" $ %s", names[idx]);
         printf(" )\n");
         ldapschema_memfree(oid);
         ldapschema_memfree(names);
         objcls = ldapschema_next_objectclass(cnf->lsd, cur);
      };
      ldapschema_curfree(cur);
   };

   return(0);
}


// fress resources
void my_unbind(MyConfig * cnf)
{
   assert(cnf != NULL);

   if ((cnf->lud))
      ldaputils_unbind(cnf->lud);

   if ((cnf->lsd))
      ldapschema_free(cnf->lsd);

   if ((cnf->args))
      free(cnf->args);

   free(cnf);

   return;
}

/* end of source file */
