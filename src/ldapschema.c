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
#define MY_EXIT_NOT_FOUND     3

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
   int                  noextra;
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

int my_list_add(LDAPSchemaModel *** listp, size_t * lenp, LDAPSchemaModel * mod);
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
   printf("  --noextra                 do not include related objects or data\n");
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
      {"noextra",       no_argument,       0, '5'},
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

         // --noextra option
         case '5':
         cnf->noextra++;
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


int my_list_add(LDAPSchemaModel *** listp, size_t * lenp, LDAPSchemaModel * mod)
{
   void *               ptr;
   size_t               idx;

   if (!(mod))
      return(0);

   for(idx = 0; (idx < (*lenp)); idx++)
      if (!(ldapschema_compar_models(&mod, &listp[0][idx])))
         return(0);

   if ((ptr = realloc(*listp, (sizeof(LDAPSchemaModel *)*(*lenp +2)))) == NULL)
   {
      fprintf(stderr, "%s: out of virtual memory\n", PROGRAM_NAME);
      return(1);
   };
   *listp            = ptr;
   listp[0][*lenp]   = mod;
   (*lenp)++;
   listp[0][*lenp]   = NULL;

   return(0);
}


int my_run_details(MyConfig * cnf)
{
   size_t                     idx;
   size_t                     list_len;
   LDAPSchemaModel         ** list;
   LDAPSchemaSyntax         * syntax;
   LDAPSchemaAttributeType  * attr;
   LDAPSchemaAttributeType  * attrsup;
   LDAPSchemaObjectclass    * objcls;
   LDAPSchemaObjectclass    * objclssup;
   LDAPSchemaMatchingRule   * mtchngrl;

   list     = NULL;
   list_len = 0;

   // look for matching ldapSyntax
   for(idx = 0; ((cnf->args[idx])); idx++)
      if ((syntax = ldapschema_find_ldapsyntax(cnf->lsd, cnf->args[idx])) != NULL)
         my_list_add(&list, &list_len, (LDAPSchemaModel *)syntax);

   // look for matching matchingRules and add ldapSyntax
   for(idx = 0; ((cnf->args[idx])); idx++)
   {
      if ((mtchngrl = ldapschema_find_matchingrule(cnf->lsd, cnf->args[idx])) == NULL)
         continue;
      ldapschema_get_info_matchingrule(cnf->lsd, mtchngrl, LDAPSCHEMA_FLD_SYNTAX, &syntax);
      my_list_add(&list, &list_len, (LDAPSchemaModel *)syntax);
   };

   // look for matching attributeType and add syntaxes
   for(idx = 0; (((cnf->args[idx])) && (!(cnf->noextra))); idx++)
   {
      if ((attr = ldapschema_find_attributetype(cnf->lsd, cnf->args[idx])) == NULL)
         continue;
      ldapschema_get_info_attributetype(cnf->lsd, attr, LDAPSCHEMA_FLD_SYNTAX,   &syntax);
      my_list_add(&list, &list_len, (LDAPSchemaModel *)syntax);
      ldapschema_get_info_attributetype(cnf->lsd, attr, LDAPSCHEMA_FLD_SUPERIOR, &attrsup);
      while ((attrsup))
      {
         attr = attrsup;
         ldapschema_get_info_attributetype(cnf->lsd, attr, LDAPSCHEMA_FLD_SYNTAX,   &syntax);
         my_list_add(&list, &list_len, (LDAPSchemaModel *)syntax);
         ldapschema_get_info_attributetype(cnf->lsd, attr, LDAPSCHEMA_FLD_SUPERIOR, &attrsup);
      };
   };

   // look for matching attributeType and add matchingRules
   for(idx = 0; (((cnf->args[idx])) && (!(cnf->noextra))); idx++)
   {
      if ((attr = ldapschema_find_attributetype(cnf->lsd, cnf->args[idx])) == NULL)
         continue;

      // add syntaxes
      ldapschema_get_info_attributetype(cnf->lsd, attr, LDAPSCHEMA_FLD_EQUALITY,   &mtchngrl);
      if ((mtchngrl))
      {
         ldapschema_get_info_matchingrule(cnf->lsd, mtchngrl, LDAPSCHEMA_FLD_SYNTAX, &syntax);
         my_list_add(&list, &list_len, (LDAPSchemaModel *)syntax);
      };

      ldapschema_get_info_attributetype(cnf->lsd, attr, LDAPSCHEMA_FLD_ORDERING,   &mtchngrl);
      if ((mtchngrl))
      {
         ldapschema_get_info_matchingrule(cnf->lsd, mtchngrl, LDAPSCHEMA_FLD_SYNTAX, &syntax);
         my_list_add(&list, &list_len, (LDAPSchemaModel *)syntax);
      };

      ldapschema_get_info_attributetype(cnf->lsd, attr, LDAPSCHEMA_FLD_SUBSTR,   &mtchngrl);
      if ((mtchngrl))
      {
         ldapschema_get_info_matchingrule(cnf->lsd, mtchngrl, LDAPSCHEMA_FLD_SYNTAX, &syntax);
         my_list_add(&list, &list_len, (LDAPSchemaModel *)syntax);
      };

      // add matching rules
      ldapschema_get_info_attributetype(cnf->lsd, attr, LDAPSCHEMA_FLD_EQUALITY,   &mtchngrl);
      my_list_add(&list, &list_len, (LDAPSchemaModel *)mtchngrl);

      ldapschema_get_info_attributetype(cnf->lsd, attr, LDAPSCHEMA_FLD_ORDERING,   &mtchngrl);
      my_list_add(&list, &list_len, (LDAPSchemaModel *)mtchngrl);

      ldapschema_get_info_attributetype(cnf->lsd, attr, LDAPSCHEMA_FLD_SUBSTR,   &mtchngrl);
      my_list_add(&list, &list_len, (LDAPSchemaModel *)mtchngrl);
   };

   // look for matching matchingRule
   for(idx = 0; ((cnf->args[idx])); idx++)
      if ((mtchngrl = ldapschema_find_matchingrule(cnf->lsd, cnf->args[idx])) != NULL)
         my_list_add(&list, &list_len, (LDAPSchemaModel *)mtchngrl);

   // look for matching attributeType and add attributes
   for(idx = 0; (((cnf->args[idx])) && (!(cnf->noextra))); idx++)
   {
      if ((attr = ldapschema_find_attributetype(cnf->lsd, cnf->args[idx])) == NULL)
         continue;
      ldapschema_get_info_attributetype(cnf->lsd, attr, LDAPSCHEMA_FLD_SUPERIOR, &attrsup);
      while ((attrsup))
      {
         attr = attrsup;
         my_list_add(&list, &list_len, (LDAPSchemaModel *)attr);
         ldapschema_get_info_attributetype(cnf->lsd, attr, LDAPSCHEMA_FLD_SUPERIOR, &attrsup);
      };
   };
   for(idx = 0; ((cnf->args[idx])); idx++)
      if ((attr = ldapschema_find_attributetype(cnf->lsd, cnf->args[idx])) != NULL)
         my_list_add(&list, &list_len, (LDAPSchemaModel *)attr);

   // look for matching objectclasses
   for(idx = 0; (((cnf->args[idx])) && (!(cnf->noextra))); idx++)
   {
      if ((objcls = ldapschema_find_objectclass(cnf->lsd, cnf->args[idx])) == NULL)
         continue;
      ldapschema_get_info_objectclass(cnf->lsd, objcls, LDAPSCHEMA_FLD_SUPERIOR, &objclssup);
      while ((objclssup))
      {
         objcls = objclssup;
         my_list_add(&list, &list_len, (LDAPSchemaModel *)objcls);
         ldapschema_get_info_objectclass(cnf->lsd, objcls, LDAPSCHEMA_FLD_SUPERIOR, &objclssup);
      };
   };
   for(idx = 0; ((cnf->args[idx])); idx++)
      if ((objcls = ldapschema_find_objectclass(cnf->lsd, cnf->args[idx])) != NULL)
         my_list_add(&list, &list_len, (LDAPSchemaModel *)objcls);

   // print results
   for(idx = 0; (idx < list_len); idx++)
   {
      ldapschema_print(cnf->lsd, list[idx]);
      printf("\n\n");
   };

   return(0);
}


int my_run_dump(MyConfig * cnf)
{
   if ((cnf->types & MY_OBJ_SYNTAX) != 0)
      ldapschema_printall(cnf->lsd, LDAPSCHEMA_SYNTAX);

   if ((cnf->types & MY_OBJ_MATCHING) != 0)
      ldapschema_printall(cnf->lsd, LDAPSCHEMA_MATCHINGRULE);

   if ((cnf->types & MY_OBJ_ATTR) != 0)
      ldapschema_printall(cnf->lsd, LDAPSCHEMA_ATTRIBUTETYPE);

   if ((cnf->types & MY_OBJ_OBJCLS) != 0)
      ldapschema_printall(cnf->lsd, LDAPSCHEMA_OBJECTCLASS);

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
      printf("%s\n", errs[pos]);
   ldapschema_value_free(errs);

   printf("%zu issues reported\n", pos);

   return(MY_EXIT_SCHEMAERR);
}


int my_run_list(MyConfig * cnf)
{
   size_t                              idx;
   LDAPSchemaCur                       cur;
   const LDAPSchemaAttributeType *     attr;
   const LDAPSchemaObjectclass *       objcls;
   const LDAPSchemaSyntax *            syntax;
   const LDAPSchemaMatchingRule *      rule;
   char *                              oid;
   char *                              desc;
   char **                             names;
   char                                buff[256];
   size_t                              len;

   if ((cnf->types & MY_OBJ_SYNTAX) != 0)
   {
      cur = NULL;
      syntax = ldapschema_first_ldapsyntax(cnf->lsd, &cur);
      while ((syntax))
      {
         ldapschema_get_info_ldapsyntax(cnf->lsd, syntax, LDAPSCHEMA_FLD_OID,  &oid);
         ldapschema_get_info_ldapsyntax(cnf->lsd, syntax, LDAPSCHEMA_FLD_DESC, &desc);
         if ((desc))
         {
            printf("%-15s %-35s DESC ( %s )\n", "ldapsyntax:", oid, desc);
            ldapschema_memfree(desc);
         } else
         {
            printf("%-15s %s\n", "ldapsyntax:", oid);
         };
         ldapschema_memfree(oid);
         syntax = ldapschema_next_ldapsyntax(cnf->lsd, cur);
      };
      ldapschema_curfree(cur);
   };

   if ((cnf->types & MY_OBJ_MATCHING) != 0)
   {
      cur = NULL;
      rule = ldapschema_first_matchingrule(cnf->lsd, &cur);
      while ((rule))
      {
         ldapschema_get_info_matchingrule(cnf->lsd, rule, LDAPSCHEMA_FLD_OID,  &oid);
         ldapschema_get_info_matchingrule(cnf->lsd, rule, LDAPSCHEMA_FLD_NAME, &names);
         if ((names))
         {
            printf("%-15s %-35s NAME ( %s", "matchingRule:", oid, names[0]);
            for(idx = 1; ((names[idx])); idx++)
               printf(" $ %s", names[idx]);
            printf(" )\n");
            ldapschema_value_free(names);
         } else
         {
            printf("%-15s %-35s", "matchingRule:", oid);
         };
         ldapschema_memfree(oid);
         rule = ldapschema_next_matchingrule(cnf->lsd, cur);
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
         ldapschema_get_info_attributetype(cnf->lsd, attr, LDAPSCHEMA_FLD_SYNTAX, &syntax);
         buff[0] = '\0';
         if ((names))
         {
            snprintf(buff, sizeof(buff), "( %s", names[0]);
            for(idx = 1; ((names[idx])); idx++)
            {
               len = strlen(buff);
               snprintf(&buff[len], (sizeof(buff)-len-2), " $ %s", names[idx]);
            };
            len = strlen(buff);
            snprintf(&buff[len], (sizeof(buff)-len-2), " )");
            ldapschema_memfree(names);
         };
         if ( ((syntax)) && (!(cnf->noextra)) )
            printf("%-15s %-35s NAME %-30s", "attributeType:", oid, buff);
         else
            printf("%-15s %-35s NAME %s", "attributeType:", oid, buff);
         ldapschema_memfree(oid);
         if ( ((syntax)) && (!(cnf->noextra)) )
         {
            ldapschema_get_info_ldapsyntax(cnf->lsd, syntax, LDAPSCHEMA_FLD_DESC, &desc);
            printf("   [ %s ]", desc);
            ldapschema_memfree(desc);
         };
         printf("\n");
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
         if ((names))
         {
            printf("%-15s %-35s NAME ( %s", "objectClass:", oid, names[0]);
            for(idx = 1; ((names[idx])); idx++)
               printf(" $ %s", names[idx]);
            printf(" )\n");
            ldapschema_memfree(names);
         } else
         {
            printf("%-15s %-35s", "objectClass:", oid);
         };
         ldapschema_memfree(oid);
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
