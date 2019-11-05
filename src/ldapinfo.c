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
 *  @file src/ldapinfo.c export LDAP data to CSV file
 */
/*
 *  Simple Build:
 *     export CFLAGS='-DPROGRAM_NAME="ldapinfo" -Wall -I../include'
 *     gcc ${CFLAGS} -c ldapinfo.c
 *     gcc ${CFLAGS} -lldap -o ldapinfo ldapinfo.o ../lib/libldaputils.a
 *
 *  Libtool Build:
 *     export CFLAGS='-DPROGRAM_NAME="ldapinfo" -Wall -I../include'
 *     libtool --mode=compile --tag=CC gcc ${CFLAGS} -c ldapinfo.c
 *     libtool --mode=link    --tag=CC gcc ${CFLAGS} -lldap -o ldapinfo \
 *             ldapinfo.lo ../lib/libldaputils.a
 *
 *  Libtool Clean:
 *     libtool --mode=clean rm -f ldapinfo.lo ldapinfo
 */
#define _LDAP_UTILS_SRC_LDAPINFO 1

///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

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


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#pragma mark - Definitions

#ifndef PROGRAM_NAME
#define PROGRAM_NAME "ldapinfo"
#endif

#define MY_SHORT_OPTIONS LDAPUTILS_OPTIONS_COMMON LDAPUTILS_OPTIONS_SEARCH "o:"


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#pragma mark - Datatypes

// configuration union
typedef struct my_config MyConfig;
struct my_config
{
   LDAPUtils   * lud;
   const char  * filter;
   const char  * prog_name;
   const char ** defvals;
   char          output[LDAPUTILS_OPT_LEN];
};


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

static const char * ldapinfo_attrs[] =
{
   "attributeTypes",
   "ldapSyntaxes",
   "matchingRuleUse",
   "matchingRules",
   "objectClasses",
   "dITContentRules",
   "dITStructureRules",
   "nameForms",
   "cn",
   "objectclass",
   "configContext",
   "isGlobalCatalogReady",
   "monitorContext",
   "monitorCounter",
   "monitoredInfo",
   "monitorOverlay",
   "monitorUpdateRef",
   "namingContexts",
   "objectclass",
   "readOnly",
   "subschemaSubentry",
   "supportedControl",
   "supportedExtension",
   "supportedFeatures",
   "supportedLDAPVersion",
   "supportedSASLMechanisms",
   "vendorVersion",
   "vendorName",
   "monitorConnectionLocalAddress",
   "labeledURI",
   NULL
};


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

// main statement
int main(int argc, char * argv[]);

// parses configuration
int my_config(int argc, char * argv[], MyConfig ** cnfp);

void my_field(const char * name, const char * val);

void my_fields(const char * name, char ** vals);

int my_monitor_connections(MyConfig * cnf, const char * base);

int my_monitor_database(MyConfig * cnf, const char * base);

int my_monitor_listeners(MyConfig * cnf, const char * base);

int my_monitor_operations(MyConfig * cnf, const char * base);

// parses RootDSE
int my_rootdse(MyConfig * cnf);

int my_results(MyConfig * cnf, LDAPMessage * res);

int my_schema(MyConfig * cnf, const char * base);

// fress resources
void my_unbind(MyConfig * cnf);


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

/// prints program usage and exits
void ldaputils_usage(void)
{
   printf("Usage: %s [options]\n", PROGRAM_NAME);
   ldaputils_usage_common(MY_SHORT_OPTIONS);
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
      fprintf(stderr, "%s: ldap_sasl_bind_s(): %s\n", ldaputils_get_prog_name(cnf->lud), ldap_err2string(err));
      my_unbind(cnf);
      return(1);
   };

   // processes root DSE
   if ((err = my_rootdse(cnf)) == -1)
   {
      my_unbind(cnf);
      return(1);
   };

   my_unbind(cnf);

   return(0);
}


/// parses configuration
/// @param[in] argc   number of arguments
/// @param[in] argv   array of arguments
/// @param[in] cnfp   reference to configuration pointer
int my_config(int argc, char * argv[], MyConfig ** cnfp)
{
   int         c;
   size_t      s;
   size_t      len;
   int         err;
   int         option_index;
   MyConfig  * cnf;

   static char   short_options[] = MY_SHORT_OPTIONS;
   static struct option long_options[] =
   {
      {"help",          no_argument, 0, 'h'},
      {"verbose",       no_argument, 0, 'v'},
      {"version",       no_argument, 0, 'V'},
      {NULL,            0,           0, 0  }
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

   cnf->prog_name = ldaputils_get_prog_name(cnf->lud);

   // checks for required arguments
   if (argc != optind)
   {
      fprintf(stderr, "%s: unknown arguments\n", cnf->prog_name);
      fprintf(stderr, "Try `%s --help' for more information.\n", cnf->prog_name);
      my_unbind(cnf);
      return(1);
   };

   // saves filter
   cnf->lud->filter = "(objectclass=*)";

   // configures LDAP attributes to return in results
   for(len = 0; ((ldapinfo_attrs[len])); len++);
   if ((cnf->lud->attrs = (char **) malloc(sizeof(char *) * (len+1))) == NULL)
   {
      fprintf(stderr, "%s: out of virtual memory\n", cnf->prog_name);
      my_unbind(cnf);
      return(1);
   };
   bzero(cnf->lud->attrs, sizeof(char *) * (len+1));
   for(s = 0; s < len; s++)
   {
      if ((cnf->lud->attrs[s] = strdup(ldapinfo_attrs[s])) == NULL)
      {
         fprintf(stderr, "%s: out of virtual memory\n", cnf->prog_name);
         my_unbind(cnf);
         return(1);
      };
   };
   cnf->lud->attrs[s] = NULL;

   // reads password
   if ((err = ldaputils_pass(cnf->lud)) != 0)
   {
      my_unbind(cnf);
      return(1);
   };

   *cnfp = cnf;

   return(0);
}


void my_field(const char * name, const char * val)
{
   if (!(name))
      name = "";
   printf("%-28s %s\n", name, val);
   return;
}


void my_fields(const char * name, char ** vals)
{
   size_t x;
   if (!(vals))
   {
      my_field(name, NULL);
      return;
   };
   my_field(name, vals[0]);
   for(x = 1; ((vals[x])); x++)
      my_field(NULL, vals[x]);
   return;
}


int my_monitor_connections(MyConfig * cnf, const char * base)
{
   int               rc;
   int               err;
   int               msgid;
   int               count;
   char           ** name;
   char           ** vals;
   char              dn[256];
   LDAP            * ld;
   LDAPMessage     * res;
   LDAPMessage     * msg;
   struct timeval    timeout;

   ld  = cnf->lud->ld;

   // searches for cn=Connections,<monitor>
   timeout.tv_sec  = 5;
   timeout.tv_usec = 0;
   strncpy(dn, "cn=Connections,", sizeof(dn));
   strncat(dn, base, (sizeof(dn)-strlen(dn)-1));
   if ((err = ldap_search_ext(ld, dn, LDAP_SCOPE_ONE, "(objectclass=*)", cnf->lud->attrs, 0, NULL, NULL, &timeout, -1, &msgid)) != LDAP_SUCCESS)
      return(-1);
   if ((err = ldap_result(ld, msgid, LDAP_MSG_ALL, NULL, &res)) < 1)
      return(-1);

   // parses result
   rc = ldap_parse_result(ld, res, &err, NULL, NULL, NULL, NULL, 0);
   if ((rc != LDAP_SUCCESS) || (err != LDAP_SUCCESS))
   {
      ldap_msgfree(res);
      return(-1);
   };

   // retrieves entry
   count = 0;
   msg   = ldap_first_entry(ld, res);
   while ((msg))
   {
      if ((name = ldap_get_values(ld, msg, "cn")) == NULL)
      {
         msg = ldap_next_entry(ld, msg);
         continue;
      };
      if (!(name[0][0]))
      {
         ldap_value_free(name);
         msg = ldap_next_entry(ld, msg);
         continue;
      };

      vals = ldap_get_values(ld, msg, "monitorCounter");

      if (!(strcasecmp(name[0], "Current")))
         my_field("Current connections:", vals[0]);
      else if (!(strcasecmp(name[0], "Total")))
         my_field("Total connections:", vals[0]);
      else if (!(strcasecmp(name[0], "Max File Descriptors")))
         my_field("Max File Descriptors:", vals[0]);

      if ((name))
         ldap_value_free(name);
      if ((vals))
         ldap_value_free(vals);

      // retrieves next entry
      msg = ldap_next_entry(ld, msg);
   };

   printf("\n");

   return(0);
}


int my_monitor_database(MyConfig * cnf, const char * base)
{
   int               rc;
   int               err;
   int               msgid;
   int               count;
   size_t            s;
   char           ** vals;
   char              dn[256];
   char              buff[256];
   LDAP            * ld;
   LDAPMessage     * res;
   LDAPMessage     * msg;
   struct timeval    timeout;

   ld  = cnf->lud->ld;

   // searches for cn=Databases,cn=monitor
   timeout.tv_sec  = 5;
   timeout.tv_usec = 0;
   strncpy(dn, "cn=Databases,", sizeof(dn));
   strncat(dn, base, (sizeof(dn)-strlen(dn)-1));
   if ((err = ldap_search_ext(ld, dn, LDAP_SCOPE_ONE, "(objectclass=*)", cnf->lud->attrs, 0, NULL, NULL, &timeout, -1, &msgid)) != LDAP_SUCCESS)
      return(-1);
   if ((err = ldap_result(ld, msgid, LDAP_MSG_ALL, NULL, &res)) < 1)
      return(-1);

   // parses result
   rc = ldap_parse_result(ld, res, &err, NULL, NULL, NULL, NULL, 0);
   if ((rc != LDAP_SUCCESS) || (err != LDAP_SUCCESS))
   {
      ldap_msgfree(res);
      return(-1);
   };

   // retrieves entry
   count = 0;
   msg   = ldap_first_entry(ld, res);
   while ((msg))
   {
      if ((vals = ldap_get_values(ld, msg, "namingContexts")) == NULL)
      {
         msg = ldap_next_entry(ld, msg);
         continue;
      };
      if (!(vals[0][0]))
      {
         msg = ldap_next_entry(ld, msg);
         continue;
      };
      strncpy(buff, vals[0], sizeof(buff));
      ldap_value_free(vals);

      if ((vals = ldap_get_values(ld, msg, "monitoredInfo")) != NULL)
      {
         strncat(buff, " (", sizeof(buff)-strlen(buff)-1);
         strncat(buff, vals[0], sizeof(buff)-strlen(buff)-1);
         strncat(buff, ")", sizeof(buff)-strlen(buff)-1);
         ldap_value_free(vals);
      };

      if ((vals = ldap_get_values(ld, msg, "monitorOverlay")) != NULL)
      {
         strncat(buff, " [", sizeof(buff)-strlen(buff)-1);
         for(s = 0; ((vals[s])); s++)
         {
            strncat(buff, " ", sizeof(buff)-strlen(buff)-1);
            strncat(buff, vals[s], sizeof(buff)-strlen(buff)-1);
         };
         strncat(buff, " ]", sizeof(buff)-strlen(buff)-1);
         ldap_value_free(vals);
      };

      my_field(((count)) ? NULL : "Naming contexts:", buff);
      count++;

      // retrieves next entry
      msg = ldap_next_entry(ld, msg);
   };

   return(0);
}


int my_monitor_listeners(MyConfig * cnf, const char * base)
{
   int               rc;
   int               err;
   int               msgid;
   int               count;
   char           ** cn;
   char           ** initiated;
   char           ** completed;
   char              dn[256];
   char              buff[256];
   LDAP            * ld;
   LDAPMessage     * res;
   LDAPMessage     * msg;
   struct timeval    timeout;

   ld  = cnf->lud->ld;

   // searches for cn=Connections,<monitor>
   timeout.tv_sec  = 5;
   timeout.tv_usec = 0;
   strncpy(dn, "cn=Operations,", sizeof(dn));
   strncat(dn, base, (sizeof(dn)-strlen(dn)-1));
   if ((err = ldap_search_ext(ld, dn, LDAP_SCOPE_ONE, "(objectclass=*)", cnf->lud->attrs, 0, NULL, NULL, &timeout, -1, &msgid)) != LDAP_SUCCESS)
      return(-1);
   if ((err = ldap_result(ld, msgid, LDAP_MSG_ALL, NULL, &res)) < 1)
      return(-1);

   // parses result
   rc = ldap_parse_result(ld, res, &err, NULL, NULL, NULL, NULL, 0);
   if ((rc != LDAP_SUCCESS) || (err != LDAP_SUCCESS))
   {
      ldap_msgfree(res);
      return(-1);
   };

   // retrieves entry
   count = 0;
   msg   = ldap_first_entry(ld, res);
   while ((msg))
   {
      if ((cn = ldap_get_values(ld, msg, "cn")) == NULL)
      {
         msg = ldap_next_entry(ld, msg);
         continue;
      };
      if (!(cn[0][0]))
      {
         ldap_value_free(cn);
         msg = ldap_next_entry(ld, msg);
         continue;
      };

      if ((initiated = ldap_get_values(ld, msg, "monitorOpInitiated")) == NULL)
      {
         ldap_value_free(cn);
         msg = ldap_next_entry(ld, msg);
         continue;
      };
      if (!(initiated[0][0]))
      {
         ldap_value_free(cn);
         ldap_value_free(initiated);
         msg = ldap_next_entry(ld, msg);
         continue;
      };

      if ((completed = ldap_get_values(ld, msg, "monitorOpCompleted")) == NULL)
      {
         ldap_value_free(cn);
         ldap_value_free(initiated);
         msg = ldap_next_entry(ld, msg);
         continue;
      };
      if (!(completed[0][0]))
      {
         ldap_value_free(cn);
         ldap_value_free(completed);
         ldap_value_free(initiated);
         msg = ldap_next_entry(ld, msg);
         continue;
      };

      snprintf(buff, sizeof(buff), "%s initiated: %s; completed %s", cn[0], initiated[0], completed[0]);
      if (!(count))
         my_field("Operations:", buff);
      else
         my_field(NULL, buff);
      count++;

      ldap_value_free(cn);
      ldap_value_free(initiated);
      ldap_value_free(completed);

      // retrieves next entry
      msg = ldap_next_entry(ld, msg);
   };

   printf("\n");

   return(0);
}


int my_monitor_operations(MyConfig * cnf, const char * base)
{
   int               rc;
   int               err;
   int               msgid;
   int               count;
   char            * uri;
   char           ** uris;
   char            * addr;
   char           ** addrs;
   char              dn[256];
   char              buff[256];
   LDAP            * ld;
   LDAPMessage     * res;
   LDAPMessage     * msg;
   struct timeval    timeout;

   ld  = cnf->lud->ld;

   // searches for cn=Connections,<monitor>
   timeout.tv_sec  = 5;
   timeout.tv_usec = 0;
   strncpy(dn, "cn=Operations,", sizeof(dn));
   strncat(dn, base, (sizeof(dn)-strlen(dn)-1));
   if ((err = ldap_search_ext(ld, dn, LDAP_SCOPE_ONE, "(objectclass=*)", cnf->lud->attrs, 0, NULL, NULL, &timeout, -1, &msgid)) != LDAP_SUCCESS)
      return(-1);
   if ((err = ldap_result(ld, msgid, LDAP_MSG_ALL, NULL, &res)) < 1)
      return(-1);

   // parses result
   rc = ldap_parse_result(ld, res, &err, NULL, NULL, NULL, NULL, 0);
   if ((rc != LDAP_SUCCESS) || (err != LDAP_SUCCESS))
   {
      ldap_msgfree(res);
      return(-1);
   };

   // retrieves entry
   count = 0;
   msg   = ldap_first_entry(ld, res);
   while ((msg))
   {
      if ((uris = ldap_get_values(ld, msg, "labeledURI")) == NULL)
      {
         msg = ldap_next_entry(ld, msg);
         continue;
      };
      if (!(uris[0][0]))
      {
         ldap_value_free(uris);
         msg = ldap_next_entry(ld, msg);
         continue;
      };

      if ((addrs = ldap_get_values(ld, msg, "monitorConnectionLocalAddress")) == NULL)
      {
         ldap_value_free(uris);
         msg = ldap_next_entry(ld, msg);
         continue;
      };
      if (!(addrs[0][0]))
      {
         ldap_value_free(addrs);
         ldap_value_free(uris);
         msg = ldap_next_entry(ld, msg);
         continue;
      };

      if ((addr = rindex(addrs[0], '=')) == NULL)
      {
         ldap_value_free(addrs);
         ldap_value_free(uris);
         msg = ldap_next_entry(ld, msg);
         continue;
      };
      addr++;
      uri = index(uris[0], '/');
      if ((uri != NULL))
         uri = &uri[2];
      if ((uri))
      {
         uri[0] = '\0';
         snprintf(buff, sizeof(buff), "%s%s", uris[0], addr);
         if (!(count))
            my_field("Listeners:", buff);
         else
            my_field(NULL, buff);
         count++;
      };

      ldap_value_free(addrs);
      ldap_value_free(uris);

      // retrieves next entry
      msg = ldap_next_entry(ld, msg);
   };

   printf("\n");

   return(0);
}


// parses RootDSE
int my_rootdse(MyConfig * cnf)
{
   int               rc;
   int               err;
   int               msgid;
   size_t            s;
   char           ** monitor;
   char           ** schema;
   char           ** vals;
   char            * errmsg;
   LDAP            * ld;
   LDAPMessage     * res;
   LDAPMessage     * msg;
   struct timeval    timeout;

   ld  = cnf->lud->ld;

   // searches for RootDSE
   timeout.tv_sec  = 5;
   timeout.tv_usec = 0;
   if ((err = ldap_search_ext(ld, "", LDAP_SCOPE_BASE, "(objectclass=*)", cnf->lud->attrs, 0, NULL, NULL, &timeout, -1, &msgid)) != LDAP_SUCCESS)
   {
      fprintf(stderr, "%s: ldap_search_ext(): %s\n", cnf->prog_name, ldap_err2string(err));
      return(-1);
   };
   switch((err = ldap_result(ld, msgid, LDAP_MSG_ALL, NULL, &res)))
   {
      case 0:
      fprintf(stderr, "%s: ldap_search_ext(): operation timed out\n", cnf->prog_name);
      return(-1);

      case -1:
      ldap_get_option(ld, LDAP_OPT_ERROR, &err);
      fprintf(stderr, "%s: ldap_result(): %s\n", cnf->prog_name, ldap_err2string(err));
      return(-1);

      default:
      break;
   };

   // parses result
   rc = ldap_parse_result(ld, res, &err, NULL, &errmsg, NULL, NULL, 0);
   if (rc != LDAP_SUCCESS)
   {
      fprintf(stderr, "%s: ldap_parse_result(): %s\n", cnf->prog_name, ldap_err2string(rc));
      ldap_msgfree(res);
      return(-1);
   };
   if (err != LDAP_SUCCESS)
   {
      fprintf(stderr, "%s: ldap_parse_result(): %s\n", cnf->prog_name, errmsg);
      ldap_memfree(errmsg);
      ldap_msgfree(res);
      return(-1);
   };

   // retrieves entry
   msg = ldap_first_entry(ld, res);

   // obtain vendor name and version
   if ((vals = ldap_get_values(ld, msg, "vendorName")) != NULL)
   {
      my_fields("Vendor name:", vals);
      ldap_value_free(vals);
   }
   else if ((vals = ldap_get_values(ld, msg, "isGlobalCatalogReady")) != NULL)
   {
      my_field("Vendor name:", "Microsoft Active Directory");
      ldap_value_free(vals);
   }
   else if ((vals = ldap_get_values(ld, msg, "objectClass")) != NULL)
   {
      for(s = 0; ((vals[s])); s++)
         if (!(strcasecmp(vals[s], "OpenLDAProotDSE")))
            my_field("Vendor name:", "OpenLDAP");
      ldap_value_free(vals);
   };
   if ((vals = ldap_get_values(ld, msg, "vendorVersion")) != NULL)
   {
      my_fields("Vendor version:", vals);
      ldap_value_free(vals);
   };
   if ((vals = ldap_get_values(ld, msg, "supportedLDAPVersion")) != NULL)
   {
      my_fields("LDAP version:", vals);
      ldap_value_free(vals);
   };

   // DNs
   if ((schema = ldap_get_values(ld, msg, "subschemaSubentry")) != NULL)
      my_fields("Subschema Subentry:", schema);
   if ((vals = ldap_get_values(ld, msg, "configContext")) != NULL)
   {
      my_fields("Configuration context:", vals);
      ldap_value_free(vals);
   };
   if ((monitor = ldap_get_values(ld, msg, "monitorContext")) != NULL)
      my_fields("Monitoring context:", monitor);
   printf("\n");

   if ((schema))
      my_schema(cnf, schema[0]);

   // display monitoring information
   if ((monitor))
   {
      // listeners
      my_monitor_listeners(cnf, monitor[0]);

      // connection stats
      my_monitor_connections(cnf, monitor[0]);
   };

   // obtain naming contexts
   vals = ldap_get_values(ld, msg, "namingContexts");
   if ((monitor))
   {
      if ((rc = my_monitor_database(cnf, monitor[0])) == -1)
         my_fields("Naming contexts:", vals);
      printf("\n");
   }
   else
   {
      my_fields("Naming contexts:", vals);
      printf("\n");
   };

   if ((schema))
      ldap_value_free(schema);
   if ((monitor))
      ldap_value_free(monitor);

   // obtain supported controls
   if ((vals = ldap_get_values(ld, msg, "supportedControl")) != NULL)
   {
      my_fields("Supported controls:", vals);
      printf("\n");
      ldap_value_free(vals);
   };

   // obtain supported extension
   if ((vals = ldap_get_values(ld, msg, "supportedExtension")) != NULL)
   {
      my_fields("Supported extension:", vals);
      printf("\n");
      ldap_value_free(vals);
   };

   // obtain supported features
   if ((vals = ldap_get_values(ld, msg, "supportedFeatures")) != NULL)
   {
      my_fields("Supported features:", vals);
      printf("\n");
      ldap_value_free(vals);
   };

   // obtain supported SASL mechanisms
   if ((vals = ldap_get_values(ld, msg, "supportedSASLMechanisms")) != NULL)
   {
      my_fields("Supported SASL mechanisms:", vals);
      printf("\n");
      ldap_value_free(vals);
   };

   // frees response
   ldap_msgfree(res);

   return(0);
}


int my_schema(MyConfig * cnf, const char * base)
{
   int               rc;
   int               err;
   int               msgid;
   int               i;
   char           ** vals;
   char              buff[256];
   LDAP            * ld;
   LDAPMessage     * res;
   LDAPMessage     * msg;
   struct timeval    timeout;

   ld  = cnf->lud->ld;

   // searches for cn=Connections,<monitor>
   timeout.tv_sec  = 5;
   timeout.tv_usec = 0;
   if ((err = ldap_search_ext(ld, base, LDAP_SCOPE_BASE, "(objectclass=*)", cnf->lud->attrs, 0, NULL, NULL, &timeout, -1, &msgid)) != LDAP_SUCCESS)
      return(-1);
   if ((err = ldap_result(ld, msgid, LDAP_MSG_ALL, NULL, &res)) < 1)
      return(-1);

   // parses result
   rc = ldap_parse_result(ld, res, &err, NULL, NULL, NULL, NULL, 0);
   if ((rc != LDAP_SUCCESS) || (err != LDAP_SUCCESS))
   {
      ldap_msgfree(res);
      return(-1);
   };

   // retrieves entry
   msg   = ldap_first_entry(ld, res);

   if ((vals = ldap_get_values(ld, msg, "ldapSyntaxes")) != NULL)
   {
      for(i = 0; ((vals[i])); i++);
      if (i > 0)
      {
         snprintf(buff, sizeof(buff), "ldapSyntaxes: %i", i);
         my_field("Schema:",  buff);
      };
      ldap_value_free(vals);
   };

   if ((vals = ldap_get_values(ld, msg, "matchingRules")) != NULL)
   {
      for(i = 0; ((vals[i])); i++);
      if (i > 0)
      {
         snprintf(buff, sizeof(buff), "matchingRules: %i", i);
         my_field(NULL,  buff);
      };
      ldap_value_free(vals);
   };

   if ((vals = ldap_get_values(ld, msg, "matchingRuleUse")) != NULL)
   {
      for(i = 0; ((vals[i])); i++);
      if (i > 0)
      {
         snprintf(buff, sizeof(buff), "matchingRuleUse: %i", i);
         my_field(NULL,  buff);
      };
      ldap_value_free(vals);
   };

   if ((vals = ldap_get_values(ld, msg, "attributeTypes")) != NULL)
   {
      for(i = 0; ((vals[i])); i++);
      if (i > 0)
      {
         snprintf(buff, sizeof(buff), "attributeTypes: %i", i);
         my_field(NULL,  buff);
      };
      ldap_value_free(vals);
   };

   if ((vals = ldap_get_values(ld, msg, "objectClasses")) != NULL)
   {
      for(i = 0; ((vals[i])); i++);
      if (i > 0)
      {
         snprintf(buff, sizeof(buff), "objectClasses: %i", i);
         my_field(NULL,  buff);
      };
      ldap_value_free(vals);
   };

   if ((vals = ldap_get_values(ld, msg, "dITContentRules")) != NULL)
   {
      for(i = 0; ((vals[i])); i++);
      if (i > 0)
      {
         snprintf(buff, sizeof(buff), "dITContentRules: %i", i);
         my_field(NULL,  buff);
      };
      ldap_value_free(vals);
   };

   if ((vals = ldap_get_values(ld, msg, "dITStructureRules")) != NULL)
   {
      for(i = 0; ((vals[i])); i++);
      if (i > 0)
      {
         snprintf(buff, sizeof(buff), "dITStructureRules: %i", i);
         my_field(NULL,  buff);
      };
      ldap_value_free(vals);
   };

   if ((vals = ldap_get_values(ld, msg, "nameForms")) != NULL)
   {
      for(i = 0; ((vals[i])); i++);
      if (i > 0)
      {
         snprintf(buff, sizeof(buff), "nameForms: %i", i);
         my_field(NULL,  buff);
      };
      ldap_value_free(vals);
   };

   printf("\n");

   return(0);
}


// fress resources
void my_unbind(MyConfig * cnf)
{
   assert(cnf != NULL);

   if ((cnf->lud))
      ldaputils_unbind(cnf->lud);

   if ((cnf->defvals))
      free(cnf->defvals);

   free(cnf);

   return;
}

/* end of source file */
