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
// MARK: - Headers

#include <ldaputils_compat.h>

#ifdef HAVE_CONFIG_H
#   include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <time.h>
#include <getopt.h>
#include <assert.h>

#include <ldap.h>
#include <ldaputils.h>


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
// MARK: - Definitions

#ifndef PROGRAM_NAME
#define PROGRAM_NAME "ldapppolicy"
#endif

#define MY_SHORT_OPTIONS LDAPUTILS_OPTIONS_COMMON LDAPUTILS_OPTIONS_SEARCH "o:"


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
// MARK: - Datatypes

// configuration union
typedef struct my_config MyConfig;
struct my_config
{
   int               res_count;
   int               attr_name;
   int               scope;
   LDAPUtils *       lud;
   const char *      filter;
   const char *      prog_name;
   const char *      base;
   const char **     defvals;
   char              output[LDAPUTILS_OPT_LEN];
};


/////////////////
//             //
//  Variables  //
//             //
/////////////////
// MARK: - Variables

static char * my_attrs[] =
{
   (char []){ "namingContexts" },
   (char []){ "objectClass" },
   (char []){ "pwdAccountLockedTime" },
   (char []){ "pwdAllowUserChange" },
   (char []){ "pwdAttribute" },
   (char []){ "pwdChangedTime" },
   (char []){ "pwdCheckModule" },
   (char []){ "pwdCheckQuality" },
   (char []){ "pwdExpireWarning" },
   (char []){ "pwdFailureCountInterval" },
   (char []){ "pwdFailureTime" },
   (char []){ "pwdGraceAuthnLimit" },
   (char []){ "pwdGraceUseTime" },
   (char []){ "pwdHistory" },
   (char []){ "pwdInHistory" },
   (char []){ "pwdLockout" },
   (char []){ "pwdLockoutDuration" },
   (char []){ "pwdMaxAge" },
   (char []){ "pwdMaxFailure" },
   (char []){ "pwdMinAge" },
   (char []){ "pwdMinLength" },
   (char []){ "pwdMustChange" },
   (char []){ "pwdPolicySubentry" },
   (char []){ "pwdReset" },
   (char []){ "pwdSafeModify" },
   NULL
};


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
// MARK: - Prototypes

// main statement
extern int
main(
         int                           argc,
         char *                        argv[] );


static int
my_config(
         int                           argc,
         char *                        argv[],
         MyConfig **                   cnfp );


static int
my_entry(
         MyConfig *                    cnf,
         LDAPMessage *                 msg );


static void
my_field(
         MyConfig *                    cnf,
         const char *                  name,
         const char *                  attr,
         const char *                  val );


static void
my_field_array(
         MyConfig *                    cnf,
         LDAPMessage *                 msg,
         const char *                  attr,
         const char *                  name,
         const char *                  dflt );


static void
my_field_interval(
         MyConfig *                    cnf,
         LDAPMessage *                 msg,
         const char *                  attr,
         const char *                  name,
         const char *                  dflt );


static void
my_field_quality(
         MyConfig *                    cnf,
         LDAPMessage *                 msg,
         const char *                  attr,
         const char *                  name,
         const char *                  dflt );


static void
my_field_str(
         MyConfig *                    cnf,
         LDAPMessage *                 msg,
         const char *                  attr,
         const char *                  name,
         const char *                  dflt );


static int
my_naming_contexts(
         MyConfig *                    cnf );


static int
my_search(
         MyConfig *                    cnf,
         const char *                  base,
         int                           scope,
         const char *                  filter );


static void
my_unbind(
         MyConfig *                    cnf );


/////////////////
//             //
//  Functions  //
//             //
/////////////////
// MARK: - Functions

/// prints program usage and exits
void
ldaputils_usage(
         void )
{
   printf("Usage: %s [options] [dn [filter]]\n", PROGRAM_NAME);
   ldaputils_usage_common(MY_SHORT_OPTIONS);
   printf("Display Options:\n");
   printf("  -A                        show attribute names instead of descriptions\n");
   printf("\nReport bugs to <%s>.\n", PACKAGE_BUGREPORT);
   return;
}


int
main(
         int                           argc,
         char *                        argv[] )
{
   int            err;
   int            rc;
   MyConfig *     cnf;

   cnf = NULL;

   // initializes resources and parses CLI arguments
   if (my_config(argc, argv, &cnf) != 0)
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

   rc = 0;
   if ((cnf->base))
      rc = my_search(cnf, cnf->base, cnf->scope, cnf->filter);
   else
      rc = my_naming_contexts(cnf);

   if (!(cnf->res_count))
   {
      fprintf(stderr, "%s: no entries found\n", ldaputils_get_prog_name(cnf->lud));
      rc = -1;
   };

   my_unbind(cnf);

   return( ((rc)) ? 1 : 0 );
}


int
my_config(
         int                           argc,
         char *                        argv[],
         MyConfig **                   cnfp )
{
   int         c;
   int         err;
   int         option_index;
   MyConfig *  cnf;

   static char   short_options[] = MY_SHORT_OPTIONS "A";
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

         case 'A':
         cnf->attr_name = 1;
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

   cnf->prog_name = ldaputils_get_prog_name(cnf->lud);

   // checks for required arguments
   if (argc > (optind+2))
   {
      fprintf(stderr, "%s: unknown arguments\n", cnf->prog_name);
      fprintf(stderr, "Try `%s --help' for more information.\n", cnf->prog_name);
      my_unbind(cnf);
      return(1);
   };

   // saves search base and filter
   if (argc > optind)
      cnf->base = argv[optind];
   if (argc > (optind+1))
      cnf->filter = argv[optind+1];
   cnf->scope  = ((cnf->filter)) ? LDAP_SCOPE_SUB : LDAP_SCOPE_BASE;
   cnf->filter = ((cnf->filter)) ? cnf->filter    : "(objectClass=*)";

   // reads password
   if ((err = ldaputils_pass(cnf->lud)) != 0)
   {
      my_unbind(cnf);
      return(1);
   };

   *cnfp = cnf;

   return(0);
}


int
my_entry(
         MyConfig *                    cnf,
         LDAPMessage *                 msg )
{
   int               isppolicy;
   int               pos;
   char *            dn;
   char **           vals;
   LDAP *            ld;

   ld  = cnf->lud->ld;

   // check for objectClass pwdPolicy
   isppolicy   = 0;
   vals        = ldaputils_get_values(ld, msg, "objectClass");
   for(pos = 0; ((vals[pos])); pos++)
   {
      if (!(strcasecmp(vals[pos], "pwdPolicy")))
         isppolicy = 1;
      free(vals[pos]);
   };
   free(vals);

   // print dn
   dn = ldap_get_dn(ld, msg);
   printf("%s: %s\n", (((isppolicy)) ? "ppolicy" : "entry"), dn);
   if ((isppolicy))
   {
      my_field_str(        cnf, msg, "pwdAttribute",              "Password Attribute",         NULL);
      my_field_interval(   cnf, msg, "pwdMinAge",                 "Password Minimum Age",       "0");
      my_field_interval(   cnf, msg, "pwdMaxAge",                 "Password Maximum Age",       NULL);
      my_field_str(        cnf, msg, "pwdMinLength",              "Password Minimum Length",    "0");
      my_field_quality(    cnf, msg, "pwdCheckQuality",           "Password Syntax Checks",     "0");
      my_field_str(        cnf, msg, "pwdInHistory",              "Passwords In History",       NULL);
      my_field_interval(   cnf, msg, "pwdExpireWarning",          "Password Expire Warning",    "0");
      my_field_str(        cnf, msg, "pwdGraceAuthnLimit",        "Expired Grace Binds",        "0");
      my_field_str(        cnf, msg, "pwdLockout",                "Lockout After Failures",     NULL);
      my_field_interval(   cnf, msg, "pwdLockoutDuration",        "Lockout Duration",           NULL);
      my_field_str(        cnf, msg, "pwdMaxFailure",             "Lockout Max Failures",       NULL);
      my_field_interval(   cnf, msg, "pwdFailureCountInterval",   "Lockout Failure Interval",   NULL);
      my_field_str(        cnf, msg, "pwdMustChange",             "Password Must Change",       NULL);
      my_field_str(        cnf, msg, "pwdAllowUserChange",        "Allow User Change",          NULL);
      my_field_str(        cnf, msg, "pwdSafeModify",             "Require Safe Modify",        NULL);
      my_field_str(        cnf, msg, "pwdCheckModule",            "Password Check Module",      NULL);
   };
   my_field_str(        cnf, msg, "pwdPolicySubentry",    "Password Policy",         NULL);
   my_field_str(        cnf, msg, "pwdChangedTime",       "Password Last Changed",   NULL);
   my_field_str(        cnf, msg, "pwdAccountLockedTime", "Account Locked Time",     NULL);
   my_field_array(      cnf, msg, "pwdFailureTime",       "Password Failures",       NULL);
   my_field_array(      cnf, msg, "pwdHistory",           "Password History",        NULL);
   my_field_array(      cnf, msg, "pwdGraceUseTime",      "Grace Use Time",          NULL);
   my_field_str(        cnf, msg, "pwdReset",             "Must Reset Password",     NULL);
   printf("\n");

   return(0);
}


void
my_field(
         MyConfig *                    cnf,
         const char *                  name,
         const char *                  attr,
         const char *                  val )
{
   char           desc[32];

   if (!(val))
      return;

   name = ((cnf->attr_name)) ? attr : name;

   if ((name))
      snprintf(desc, sizeof(desc), "%s:", name);
   else
      snprintf(desc, sizeof(desc), " ");

   printf("   %-25s %s\n", desc, val);

   return;
}


void
my_field_array(
         MyConfig *                    cnf,
         LDAPMessage *                 msg,
         const char *                  attr,
         const char *                  name,
         const char *                  dflt )
{
   LDAP *      ld;
   int         pos;
   char **     vals;

   ld = cnf->lud->ld;

   if ((vals = ldaputils_get_values(ld, msg, attr)) != NULL)
   {
      my_field(cnf, name, attr, vals[0]);
      for(pos = 1; ((vals[pos])); pos++)
         my_field(cnf, NULL, attr, vals[0]);
      ldaputils_value_free(vals);
      return;
   }

   if ((dflt))
      my_field(cnf, name, attr, dflt);

   return;
}


void
my_field_interval(
         MyConfig *                    cnf,
         LDAPMessage *                 msg,
         const char *                  attr,
         const char *                  name,
         const char *                  dflt )
{
   LDAP *      ld;
   char **     vals;
   char *      endptr;
   char        attrval[128];
   char        unit[24];
   char        val[32];
   long long   w;
   long long   d;
   long long   h;
   long long   m;
   long long   s;

   ld = cnf->lud->ld;

   if ((vals = ldaputils_get_values(ld, msg, attr)) != NULL)
   {
      snprintf(attrval, sizeof(attrval), "%s", vals[0]);
      ldaputils_value_free(vals);
   } else if ((dflt))
      snprintf(attrval, sizeof(attrval), "%s", dflt);
   else
      return;

   s = strtoll(attrval, &endptr, 10);
   if (endptr[0] != 0)
      return;

   if (s == 0)
   {
      my_field(cnf, name, attr, "0s");
      return;
   };

   w  = (s / 604800);
   s %= 604800;
   d  = (s / 86400);
   s %= 86400;
   h  = (s / 3600);
   s %= 3600;
   m  = (s / 60);
   s %= 60;

   val[0] = '\0';
   if ((w))
   {
      snprintf(unit, sizeof(unit), "%lliw ", w);
      strncat(val, unit, (sizeof(val)-1));
   };
   if ((d))
   {
      snprintf(unit, sizeof(unit), "%llid ", d);
      strncat(val, unit, (sizeof(val)-1));
   };
   if ((h))
   {
      snprintf(unit, sizeof(unit), "%llih ", h);
      strncat(val, unit, (sizeof(val)-1));
   };
   if ((m))
   {
      snprintf(unit, sizeof(unit), "%llim ", m);
      strncat(val, unit, (sizeof(val)-1));
   };
   if ((s))
   {
      snprintf(unit, sizeof(unit), "%llis ", s);
      strncat(val, unit, (sizeof(val)-1));
   };
   val[strlen(val)-1] = '\0';

   my_field(cnf, name, attr, val);

   return;
}


void
my_field_quality(
         MyConfig *                    cnf,
         LDAPMessage *                 msg,
         const char *                  attr,
         const char *                  name,
         const char *                  dflt )
{
   LDAP *         ld;
   char **        vals;
   const char *   val;
   char           attrval[128];

   ld = cnf->lud->ld;

   if ((vals = ldaputils_get_values(ld, msg, attr)) != NULL)
   {
      snprintf(attrval, sizeof(attrval), "%s", vals[0]);
      ldaputils_value_free(vals);
   } else if ((dflt))
      snprintf(attrval, sizeof(attrval), "%s", dflt);
   else
      return;

   if (!(strcmp(attrval, "0")))
      val = "disabled";
   else if (!(strcmp(attrval, "1")))
      val = "enabled, ignore errors";
   else if (!(strcmp(attrval, "2")))
      val = "enabled, fail on errors";
   else
      val = "unknown code";

   my_field(cnf, name, attr, val);

   return;
}


void
my_field_str(
         MyConfig *                    cnf,
         LDAPMessage *                 msg,
         const char *                  attr,
         const char *                  name,
         const char *                  dflt )
{
   LDAP *      ld;
   char **     vals;
   char        attrval[128];

   ld = cnf->lud->ld;

   if ((vals = ldaputils_get_values(ld, msg, attr)) != NULL)
   {
      snprintf(attrval, sizeof(attrval), "%s", vals[0]);
      ldaputils_value_free(vals);
   } else if ((dflt))
      snprintf(attrval, sizeof(attrval), "%s", dflt);
   else
      return;

   my_field(cnf, name, attr, attrval);

   return;
}


int
my_naming_contexts(
         MyConfig *                    cnf )
{
   int               rc;
   int               err;
   int               msgid;
   int               pos;
   char *            errmsg;
   char **           vals;
   LDAP *            ld;
   LDAPMessage *     res;
   LDAPMessage *     msg;
   struct timeval    timeout;

   ld  = cnf->lud->ld;

   timeout.tv_sec  = 5;
   timeout.tv_usec = 0;
   if ((err = ldap_search_ext(ld, "", LDAP_SCOPE_BASE, "objectclass=*", my_attrs, 0, NULL, NULL, &timeout, -1, &msgid)) != LDAP_SUCCESS)
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
   errmsg = NULL;
   rc = ldap_parse_result(ld, res, &err, NULL, &errmsg, NULL, NULL, 0);
   if (err != LDAP_SUCCESS)
   {
      fprintf(stderr, "%s: ldap_parse_result(): %s\n", cnf->prog_name, errmsg);
      fprintf(stderr, "%s: ldap_parse_result(): %s\n", cnf->prog_name, ldap_err2string(rc));
      ldap_memfree(errmsg);
      ldap_msgfree(res);
      return(-1);
   };
   if ((errmsg))
      ldap_memfree(errmsg);

   if ((msg = ldap_first_entry(ld, res)) == NULL)
   {
      ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &err);
      fprintf(stderr, "%s: ldap_first_entry(): %s\n", cnf->prog_name, ldap_err2string(rc));
      ldap_msgfree(res);
      return(-1);
   };

   if ((vals = ldaputils_get_values(ld, msg, "namingContexts")) == NULL)
   {
      ldap_msgfree(res);
      return(-1);
   };

   for(pos = 0; ((vals[pos])); pos++)
   {
      if (my_search(cnf, vals[pos], LDAP_SCOPE_SUB, "objectClass=pwdPolicy") == -1)
      {
         ldaputils_value_free(vals);
         ldap_msgfree(res);
         return(-1);
      };
   };

   // frees response
   ldap_msgfree(res);

   return(0);
}


int
my_search(
         MyConfig *                    cnf,
         const char *                  base,
         int                           scope,
         const char *                  filter )
{
   int               rc;
   int               err;
   int               msgid;
   char *            errmsg;
   LDAP *            ld;
   LDAPMessage *     res;
   LDAPMessage *     msg;
   struct timeval    timeout;

   ld  = cnf->lud->ld;

   timeout.tv_sec  = 5;
   timeout.tv_usec = 0;
   if ((err = ldap_search_ext(ld, base, scope, filter, my_attrs, 0, NULL, NULL, &timeout, -1, &msgid)) != LDAP_SUCCESS)
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
   errmsg = NULL;
   rc = ldap_parse_result(ld, res, &err, NULL, &errmsg, NULL, NULL, 0);
   if (err != LDAP_SUCCESS)
   {
      fprintf(stderr, "%s: ldap_parse_result(): %s\n", cnf->prog_name, errmsg);
      fprintf(stderr, "%s: ldap_parse_result(): %s\n", cnf->prog_name, ldap_err2string(rc));
      ldap_memfree(errmsg);
      ldap_msgfree(res);
      return(-1);
   };
   if ((errmsg))
      ldap_memfree(errmsg);

   // print entry
   for(msg = ldap_first_entry(ld, res); ((msg)); msg = ldap_next_entry(ld, msg))
   {
      my_entry(cnf, msg);
      cnf->res_count++;
   };

   // frees response
   ldap_msgfree(res);

   return(0);
}


void
my_unbind(
         MyConfig *                    cnf )
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
