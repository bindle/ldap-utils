/*
 *  LDAP Utilities
 *  Copyright (C) 2023 David M. Syzdek <david@syzdek.net>.
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
 *  @file src/ldapconns.c export LDAP data to CSV file
 */
/*
 *  Simple Build:
 *     export CFLAGS='-DPROGRAM_NAME="ldapconns" -Wall -I../include'
 *     gcc ${CFLAGS} -c ldapconns.c
 *     gcc ${CFLAGS} -lldap -o ldapconns ldapconns.o ../lib/libldaputils.a
 *
 *  Libtool Build:
 *     export CFLAGS='-DPROGRAM_NAME="ldapconns" -Wall -I../include'
 *     libtool --mode=compile --tag=CC gcc ${CFLAGS} -c ldapconns.c
 *     libtool --mode=link    --tag=CC gcc ${CFLAGS} -lldap -o ldapconns \
 *             ldapconns.lo ../lib/libldaputils.a
 *
 *  Libtool Clean:
 *     libtool --mode=clean rm -f ldapconns.lo ldapconns
 */
#define _LDAP_UTILS_SRC_LDAPCONNS 1

///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

#include <ldaputils_compat.h>

#define _GNU_SOURCE 1
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
#pragma mark - Definitions

#ifndef PROGRAM_NAME
#define PROGRAM_NAME "ldapconns"
#endif

#define MY_SHORT_OPTIONS LDAPUTILS_OPTIONS_COMMON LDAPUTILS_OPTIONS_SEARCH "o:"


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#pragma mark - Datatypes

typedef struct my_record MyRec;
struct my_record
{
   unsigned       rec_num;
   unsigned       rec_proto;
   unsigned       rec_ops_recv;
   unsigned       rec_ops_exec;
   unsigned       rec_ops_pend;
   unsigned       rec_ops_comp;
   char **        rec_mask;
   char **        rec_authzdn;
   char **        rec_listener;
   char **        rec_peer;
   char **        rec_local;
   char **        rec_start;
   char **        rec_activity;
};


// configuration union
typedef struct my_config MyConfig;
struct my_config
{
   size_t         recs_len;
   LDAPUtils *    lud;
   const char *   filter;
   const char *   prog_name;
   const char **  defvals;
   char **        monitor;
   MyRec **       recs;
   char           output[LDAPUTILS_OPT_LEN];
};


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

static const char * ldapinfo_attrs[] =
{
   "cn",
   "monitorConnectionNumber",
   "monitorConnectionProtocol",
   "monitorConnectionOpsReceived",
   "monitorConnectionOpsExecuting",
   "monitorConnectionOpsPending",
   "monitorConnectionOpsCompleted",
   "monitorConnectionGet",
   "monitorConnectionRead",
   "monitorConnectionWrite",
   "monitorConnectionMask",
   "monitorConnectionAuthzDN",
   "monitorConnectionListener",
   "monitorConnectionPeerAddress",
   "monitorConnectionLocalAddress",
   "monitorConnectionStartTime",
   "monitorConnectionActivityTime",
   "monitorContext",
   "objectclass",
   NULL
};


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

// main statement
extern int
main(
         int                           argc,
         char *                        argv[] );


// parses configuration
static int
my_config(
         int                           argc,
         char *                        argv[],
         MyConfig **                   cnfp );


static int
my_field_len(
         int                           len,
         char **                       val_str,
         unsigned                      val_num );


static int
my_monitor_connections(
         MyConfig *                    cnf,
         const char *                  base );


// parses RootDSE
static int
my_rootdse(
         MyConfig *                    cnf );


// fress resources
static void
my_unbind(
         MyConfig *                    cnf );


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

void
ldaputils_usage(
         void )
{
   printf("Usage: %s [options]\n", PROGRAM_NAME);
   ldaputils_usage_common(MY_SHORT_OPTIONS);
   printf("\nReport bugs to <%s>.\n", PACKAGE_BUGREPORT);
   return;
}


int
main(
         int                           argc,
         char *                        argv[] )
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
   if (!(cnf->monitor))
   {
      fprintf(stderr, "%s: unable to determine monitoring context\n", ldaputils_get_prog_name(cnf->lud));
      my_unbind(cnf);
      return(1);
   };

   my_unbind(cnf);

   return(0);
}


int
my_config(
         int                           argc,
         char *                        argv[],
         MyConfig **                   cnfp )
{
   int         c;
   size_t      s;
   size_t      len;
   int         err;
   int         option_index;
   MyConfig *  cnf;

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


int
my_monitor_connections(
         MyConfig *                    cnf,
         const char *                  base )
{
   int               rc;
   int               err;
   int               msgid;
   int               count;
   char **           vals;
   char              dn[256];
   char              ops[128];
   char *            conn_local;
   char *            conn_peer;
   char *            str;
   LDAP *            ld;
   LDAPMessage *     res;
   LDAPMessage *     msg;
   struct timeval    timeout;
   MyRec *           rec;
   void *            ptr;
   size_t            pos;
   int               len_listener;
   int               len_local;
   int               len_peer;
   int               len_proto;
   int               len_mask;
   int               len_start;
   int               len_activity;
   int               len_ops;
   int               len_ops_recv;
   int               len_ops_exec;
   int               len_ops_pend;
   int               len_ops_comp;

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
      // skip entry if not a connection
      if ((vals = ldap_get_values(ld, msg, "monitorConnectionNumber")) == NULL)
      {
         msg = ldap_next_entry(ld, msg);
         continue;
      };

      // allocate memory for records
      if ((ptr = realloc(cnf->recs, (sizeof(MyRec *)*(cnf->recs_len+1)))) == NULL)
         return(-1);
      cnf->recs = ptr;
      if ((cnf->recs[cnf->recs_len] = malloc(sizeof(MyRec))) == NULL)
         return(-1);
      memset(cnf->recs[cnf->recs_len], 0, sizeof(MyRec));
      rec            = cnf->recs[cnf->recs_len];
      cnf->recs_len++;

      // process monitorConnectionNumber
      rec->rec_num = (unsigned)strtoull(vals[0], NULL, 10);
      ldap_value_free(vals);

      // process values
      if ((vals = ldap_get_values(ld, msg, "monitorConnectionProtocol")) != NULL)
      {
         rec->rec_proto = (unsigned)strtoull(vals[0], NULL, 10);
         ldap_value_free(vals);
      };
      if ((vals = ldap_get_values(ld, msg, "monitorConnectionOpsReceived")) != NULL)
      {
         rec->rec_ops_recv = (unsigned)strtoull(vals[0], NULL, 10);
         ldap_value_free(vals);
      };
      if ((vals = ldap_get_values(ld, msg, "monitorConnectionOpsExecuting")) != NULL)
      {
         rec->rec_ops_exec = (unsigned)strtoull(vals[0], NULL, 10);
         ldap_value_free(vals);
      };
      if ((vals = ldap_get_values(ld, msg, "monitorConnectionOpsPending")) != NULL)
      {
         rec->rec_ops_pend = (unsigned)strtoull(vals[0], NULL, 10);
         ldap_value_free(vals);
      };
      if ((vals = ldap_get_values(ld, msg, "monitorConnectionOpsCompleted")) != NULL)
      {
         rec->rec_ops_comp = (unsigned)strtoull(vals[0], NULL, 10);
         ldap_value_free(vals);
      };
      rec->rec_mask     = ldap_get_values(ld, msg, "monitorConnectionMask");
      rec->rec_authzdn  = ldap_get_values(ld, msg, "monitorConnectionAuthzDN");
      rec->rec_listener = ldap_get_values(ld, msg, "monitorConnectionListener");
      rec->rec_peer     = ldap_get_values(ld, msg, "monitorConnectionPeerAddress");
      rec->rec_local    = ldap_get_values(ld, msg, "monitorConnectionLocalAddress");
      rec->rec_start    = ldap_get_values(ld, msg, "monitorConnectionStartTime");
      rec->rec_activity = ldap_get_values(ld, msg, "monitorConnectionActivityTime");

      // retrieves next entry
      msg = ldap_next_entry(ld, msg);
   };

   str            = ops;
   len_listener   = (int)strlen("Listener");
   len_proto      = (int)strlen(" ");
   len_mask       = (int)strlen("Mask");
   len_local      = (int)strlen("Local");
   len_peer       = (int)strlen("Peer");
   len_start      = (int)strlen("Start");
   len_activity   = (int)strlen("Last Activity");
   len_ops        = (int)strlen("Ops R/E/P/C");
   len_ops_recv   = (int)strlen("OpsRecv");
   len_ops_exec   = (int)strlen("OpsExec");
   len_ops_pend   = (int)strlen("OpsPend");
   len_ops_comp   = (int)strlen("OpsCmplt");
   for(pos = 0; (pos < cnf->recs_len); pos++)
   {
      if (!(cnf->recs[pos]->rec_proto))
         continue;
      conn_peer  = strrchr(cnf->recs[pos]->rec_peer[0],  '=');
      conn_peer  = ((conn_peer)) ? &conn_peer[1] : cnf->recs[pos]->rec_peer[0];
      conn_local = strrchr(cnf->recs[pos]->rec_local[0], '=');
      conn_local = ((conn_local)) ? &conn_local[1] : cnf->recs[pos]->rec_local[0];
      snprintf(ops, sizeof(ops), "%i/%i/%i/%i",
         cnf->recs[pos]->rec_ops_recv,
         cnf->recs[pos]->rec_ops_exec,
         cnf->recs[pos]->rec_ops_pend,
         cnf->recs[pos]->rec_ops_comp
      );
      len_listener   = my_field_len(len_listener,  cnf->recs[pos]->rec_listener,    0);
      len_mask       = my_field_len(len_mask,      cnf->recs[pos]->rec_mask,        0);
      len_local      = my_field_len(len_local,     &conn_local,                     0);
      len_peer       = my_field_len(len_peer,      &conn_peer,                      0);
      len_start      = my_field_len(len_start,     cnf->recs[pos]->rec_start,       0);
      len_activity   = my_field_len(len_start,     cnf->recs[pos]->rec_activity,    0);
      len_ops        = my_field_len(len_ops,       &str,                            0);
      len_ops_recv   = my_field_len(len_ops_recv,  NULL, cnf->recs[pos]->rec_ops_recv);
      len_ops_exec   = my_field_len(len_ops_exec,  NULL, cnf->recs[pos]->rec_ops_exec);
      len_ops_pend   = my_field_len(len_ops_pend,  NULL, cnf->recs[pos]->rec_ops_pend);
      len_ops_comp   = my_field_len(len_ops_comp,  NULL, cnf->recs[pos]->rec_ops_comp);
   };

   printf("%-*s  %-*s %-*s %-*s %-*s %-*s %-*s %-*s %s\n",
      len_listener,  "Listener",
      len_proto,     " ",
      len_mask,      "Mask",
      len_ops,       "Ops R/E/P/C",
      len_local,     "Local",
      len_peer,      "Peer",
      len_start,     "Start",
      len_activity,  "Last Activity",
      "AuthzDN"
   );

   for(pos = 0; (pos < cnf->recs_len); pos++)
   {
      if (!(cnf->recs[pos]->rec_proto))
         continue;
      conn_peer  = strrchr(cnf->recs[pos]->rec_peer[0],  '=');
      conn_peer  = ((conn_peer)) ? &conn_peer[1] : cnf->recs[pos]->rec_peer[0];
      conn_local = strrchr(cnf->recs[pos]->rec_local[0], '=');
      conn_local = ((conn_local)) ? &conn_local[1] : cnf->recs[pos]->rec_local[0];
      snprintf(ops, sizeof(ops), "%i/%i/%i/%i",
         cnf->recs[pos]->rec_ops_recv,
         cnf->recs[pos]->rec_ops_exec,
         cnf->recs[pos]->rec_ops_pend,
         cnf->recs[pos]->rec_ops_comp
      );
      printf("%-*s v%-*i %-*s %-*s %-*s %-*s %-*s %-*s %s\n",
         len_listener,  cnf->recs[pos]->rec_listener[0],
         len_proto,     cnf->recs[pos]->rec_proto,
         len_mask,      cnf->recs[pos]->rec_mask[0],
         len_ops,       ops,
         len_local,     conn_local,
         len_peer,      conn_peer,
         len_start,     cnf->recs[pos]->rec_start[0],
         len_activity,  cnf->recs[pos]->rec_activity[0],
         (((cnf->recs[pos]->rec_authzdn)) ? cnf->recs[pos]->rec_authzdn[0] : "")
      );
   };

   return(0);
}

int
my_field_len(
         int                           len,
         char **                       val_str,
         unsigned                      val_num )
{
   int val_len;
   char buff[128];
   char * ptr;
   if (!(val_str))
   {
      snprintf(buff, (sizeof(buff)-1), "%u", val_num);
      ptr     = buff;
      val_str = &ptr;
   };
   val_len = (int)strlen(val_str[0]);
   return( (val_len > len) ? val_len : len);
}


int
my_rootdse(
         MyConfig *                    cnf )

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

   // retrieve DNs
   cnf->monitor  = ldap_get_values(ld, msg, "monitorContext");
   my_monitor_connections(cnf, cnf->monitor[0]);

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
