/*
 *  LDAP Utilities
 *  Copyright (C) 2019 David M. Syzdek <david@syzdek.net>
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
 */
/*
 *  Simple example of LDAP search using asynchronous functions.
 */
/*
 *  Simple Build:
 *     gcc -Wall     -c  -o ldap_search_ext.o ldap_search_ext.c
 *     gcc -lldap -llber -o ldap_search_ext   ldap_search_ext.o
 */

#include <stdio.h>
#include <stdlib.h>

#define LDAP_DEPRECATED 1
#include <ldap.h>

int main(void);

int main(void)
{
   int              i;
   int              rc;
   int              err;
   int              msgid;
   int              opt_i;
   const char     * opt_s;
   char           * dn;
   char           * name;
   char           * str;
   LDAP           * ld;
   LDAPMessage    * res;
   LDAPMessage    * msg;
   BerValue         cred;
   BerElement     * ber;
   BerValue       * servercredp;
   char          ** rdns;
   struct berval ** vals;
   char           * attrs[32];


   printf("# ldap_initialize ...\n");
   if ((rc = ldap_initialize(&ld, NULL)) != LDAP_SUCCESS)
   {
      perror("ldap_initialize()");
      ldap_unbind_ext_s(ld, NULL, NULL);
      return(1);
   };


   printf("# ldap_set_option(LDAP_OPT_PROTOCOL_VERSION) ...\n");
   opt_i = 3;
   if ((rc = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &opt_i)) != LDAP_OPT_SUCCESS)
   {
      fprintf(stderr, "LDAP_OPT_PROTOCOL_VERSION error\n");
      ldap_unbind_ext_s(ld, NULL, NULL);
      return(1);
   };


   printf("# ldap_set_option(LDAP_OPT_TIMELIMIT) ...\n");
   opt_i = 5;
   if ((rc = ldap_set_option(ld, LDAP_OPT_TIMELIMIT, &opt_i)) != LDAP_OPT_SUCCESS)
   {
      fprintf(stderr, "LDAP_OPT_PROTOCOL_VERSION error\n");
      ldap_unbind_ext_s(ld, NULL, NULL);
      return(1);
   };


   if ((opt_s = getenv("DEMO_LDAP_URI")) != NULL)
   {
      printf("# ldap_set_option(LDAP_OPT_URI) ...\n");
      if ((rc = ldap_set_option(ld, LDAP_OPT_URI, opt_s)) != LDAP_OPT_SUCCESS)
      {
         fprintf(stderr, "LDAP_OPT_URI error\n");
         ldap_unbind_ext_s(ld, NULL, NULL);
         return(1);
      };
   };
   if ((rc = ldap_get_option(ld, LDAP_OPT_URI, &str)) == LDAP_OPT_SUCCESS)
   {
      printf("# URI:   %s\n", str);
      ldap_memfree(str);
   };


   printf("# ldap_sasl_bind_s ...\n");
   bzero(&cred, sizeof(cred));
   servercredp = NULL;
   if ((rc = ldap_sasl_bind_s(ld, NULL, (const char *)LDAP_SASL_SIMPLE, &cred, NULL, NULL, &servercredp)) != LDAP_SUCCESS)
   {
      fprintf(stderr, "ldap_sasl_bind_s(): %s\n", ldap_err2string(rc));

      ldap_unbind_ext_s(ld, NULL, NULL);
      return(1);
   };


   attrs[0] = "gn";
   attrs[1] = "sn";
   attrs[2] = "uid";
   attrs[3] = "title";
   attrs[4] = "objectClass";
   attrs[5] = "o";
   attrs[6] = NULL;


   printf("# ldap_search_ext ...\n");
   //if ((err = ldap_search_ext(ld, "dc=example,dc=com", LDAP_SCOPE_SUBTREE, "(cn=*)", attrs, 0, NULL, NULL, NULL, -1, &msgid)))
   if ((err = ldap_search_ext(  ld, NULL,                LDAP_SCOPE_SUBTREE, NULL,     attrs, 0, NULL, NULL, NULL, -1, &msgid)))
   {
      fprintf(stderr, "ldap_search_ext_s(): %s\n", ldap_err2string(err));
      ldap_unbind_ext_s(ld, NULL, NULL);
      return(1);
   };


   printf("# ldap_result ...\n");
   switch((err = ldap_result(ld, msgid, LDAP_MSG_ALL, NULL, &res)))
   {
      case 0:
      break;

      case -1:
      fprintf(stderr, "ldap_result(): %s\n", ldap_err2string(err));
      ldap_unbind_ext_s(ld, NULL, NULL);
      return(-1);

      default:
      break;
   };


   printf("# ldap_parse_result ...\n");
   if ((rc = ldap_parse_result(ld, res, &err, NULL, NULL, NULL, NULL, 0)) != LDAP_SUCCESS)
   {
      fprintf(stderr, "ldap_parse_result(): %s\n", ldap_err2string(rc));
      ldap_unbind_ext_s(ld, NULL, NULL);
      return(1);
   };
   if (err != LDAP_SUCCESS)
   {
      fprintf(stderr, "ldap_parse_result(): %s\n", ldap_err2string(err));
      ldap_unbind_ext_s(ld, NULL, NULL);
      return(1);
   };


   printf("# Entry count: %i\n", ldap_count_entries(ld, res));


   printf("# ldap_first_entry ...\n\n\n");
   msg = ldap_first_entry(ld, res);
   while ((msg))
   {
      // retrieve DN
      dn = ldap_get_dn(ld, msg);

      // prints DN in "User Friendly Naming" format
      if ((str = ldap_dn2ufn(dn)) == NULL)
      {
         fprintf(stderr, "ldap_dn2ufn(): out of virtual memory\n");
         ldap_unbind_ext_s(ld, NULL, NULL);
         return(1);
      };
      printf("# UFN: %s\n", str);
      ldap_memfree(str);

      // prints DN using "DCE" style
      if ((str = ldap_dn2dcedn(dn)) == NULL)
      {
         fprintf(stderr, "ldap_dn2dcedn(): out of virtual memory\n");
         ldap_unbind_ext_s(ld, NULL, NULL);
         return(1);
      };
      printf("# DCE: %s\n", str);
      ldap_memfree(str);

      // prints DN as "AD canonical name"
      if ((str = ldap_dn2ad_canonical(dn)) == NULL)
      {
         fprintf(stderr, "ldap_dn2dcedn(): out of virtual memory\n");
         ldap_unbind_ext_s(ld, NULL, NULL);
         return(1);
      };
      printf("# ADC: %s\n", str);
      ldap_memfree(str);

      // prints RDNs
      if ((rdns = ldap_explode_dn(dn, 0)) == NULL)
      {
         fprintf(stderr, "ldap_explode_dn(): out of virtual memory\n");
         ldap_unbind_ext_s(ld, NULL, NULL);
         return(1);
      };
      for(i = 0; ((rdns[i])); i++)
      {
         printf("# RDN %i: %s\n", i, rdns[i]);
      };
      ldap_value_free(rdns);


      // prints and free DN
      printf("dn: %s\n", dn);
      ldap_memfree(dn);

      name = ldap_first_attribute(ld, msg, &ber);
      while((name))
      {
         if ((vals = ldap_get_values_len(ld, msg, name)))
         {
            for(i = 0; (i < ldap_count_values_len(vals)); i++)
               //printf("%s: %s (%lu)\n", name, vals[i]->bv_val, vals[i]->bv_len);
               printf("%s: %s\n", name, vals[i]->bv_val);
            ldap_value_free_len(vals);
         };

         name = ldap_next_attribute(ld, msg, ber);
      };
      ber_free(ber, 0);
      printf("\n");

      msg = ldap_next_entry(ld, msg);
   };

   ldap_msgfree(res);


   ldap_unbind_ext_s(ld, NULL, NULL);


   return(0);
}
