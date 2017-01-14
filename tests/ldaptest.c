
#include <stdio.h>
#include <stdio.h>
#include <ldap.h>

int main(void);
int main(void)
{
   int            opt;
   int            lerr;
   int            count;
   LDAP         * ld;
   LDAPMessage  * res;
   //LDAPMessage  * entry;

   printf("running: ldap_initialize()\n");
   if (ldap_initialize(&ld, NULL))
   {
      perror("ldap_initialize()");
      return(1);
   };

   opt = 0xffff;
   ldap_set_option(ld, LDAP_OPT_DEBUG_LEVEL, &opt);

   printf("running: ldap_search_ext_s()\n");
   if ((lerr = ldap_search_ext_s(ld, NULL, LDAP_SCOPE_SUB, "(mail=syzdek@mosquitonet.com)", NULL, 0, NULL, NULL, NULL, -1, &res)))
   {
      fprintf(stderr, "ldap_search_ext_s(): %s\n", ldap_err2string(lerr));
      ldap_unbind_ext_s(ld, NULL, NULL);
      return(1);
   };

   printf("running: ldap_count_entries()\n");
   if (!(count = ldap_count_entries(ld, res)))
   {
      ldap_msgfree(res);
      ldap_unbind_ext_s(ld, NULL, NULL);
      return(1);
   };
   printf("# %i entries found\n", count);

   printf("running: ldap_unbind_ext_s()\n");
   ldap_unbind_ext_s(ld, NULL, NULL);

   return(0);
}
