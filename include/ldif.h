
#include <ldap.h>

typedef struct ldif_data LDIF;
typedef struct ldif_entry_data LDIFEntry;
typedef struct ldif_attribute_data LDIFAttribute;

struct ldif_entry_data
{
   int              changetype;
   int              attribute_count;
   int              dn_node_count;
   char           * dn;
   char          ** dn_nodes;
   LDIFAttribute  * attributes;
};

struct ldif_attribute_data
{
   int              changetype;
   char           * name;
   struct berval ** vals;
}

