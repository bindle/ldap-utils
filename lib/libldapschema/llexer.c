
/*
 *  LDAP Utilities
 *  Copyright (C) 2012, 2019 David M. Syzdek <david@syzdek.net>.
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
 *   @file src/ldapschema/llexer.c  contains error functions and variables
 */
#define _LIB_LIBLDAPSCHEMA_LLEXER_C 1
#include "llexer.h"

//
//  RFC 4512                      LDAP Models                      June 2006
//
//  4.1.  Schema Definitions
//
//     Schema definitions in this section are described using ABNF and rely
//     on the common productions specified in Section 1.2 as well as these:
//
//        noidlen = numericoid [ LCURLY len RCURLY ]
//        len = number
//
//        oids = oid / ( LPAREN WSP oidlist WSP RPAREN )
//        oidlist = oid *( WSP DOLLAR WSP oid )
//
//        extensions = *( SP xstring SP qdstrings )
//        xstring = "X" HYPHEN 1*( ALPHA / HYPHEN / USCORE )
//
//        qdescrs = qdescr / ( LPAREN WSP qdescrlist WSP RPAREN )
//        qdescrlist = [ qdescr *( SP qdescr ) ]
//        qdescr = SQUOTE descr SQUOTE
//
//        qdstrings = qdstring / ( LPAREN WSP qdstringlist WSP RPAREN )
//        qdstringlist = [ qdstring *( SP qdstring ) ]
//        qdstring = SQUOTE dstring SQUOTE
//        dstring = 1*( QS / QQ / QUTF8 )   ; escaped UTF-8 string
//
//        QQ =  ESC %x32 %x37 ; "\27"
//        QS =  ESC %x35 ( %x43 / %x63 ) ; "\5C" / "\5c"
//
//        ; Any UTF-8 encoded Unicode character
//        ; except %x27 ("\'") and %x5C ("\")
//        QUTF8    = QUTF1 / UTFMB
//
//        ; Any ASCII character except %x27 ("\'") and %x5C ("\")
//        QUTF1    = %x00-26 / %x28-5B / %x5D-7F
//
//     Schema definitions in this section also share a number of common
//     terms.
//
//     The NAME field provides a set of short names (descriptors) that are
//     to be used as aliases for the OID.
//
//     The DESC field optionally allows a descriptive string to be provided
//     by the directory administrator and/or implementor.  While
//     specifications may suggest a descriptive string, there is no
//     requirement that the suggested (or any) descriptive string be used.
//
//     The OBSOLETE field, if present, indicates the element is not active.
//
//     Implementors should note that future versions of this document may
//     expand these definitions to include additional terms.  Terms whose
//     identifier begins with "X-" are reserved for private experiments and
//     are followed by <SP> and <qdstrings> tokens.
//

///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

/// splits string into arguments
/// @param[in]  lsd    Reference to allocated ldap_schema struct
/// @param[in]  str    contains the string representation of an LDAP defintion
/// @param[in]  strlen length of string
/// @param[out] argvp  stores the allocate array of definition arguments
///
/// @return    If successful, returns number of arguments stored in argvp. The
///            result must be freed using ldapschema_value_free(). If an error
///            is encounted, returns -1.  The error code can be retrieved
///            using ldapschema_errno().
/// @see       ldapschema_errno, ldapschema_value_free
int ldapschema_definition_split(LDAPSchema * lsd, const char * str,
   size_t strlen, char *** argvp)
{
   char        ** argv;
   char         * line;
   char           encap;   // encapsulating character for segments
   int            argc;    // argument counts
   size_t         bol;     // beginning of line index
   size_t         bos;     // beginning of segment index
   size_t         eol;     // end of line index
   size_t         line_len;
   //size_t         len;
   size_t         pos;
   size_t         margin;
   void         * ptr;

   assert(lsd     != NULL);
   assert(str     != NULL);
   assert(argvp   != NULL);

   // finds opening and ending parentheses
   for(bol = 0; ((bol < strlen) && (str[bol] != '(')); bol++);
   for(eol = strlen-1; ((eol > bol) && (str[eol] != ')')); eol--);
   if ( (str[bol] != '(') || (eol <= bol) || (str[eol] != ')') )
   {
      lsd->errcode = LDAPSCHEMA_INVALID_DEFINITION;
      return(-1);
   };

   // allocates mutable string
   line_len = (eol - bol - 1); // adjusts for beginning of line>
   if ((line = malloc(line_len+1)) == NULL)
   {
      lsd->errcode = LDAPSCHEMA_NO_MEMORY;
      return(-1);
   };
   strncpy(line, &str[bol+1], line_len);
   line[line_len] = '\0';

   // initializes argument list
   if ((argv = malloc(sizeof(char *))) == NULL)
   {
      free(line);
      lsd->errcode = LDAPSCHEMA_NO_MEMORY;
      return(-1);
   };
   argv[0]  = NULL;
   argc     = 0;
   margin   = 0;

   // splits line into multiple line segments and adds to argument list
   for(pos = 0; (pos < line_len); pos++)
   {
      switch(line[pos])
      {
         // skip white spaces
         case '\t':
         case ' ':
            break;

         // processes quoted and grouped arguments
         case '\'':
         case '(':
            // stores beginning of segment
            bos = pos;

            // determines line segment terminating character
            encap = '\'';
            if (line[pos] == '(')
               encap = ')';

            // determines data margin
            margin = 0;
            if (line[pos] == '\'')
               margin = 1;

            // finds end of line segment
            for(pos = pos+1; ((line[pos] != encap) && (line[pos] != '\0')); pos++);
            if (line[pos] == '\0')
            {
               free(line);
               ldapschema_value_free(argv);
               lsd->errcode = LDAPSCHEMA_INVALID_DEFINITION;
               return(-1);
            };

            // terminates line segment
            pos++;
            line[pos-margin] = '\0';

            // adds argument to argv
            if ((ptr = ldapschema_value_add(argv, &line[bos+margin], &argc)) == NULL)
            {
               free(line);
               ldapschema_value_free(argv);
               lsd->errcode = LDAPSCHEMA_NO_MEMORY;
               return(-1);
            };
            argv = ptr;
            break;

         // process unquoted ungrouped arguments
         default:
            // stores beginning of segment
            bos = pos;

            // finds end of line segment
            for(pos = pos+1; ((line[pos] != ' ') && (line[pos] != '\0')); pos++);
            if (line[pos] == '\0')
            {
               free(line);
               ldapschema_value_free(argv);
               lsd->errcode = LDAPSCHEMA_INVALID_DEFINITION;
               return(-1);
            };
            line[pos] = '\0';

            // adds argument to argv
            if ((ptr = ldapschema_value_add(argv, &line[bos], &argc)) == NULL)
            {
               free(line);
               ldapschema_value_free(argv);
               lsd->errcode = LDAPSCHEMA_NO_MEMORY;
               return(-1);
            };
            argv = ptr;
            break;
      };
   };

   // release resources
   free(line);

   *argvp = argv;

   return(argc);
}


/// splits string into arguments
/// @param[in]  lsd    Reference to allocated ldap_schema struct
/// @param[in]  def    contains the string representation of an LDAP defintion
/// @param[out] argvp  stores the allocate array of definition arguments
///
/// @return    If successful, returns number of arguments stored in argvp. The
///            result must be freed using ldapschema_value_free(). If an error
///            is encounted, returns -1.  The error code can be retrieved
///            using ldapschema_errno().
/// @see       ldapschema_errno, ldapschema_value_free
int ldapschema_definition_split_len(LDAPSchema * lsd, const struct berval * def, char *** argvp )
{
   assert(lsd   != NULL);
   assert(def   != NULL);
   assert(argvp != NULL);
   return(ldapschema_definition_split(lsd, def->bv_val, def->bv_len, argvp));
}


/// parses an LDAP syntax definition string
/// @param[in]    lsd         Reference to pointer used to store allocated ldap_schema struct.
/// @param[in]    def         Reference to pointer used to store allocated ldap_schema struct.
///
/// @return    If the definition was successfully parsed, an LDAPSchemaAttributeType
///            object is added to the schema returned. NULL is returned if
///            an error was encountered.  Use ldapschema_errno() to obtain
///            the error.
/// @see       ldapschema_errno, ldapschema_attributetype_free
LDAPSchemaAttributeType * ldapschema_parse_attributetype(LDAPSchema * lsd, const struct berval * def)
{
   //
   //  RFC 4512                      LDAP Models                      June 2006
   //
   //  4.1.2.  Attribute Types
   //
   //     Attribute Type definitions are written according to the ABNF:
   //
   //       AttributeTypeDescription = LPAREN WSP
   //           numericoid                    ; object identifier
   //           [ SP "NAME" SP qdescrs ]      ; short names (descriptors)
   //           [ SP "DESC" SP qdstring ]     ; description
   //           [ SP "OBSOLETE" ]             ; not active
   //           [ SP "SUP" SP oid ]           ; supertype
   //           [ SP "EQUALITY" SP oid ]      ; equality matching rule
   //           [ SP "ORDERING" SP oid ]      ; ordering matching rule
   //           [ SP "SUBSTR" SP oid ]        ; substrings matching rule
   //           [ SP "SYNTAX" SP noidlen ]    ; value syntax
   //           [ SP "SINGLE-VALUE" ]         ; single-value
   //           [ SP "COLLECTIVE" ]           ; collective
   //           [ SP "NO-USER-MODIFICATION" ] ; not user modifiable
   //           [ SP "USAGE" SP usage ]       ; usage
   //           extensions WSP RPAREN         ; extensions
   //
   //       usage = "userApplications"     /  ; user
   //               "directoryOperation"   /  ; directory operational
   //               "distributedOperation" /  ; DSA-shared operational
   //               "dSAOperation"            ; DSA-specific operational
   //
   //     where:
   //       <numericoid> is object identifier assigned to this attribute type;
   //       NAME <qdescrs> are short names (descriptors) identifying this
   //           attribute type;
   //       DESC <qdstring> is a short descriptive string;
   //       OBSOLETE indicates this attribute type is not active;
   //       SUP oid specifies the direct supertype of this type;
   //       EQUALITY, ORDERING, and SUBSTR provide the oid of the equality,
   //           ordering, and substrings matching rules, respectively;
   //       SYNTAX identifies value syntax by object identifier and may suggest
   //           a minimum upper bound;
   //       SINGLE-VALUE indicates attributes of this type are restricted to a
   //           single value;
   //       COLLECTIVE indicates this attribute type is collective
   //           [X.501][RFC3671];
   //       NO-USER-MODIFICATION indicates this attribute type is not user
   //           modifiable;
   //       USAGE indicates the application of this attribute type; and
   //       <extensions> describe extensions.
   //
   //     Each attribute type description must contain at least one of the SUP
   //     or SYNTAX fields.  If no SYNTAX field is provided, the attribute type
   //     description takes its value from the supertype.
   //
   //     If SUP field is provided, the EQUALITY, ORDERING, and SUBSTRING
   //     fields, if not specified, take their value from the supertype.
   //
   //     Usage of userApplications, the default, indicates that attributes of
   //     this type represent user information.  That is, they are user
   //     attributes.
   //
   //     A usage of directoryOperation, distributedOperation, or dSAOperation
   //     indicates that attributes of this type represent operational and/or
   //     administrative information.  That is, they are operational
   //     attributes.
   //
   //     directoryOperation usage indicates that the attribute of this type is
   //     a directory operational attribute.  distributedOperation usage
   //     indicates that the attribute of this type is a DSA-shared usage
   //     operational attribute.  dSAOperation usage indicates that the
   //     attribute of this type is a DSA-specific operational attribute.
   //
   //     COLLECTIVE requires usage userApplications.  Use of collective
   //     attribute types in LDAP is discussed in [RFC3671].
   //
   //     NO-USER-MODIFICATION requires an operational usage.
   //
   //     Note that the <AttributeTypeDescription> does not list the matching
   //     rules that can be used with that attribute type in an extensibleMatch
   //     search filter [RFC4511].  This is done using the 'matchingRuleUse'
   //     attribute described in Section 4.1.4.
   //
   //     This document refines the schema description of X.501 by requiring
   //     that the SYNTAX field in an <AttributeTypeDescription> be a string
   //     representation of an object identifier for the LDAP string syntax
   //     definition, with an optional indication of the suggested minimum
   //     bound of a value of this attribute.
   //
   //     A suggested minimum upper bound on the number of characters in a
   //     value with a string-based syntax, or the number of bytes in a value
   //     for all other syntaxes, may be indicated by appending this bound
   //     count inside of curly braces following the syntax's OBJECT IDENTIFIER
   //     in an Attribute Type Description.  This bound is not part of the
   //     syntax name itself.  For instance, "1.3.6.4.1.1466.0{64}" suggests
   //     that server implementations should allow a string to be 64 characters
   //     long, although they may allow longer strings.  Note that a single
   //     character of the Directory String syntax may be encoded in more than
   //     one octet since UTF-8 [RFC3629] is a variable-length encoding.
   //
   char                       ** argv;
   //int                           i;
   int64_t                       pos;
   int                           argc;
   int                           err;
   LDAPSchemaAttributeType     * attr;

   attr     = NULL;
   argv     = NULL;

   // initialize attributeType
   if ((attr = ldapschema_attributetype_initialize(lsd)) == NULL)
      return(NULL);

   // parses definition
   if ((argc = ldapschema_definition_split_len(lsd, def, &argv)) == -1)
   {
      ldapschema_attributetype_free(attr);
      return(NULL);
   };

   // copy definition and oid into syntax
   if ((attr->model.oid = strdup(argv[0])) == NULL)
   {
      lsd->errcode = LDAPSCHEMA_NO_MEMORY;
      ldapschema_value_free(argv);
      ldapschema_attributetype_free(attr);
      return(NULL);
   };
   if ((attr->model.definition = malloc(def->bv_len+1)) == NULL)
   {
      lsd->errcode = LDAPSCHEMA_NO_MEMORY;
      ldapschema_value_free(argv);
      ldapschema_attributetype_free(attr);
      return(NULL);
   };
   memcpy(attr->model.definition, def->bv_val, def->bv_len);
   attr->model.definition[def->bv_len] = '\0';

   // processes attribute definition
   for(pos = 1; pos < argc; pos++)
   {
      // inteprets extensions
      if (!(strncasecmp(argv[pos], "X-", 2)))
      {
         if ((err = ldapschema_parse_ext(lsd, &attr->model, argv[pos], argv[pos+1])))
         {
            ldapschema_attributetype_free(attr);
            ldapschema_value_free(argv);
            return(NULL);
         };
         pos++;
      }

      // inteprets attributeType NAME
      else if (!(strcasecmp(argv[pos], "NAME")))
      {
         pos++;
         if (argv[pos][0] == '(')
         {
            if ((err = ldapschema_definition_split(lsd, argv[pos], strlen(argv[pos]), &attr->names)) == -1)
            {
               ldapschema_value_free(argv);
               ldapschema_attributetype_free(attr);
               return(NULL);
            };
            attr->names_len = (size_t)ldapschema_count_values(attr->names);
         }
         else
         {
            if ((attr->names = malloc(sizeof(char *)*2)) == NULL)
            {
               lsd->errcode = LDAPSCHEMA_NO_MEMORY;
               ldapschema_value_free(argv);
               ldapschema_attributetype_free(attr);
               return(NULL);
            };
            attr->names[1]  = NULL;
            attr->names_len = 1;
            if ((attr->names[0] = strdup(argv[pos])) == NULL)
            {
               lsd->errcode = LDAPSCHEMA_NO_MEMORY;
               ldapschema_value_free(argv);
               ldapschema_attributetype_free(attr);
               return(NULL);
            };
         };
      }

      // inteprets attributeType DESC
      else if (!(strcasecmp(argv[pos], "DESC")))
      {
         pos++;
         if (pos >= argc)
         {
            lsd->errcode = LDAPSCHEMA_INVALID_DEFINITION;
            ldapschema_value_free(argv);
            ldapschema_attributetype_free(attr);
            return(NULL);
         };
         if ((attr->model.desc))
            free(attr->model.desc);
         if ((attr->model.desc = strdup(argv[pos])) == NULL)
         {
            lsd->errcode = LDAPSCHEMA_NO_MEMORY;
            ldapschema_value_free(argv);
            ldapschema_attributetype_free(attr);
            return(NULL);
         };
      }

      // inteprets attributeType OBSOLETE
      else if (!(strcasecmp(argv[pos], "OBSOLETE")))
      {
         attr->model.flags |= LDAPSCHEMA_O_OBSOLETE;
      }

      // inteprets attributeType SUP
      else if (!(strcasecmp(argv[pos], "SUP")))
      {
         pos++;
         if ((attr->sup_name))
            free(attr->sup_name);
         if ((attr->sup_name = strdup(argv[pos])) == NULL)
         {
            lsd->errcode = LDAPSCHEMA_NO_MEMORY;
            ldapschema_value_free(argv);
            ldapschema_attributetype_free(attr);
            return(NULL);
         };
      }

      // inteprets attributeType EQUALITY
      else if (!(strcasecmp(argv[pos], "EQUALITY")))
      {
         pos++;
      }

      // inteprets attributeType ORDERING
      else if (!(strcasecmp(argv[pos], "ORDERING")))
      {
         pos++;
      }

      // inteprets attributeType SUBSTR
      else if (!(strcasecmp(argv[pos], "SUBSTR")))
      {
         pos++;
      }

      // inteprets attributeType SYNTAX
      else if (!(strcasecmp(argv[pos], "SYNTAX")))
      {
         pos++;
         attr->syntax = ldapschema_oid(lsd, argv[pos], LDAPSCHEMA_SYNTAX);
      }

      // inteprets attributeType SINGLE-VALUE
      else if (!(strcasecmp(argv[pos], "SINGLE-VALUE")))
      {
         attr->model.flags |= LDAPSCHEMA_O_SINGLEVALUE;
      }

      // inteprets attributeType COLLECTIVE
      else if (!(strcasecmp(argv[pos], "COLLECTIVE")))
      {
         attr->model.flags |= LDAPSCHEMA_O_COLLECTIVE;
      }

      // inteprets attributeType NO-USER-MODIFICATION
      else if (!(strcasecmp(argv[pos], "NO-USER-MODIFICATION")))
      {
         attr->model.flags |= LDAPSCHEMA_O_NO_USER_MOD;
      }

      // inteprets attributeType USAGE
      else if (!(strcasecmp(argv[pos], "USAGE")))
      {
         pos++;
         if (!(strcasecmp(argv[pos], "userApplications")))
            attr->usage = LDAPSCHEMA_USER_APP;
         else if (!(strcasecmp(argv[pos], "directoryOperation")))
            attr->usage = LDAPSCHEMA_DIRECTORY_OP;
         else if (!(strcasecmp(argv[pos], "distributedOperation")))
            attr->usage = LDAPSCHEMA_DISTRIBUTED_OP;
         else if (!(strcasecmp(argv[pos], "dSAOperation")))
            attr->usage = LDAPSCHEMA_DSA_OP;
         else
         {
            lsd->errcode = LDAPSCHEMA_INVALID_DEFINITION;
            ldapschema_value_free(argv);
            ldapschema_attributetype_free(attr);
            return(NULL);
         };
      }

      // handle unknown parameters
      else
      {
         lsd->errcode = LDAPSCHEMA_INVALID_DEFINITION;
         ldapschema_value_free(argv);
         ldapschema_attributetype_free(attr);
         return(NULL);
      };
   };
   ldapschema_value_free(argv);

   // adds syntax into OID list
   if ((ldapschema_insert(lsd, &lsd->oids, &lsd->oids_len, attr, ldapschema_model_cmp)) != LDAP_SUCCESS)
   {
      ldapschema_attributetype_free(attr);
      return(NULL);
   };

   // adds syntax into attributeType list
   if ((ldapschema_insert(lsd, (void ***)&lsd->attrs, &lsd->attrs_len, attr, ldapschema_model_cmp)) != LDAP_SUCCESS)
   {
      ldapschema_attributetype_free(attr);
      return(NULL);
   };

   return(attr);
}


/// parses extension
/// @param[in]  lsd    Reference to allocated ldap_schema struct
///
/// @see       ldapschema_initialize
int ldapschema_parse_ext(LDAPSchema * lsd, LDAPSchemaModel * model, const char * key, const char * valstr)
{
   int                        err;
   LDAPSchemaExtension      * ext;

   assert(lsd    != NULL);
   assert(model  != NULL);
   assert(key    != NULL);
   assert(valstr != NULL);

   // initialize extension
   if ((ext = ldapschema_ext_initialize(lsd, key)) == NULL)
      return(-1);

   // copies values
   if (valstr[0] != '(')
   {
      if ((ext->values = malloc(sizeof(char *)*2)) == NULL)
      {
         lsd->errcode = LDAPSCHEMA_NO_MEMORY;
         ldapschema_ext_free(ext);
         return(-1);
      };
      ext->values[1] = NULL;
      if ((ext->values[0] = strdup(valstr)) == NULL)
      {
         free(ext->values);
         lsd->errcode = LDAPSCHEMA_NO_MEMORY;
         ldapschema_ext_free(ext);
         return(-1);
      };
      ext->values_len = 1;
   }
   else
   {
      if ((err = ldapschema_definition_split(lsd, valstr, strlen(valstr), &ext->values)) != LDAPSCHEMA_SUCCESS)
      {
         ldapschema_ext_free(ext);
         return(-1);
      };
   };

   if ((err = ldapschema_insert(lsd, (void ***)&model->extensions, &model->extensions_len, ext, ldapschema_extension_cmp)) != LDAP_SUCCESS)
   {
      ldapschema_ext_free(ext);
      return(-1);
   };

   return(0);
}


/// parses an LDAP syntax definition string
/// @param[in]    lsd         Reference to pointer used to store allocated ldap_schema struct.
/// @param[in]    def         Reference to pointer used to store allocated ldap_schema struct.
///
/// @return    If the definition was successfully parsed, an LDAPSchemaSyntax
///            object is added to the schema returned. NULL is returned if
///            an error was encountered.  Use ldapschema_errno() to obtain
///            the error.
/// @see       ldapschema_errno, ldapschema_syntax_free
LDAPSchemaSyntax * ldapschema_parse_syntax(LDAPSchema * lsd, const struct berval * def)
{
   //
   //  RFC 4512                      LDAP Models                      June 2006
   //
   //  4.1.5.  LDAP Syntaxes
   //
   //     LDAP Syntaxes of (attribute and assertion) values are described in
   //     terms of ASN.1 [X.680] and, optionally, have an octet string encoding
   //     known as the LDAP-specific encoding.  Commonly, the LDAP-specific
   //     encoding is constrained to a string of Unicode [Unicode] characters
   //     in UTF-8 [RFC3629] form.
   //
   //     Each LDAP syntax is identified by an object identifier (OID).
   //
   //     LDAP syntax definitions are written according to the ABNF:
   //
   //       SyntaxDescription = LPAREN WSP
   //           numericoid                 ; object identifier
   //           [ SP "DESC" SP qdstring ]  ; description
   //           extensions WSP RPAREN      ; extensions
   //
   //     where:
   //       <numericoid> is the object identifier assigned to this LDAP syntax;
   //       DESC <qdstring> is a short descriptive string; and
   //       <extensions> describe extensions.
   //
   char                 ** argv;
   int64_t                 pos;
   int                     argc;
   int                     err;
   LDAPSchemaSyntax      * syntax;

   syntax   = NULL;
   argv     = NULL;

   // initialize syntax
   if ((syntax = ldapschema_syntax_initialize(lsd)) == NULL)
      return(syntax);

   // parses definition
   if ((argc = ldapschema_definition_split_len(lsd, def, &argv)) == -1)
   {
      ldapschema_syntax_free(syntax);
      return(NULL);
   };

   // copy definition and oid into syntax
   if ((syntax->model.oid = strdup(argv[0])) == NULL)
   {
      lsd->errcode = LDAPSCHEMA_NO_MEMORY;
      ldapschema_value_free(argv);
      ldapschema_syntax_free(syntax);
      return(NULL);
   };
   if ((syntax->model.definition = malloc(def->bv_len+1)) == NULL)
   {
      lsd->errcode = LDAPSCHEMA_NO_MEMORY;
      ldapschema_value_free(argv);
      ldapschema_syntax_free(syntax);
      return(NULL);
   };
   memcpy(syntax->model.definition, def->bv_val, def->bv_len);
   syntax->model.definition[def->bv_len] = '\0';

   // processes attribute definition
   for(pos = 1; pos < argc; pos++)
   {
      // inteprets extensions
      if (!(strncasecmp(argv[pos], "X-", 2)))
      {
         if ((err = ldapschema_parse_ext(lsd, &syntax->model, argv[pos], argv[pos+1])))
         {
            ldapschema_syntax_free(syntax);
            ldapschema_value_free(argv);
            return(NULL);
         };
         pos++;
      }

      // inteprets syntax DESC
      else if (!(strcasecmp(argv[pos], "DESC")))
      {
         pos++;
         if (pos >= argc)
         {
            lsd->errcode = LDAPSCHEMA_INVALID_DEFINITION;
            ldapschema_value_free(argv);
            ldapschema_syntax_free(syntax);
            return(NULL);
         };
         if ((syntax->model.desc))
            free(syntax->model.desc);
         if ((syntax->model.desc = strdup(argv[pos])) == NULL)
         {
            lsd->errcode = LDAPSCHEMA_NO_MEMORY;
            ldapschema_value_free(argv);
            ldapschema_syntax_free(syntax);
            return(NULL);
         };
      }

      // handle unknown parameters
      else
      {
         lsd->errcode = LDAPSCHEMA_INVALID_DEFINITION;
         ldapschema_value_free(argv);
         ldapschema_syntax_free(syntax);
         return(NULL);
      };
   };
   ldapschema_value_free(argv);

   // adds syntax into OID list
   if ((ldapschema_insert(lsd, &lsd->oids, &lsd->oids_len, syntax, ldapschema_model_cmp)) != LDAP_SUCCESS)
   {
      ldapschema_syntax_free(syntax);
      return(NULL);
   };

   if ((ldapschema_insert(lsd, (void ***)&lsd->syntaxes, &lsd->syntaxes_len, syntax, ldapschema_model_cmp)) != LDAP_SUCCESS)
   {
      ldapschema_syntax_free(syntax);
      return(NULL);
   };


   return(syntax);
}


/* end of source file */
