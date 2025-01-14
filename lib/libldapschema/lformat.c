
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
 *   @file lib/libldapschema/lformat.c  contains string formatting functions
 */
#define _LIB_LIBLDAPSCHEMA_LERROR_C 1
#include "lerror.h"

///////////////
//           //
//  Headers  //
//           //
///////////////
// MARK: - Headers

#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>

#include "llexer.h"


//////////////
//          //
//  Macros  //
//          //
//////////////
// MARK: - Macros

#define IS_SPACE( c )   ( (c == ' ') || (c == '\t') || (c == '\n') )
#define IS_UPPER( c )   ( (c >= 'A') && (c <= 'Z') )
#define IS_LOWER( c )   ( (c >= 'a') && (c <= 'z') )
#define IS_DIGIT( c )   ( (c >= '0') && (c <= '9') )
#define IS_KEYWORD( c ) ( IS_UPPER(c) || (c == '-') )
#define IS_STRNG( c )   ( IS_UPPER(c) || IS_LOWER(c) || IS_DIGIT(c) || (c=='_') || (c=='.') || (c=='{') || (c=='}') || (c == '-') )


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
// MARK: - Prototypes


/////////////////
//             //
//  Functions  //
//             //
/////////////////
// MARK: - Functions

#define APPEND( c ) { last = c; if (strpos<size) str[strpos] = last; strpos++; }
#define INDENT() { if ((!IS_SPACE(last))&&((strpos))) { APPEND('\n'); for(x=0; (x<(indent*3));x++) APPEND(' '); bol=strpos; }; }
/// initializes LDAP schema
/// @param[out]   str         output buffer to store formatted definition
/// @param[in]    size        size of output buffer
/// @param[in]    def         unformatted definition string.
/// @param[in]    width       column width for line wrapping
///
/// @return    Returns a string representation of the error code.
/// @see       ldapschema_free, ldapschema_initialize, ldapschema_errno
int
ldapschema_fmt_definition(
         char * restrict               str,
         size_t                        size,
         const char * restrict         def,
         size_t                        width )
{
   size_t      defpos;
   size_t      strpos;
   size_t      tmppos;
   size_t      bol;
   size_t      deflen;
   size_t      indent;
   size_t      x;
   size_t      keylen;
   char        last;

   assert(def != NULL);

   // strips leading white space
   for (defpos = 0; ((def[defpos] != '\0') && ((def[defpos] == ' ') || (def[defpos] == '\t'))); defpos++);

   if (!(str))
      size = 0;

   deflen   =  strlen(def);
   strpos   =  0;
   bol      =  0;
   last     =  0;

   // copies formatted definition
   for(indent = 0; (defpos < deflen); defpos++)
   {
      switch(def[defpos])
      {
         // process start of groupings
         case '(':
         INDENT( );
         indent++;
         APPEND( '(' );
         APPEND( ' ' );
         break;

         // process end of groupings
         case ')':
         indent--;
         INDENT( );
         APPEND( ')' );
         break;

         // process quoted strings
         case '\'':
         APPEND( ' ' );
         APPEND( def[defpos++] );
         while ((def[defpos] != '\'') && ((defpos+1) < deflen))   // find closing quote
         {
            APPEND( def[defpos++] );
         };
         APPEND( def[defpos] );
         break;

         // process whitespace
         case ' ':
         case '\t':
         case '\n':
         break;

         default:
         for(tmppos = defpos; IS_KEYWORD( def[tmppos] ); tmppos++);
         for(keylen = 0; IS_STRNG(def[keylen+defpos]); keylen++);
         if ( (tmppos != defpos) && (IS_SPACE(def[tmppos]) || (def[tmppos] == '\0')) )
         {
            // styling for upper case keywords
            INDENT( );
         } else if (def[defpos] == '$')
         {
            // styling for delimiters
            APPEND( ' ' );
         } else
         {
            // styling for unquoted strings
            if ((strpos - bol + keylen + 2 + (indent*3)) < width)
            {
               APPEND( ' ' );
            } else
            {
               INDENT( );
            };
         };
         for(; (IS_STRNG(def[defpos+1])); defpos++)
            APPEND( def[defpos] );
         APPEND( def[defpos] );
         break;
      };
   };

   // terminate string
   if ((str))
   {
      if (strpos < size)
         str[strpos] = '\0';
      else
         str[size-1] = '\0';
   };

   return((int)(strpos));
}
#undef APPEND
#undef INDENT


/* end of source file */
