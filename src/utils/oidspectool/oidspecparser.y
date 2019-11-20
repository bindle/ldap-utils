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
%{

#include <stdio.h>
#include "oidspectool.h"

int yylex(void);

%}

%union
{
   int    num;
   char   id;
   char * str;
} 

%token NULLSTR
%token CONST_CAST
%token FLD_ABNF
%token FLD_CLASS
%token FLD_DEF
%token FLD_DESC
%token FLD_EXAMPLES
%token FLD_FLAGS
%token FLD_IGNORE
%token FLD_NAME
%token FLD_NOTES
%token FLD_OID
%token FLD_RE_POSIX
%token FLD_RE_PCRE
%token FLD_SPEC
%token FLD_SPEC_NAME
%token FLD_SPEC_SECTION
%token FLD_SPEC_SOURCE
%token FLD_SPEC_TEXT
%token FLD_SPEC_TYPE
%token FLD_SPEC_VENDOR
%token FLD_TYPE
%token <str> CSTRING
%token <str> OIDSTR
%token <str> FLAG
%token <str> TYPE
%token <str> CLASS
%token <str> SPEC_TYPE

%start stanzas


%%


stanzas           : /* empty */
                  | stanzas stanza ';'
                  ;

stanza            :
                  | '{' NULLSTR '}'                   { ; }                /* ignore empty stanzas */
                  | '{' fields '}'                    { my_yyoidspec(); }
                  ;

fields            :
                  | fields field ','
                  ;

field             :
                  | FLD_ABNF         '=' strings      { my_yycommit( FLD_ABNF             ); }
                  | FLD_CLASS        '=' CLASS        { my_yysubmit( FLD_CLASS,        $3 ); }
                  | FLD_DESC         '=' CSTRING      { my_yysubmit( FLD_DESC,         $3 ); }
                  | FLD_DEF          '=' strings      { my_yycommit( FLD_DEF              ); }
                  | FLD_EXAMPLES     '=' examples     { my_yycommit( FLD_EXAMPLES         ); }
                  | FLD_FLAGS        '=' flags        { my_yycommit( FLD_FLAGS            ); }
                  | FLD_IGNORE       '=' NULLSTR      { my_yysubmit( FLD_IGNORE,   "NULL" ); }
                  | FLD_NAME         '=' CSTRING      { my_yysubmit( FLD_NAME,         $3 ); }
                  | FLD_NOTES        '=' strings      { my_yycommit( FLD_NOTES            ); }
                  | FLD_OID          '=' CSTRING      { my_yysubmit( FLD_OID,          $3 ); }
                  | FLD_RE_PCRE      '=' strings      { my_yycommit( FLD_RE_PCRE          ); }
                  | FLD_RE_POSIX     '=' strings      { my_yycommit( FLD_RE_POSIX         ); }
                  | FLD_SPEC         '=' CSTRING      { my_yysubmit( FLD_SPEC,         $3 ); }
                  | FLD_SPEC_NAME    '=' CSTRING      { my_yysubmit( FLD_SPEC_NAME,    $3 ); }
                  | FLD_SPEC_SECTION '=' CSTRING      { my_yysubmit( FLD_SPEC_SECTION, $3 ); }
                  | FLD_SPEC_SOURCE  '=' strings      { my_yycommit( FLD_SPEC_SOURCE      ); }
                  | FLD_SPEC_VENDOR  '=' string       { my_yycommit( FLD_SPEC_VENDOR      ); }
                  | FLD_SPEC_TEXT    '=' strings      { my_yycommit( FLD_SPEC_TEXT        ); }
                  | FLD_SPEC_TYPE    '=' SPEC_TYPE    { my_yysubmit( FLD_SPEC_TYPE,    $3 ); }
                  | FLD_TYPE         '=' TYPE         { my_yysubmit( FLD_TYPE,         $3 ); }
                  ;

string            :
                  | NULLSTR
                  | CSTRING                           { my_yyappend( $1     ); }
                  ;

strings           :
                  | NULLSTR
                  | strings CSTRING                   { my_yyappend( $2     ); }
                  ;

flags             :
                  | '0'
                  | FLAG                              { my_yyappend( $1 ); }
                  | flags '|' FLAG                    { my_yyappend( $3 ); }
                  ;

examples          :
                  | NULLSTR
                  | CONST_CAST '{' NULLSTR '}'
                  | CONST_CAST '{' NULLSTR ',' '}'
                  | CONST_CAST '{' snippets NULLSTR '}'
                  | CONST_CAST '{' snippets NULLSTR ',' '}'
                  ;

snippets          :
                  | snippets snippet ','
                  ;

snippet           :
                  | CSTRING                           { my_yyappend( $1     ); }
                  ;

%%


/* end of yacc */
