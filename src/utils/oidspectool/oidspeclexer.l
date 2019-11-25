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

#include "oidspecparser.h"
void yyerror(char *s);
int yylex();

%}

%option nounput
%option yylineno
%option noinput

%%

"//"[^\n]*[\n]                      ; /* ignore C++ comments */
"/*".*"*/"                          ; /* ignore C comments */
[ \t\n]                             ; /* ignore whitespace */
"#"[a-zA-Z0-9]+[^\n]*[\n]           ; /* ignore C preprocessor directives */

"const "[^\n]+"="[^\n]*[\n]         ; /* ignore non-code blocks (allows oidspectool to process its own output) */
"&"[_a-zA-Z0-9]+","                 ; /* ignore pointer references (allows oidspectool to process its own output) */

"("[ \t]*"const"[ \t][ \t*\[\]a-zA-Z0-9_]+")"   { return(CONST_CAST); }

["]([^"]|[\\]["])*["]               { yylval.str = yytext; return(CSTRING); }
"NULL"                              { yylval.str = yytext; return(NULLSTR); }

"LDAPSCHEMA_O_SINGLEVALUE"          { yylval.str = yytext; return(FLAG); }
"LDAPSCHEMA_O_OBSOLETE"             { yylval.str = yytext; return(FLAG); }
"LDAPSCHEMA_O_COLLECTIVE"           { yylval.str = yytext; return(FLAG); }
"LDAPSCHEMA_O_NO_USER_MOD"          { yylval.str = yytext; return(FLAG); }
"LDAPSCHEMA_O_OBJECTCLASS"          { yylval.str = yytext; return(FLAG); }
"LDAPSCHEMA_O_READABLE"             { yylval.str = yytext; return(FLAG); }
"LDAPSCHEMA_O_COMMON_ABNF"          { yylval.str = yytext; return(FLAG); }
"LDAPSCHEMA_O_SCHEMA_ABNF"          { yylval.str = yytext; return(FLAG); }
"LDAPSCHEMA_O_DEPRECATED"           { yylval.str = yytext; return(FLAG); }

"LDAPSCHEMA_SYNTAX"                 { yylval.str = yytext; return(TYPE); }
"LDAPSCHEMA_MATCHINGRULES"          { yylval.str = yytext; return(TYPE); }
"LDAPSCHEMA_MATCHINGRULE"           { yylval.str = yytext; return(TYPE); }
"LDAPSCHEMA_ATTRIBUTETYPE"          { yylval.str = yytext; return(TYPE); }
"LDAPSCHEMA_OBJECTCLASS"            { yylval.str = yytext; return(TYPE); }
"LDAPSCHEMA_DITCONTENTRULE"         { yylval.str = yytext; return(TYPE); }
"LDAPSCHEMA_DITSTRUCTURERULE"       { yylval.str = yytext; return(TYPE); }
"LDAPSCHEMA_NAMEFORM"               { yylval.str = yytext; return(TYPE); }
"LDAPSCHEMA_FEATURE"                { yylval.str = yytext; return(TYPE); }
"LDAPSCHEMA_CONTROL"                { yylval.str = yytext; return(TYPE); }
"LDAPSCHEMA_EXTENSION"              { yylval.str = yytext; return(TYPE); }
"LDAPSCHEMA_UNSOLICITED"            { yylval.str = yytext; return(TYPE); }
"LDAPSCHEMA_ABNF"                   { yylval.str = yytext; return(TYPE); }

"LDAPSCHEMA_CLASS_UNKNOWN"          { yylval.str = yytext; return(SUBTYPE); }
"LDAPSCHEMA_CLASS_ASCII"            { yylval.str = yytext; return(SUBTYPE); }
"LDAPSCHEMA_CLASS_UTF8"             { yylval.str = yytext; return(SUBTYPE); }
"LDAPSCHEMA_CLASS_INTEGER"          { yylval.str = yytext; return(SUBTYPE); }
"LDAPSCHEMA_CLASS_UNSIGNED"         { yylval.str = yytext; return(SUBTYPE); }
"LDAPSCHEMA_CLASS_BOOLEAN"          { yylval.str = yytext; return(SUBTYPE); }
"LDAPSCHEMA_CLASS_DATA"             { yylval.str = yytext; return(SUBTYPE); }
"LDAPSCHEMA_CLASS_IMAGE"            { yylval.str = yytext; return(SUBTYPE); }
"LDAPSCHEMA_CLASS_AUDIO"            { yylval.str = yytext; return(SUBTYPE); }
"LDAPSCHEMA_CLASS_UTF8_MULTILINE"   { yylval.str = yytext; return(SUBTYPE); }

"LDAPSCHEMA_STRUCTURAL"             { yylval.str = yytext; return(SUBTYPE); }
"LDAPSCHEMA_ABSTRACT"               { yylval.str = yytext; return(SUBTYPE); }
"LDAPSCHEMA_AUXILIARY"              { yylval.str = yytext; return(SUBTYPE); }

"LDAPSCHEMA_USER_APP"               { yylval.str = yytext; return(SUBTYPE); }
"LDAPSCHEMA_DIRECTORY_OP"           { yylval.str = yytext; return(SUBTYPE); }
"LDAPSCHEMA_DISTRIBUTED_OP"         { yylval.str = yytext; return(SUBTYPE); }
"LDAPSCHEMA_DSA_OP"                 { yylval.str = yytext; return(SUBTYPE); }

"LDAPSCHEMA_SPEC_RFC"               { yylval.str = yytext; return(SPEC_TYPE); }
"LDAPSCHEMA_SPEC_URL"               { yylval.str = yytext; return(SPEC_TYPE); }

".abnf"                             { return(FLD_ABNF); }
".subtype"                          { return(FLD_SUBTYPE); }
".def"                              { return(FLD_DEF); }
".desc"                             { return(FLD_DESC); }
".flags"                            { return(FLD_FLAGS); }
".ignore"                           { return(FLD_IGNORE); }
".name"                             { return(FLD_NAME); }
".notes"                            { return(FLD_NOTES); }
".oid"                              { return(FLD_OID); }
".re_posix"                         { return(FLD_RE_POSIX); }
".re_pcre"                          { return(FLD_RE_PCRE); }
".spec_name"                        { return(FLD_SPEC_NAME); }
".spec_section"                     { return(FLD_SPEC_SECTION); }
".spec_source"                      { return(FLD_SPEC_SOURCE); }
".spec_type"                        { return(FLD_SPEC_TYPE); }
".spec_vendor"                      { return(FLD_SPEC_VENDOR); }
".spec_text"                        { return(FLD_SPEC_TEXT); }
".spec"                             { return(FLD_SPEC); }
".type"                             { return(FLD_TYPE); }
".examples"                         { return(FLD_EXAMPLES); }

.                                   { return((int) yytext[0]); } /* treat remaining as single character tokens */


%%

int yywrap (void) {return 1;}

/* end of lex */
