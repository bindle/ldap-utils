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
#include <stdlib.h>
#include <assert.h>

extern int    yylineno;
extern char * yytext;
extern const char * my_filename;

int yylex(void);
void yyerror(char *s);

int my_append(const char * str);

%}

%union
{
   int    num;
   char   id;
   char * str;
} 

%token NULLSTR
%token FLD_ABFN
%token FLD_CLASS
%token FLD_DEF
%token FLD_DESC
%token FLD_FLAGS
%token FLD_NAME
%token FLD_OID
%token FLD_RE_POSIX
%token FLD_RE_PCRE
%token FLD_SPEC
%token FLD_SPEC_NAME
%token FLD_SPEC_SECTION
%token FLD_SPEC_SOURCE
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


stanzas			: /* empty */
			| stanzas stanza ';'
			;

stanza			:
			| '{' fields '}' 		{ printf("%s: %i: stanza complete\n", my_filename, yylineno); }
			;

fields			:
			| fields field ','
			;

field			:
			| FLD_ABFN      '=' strings 	{ printf("   .abfn         =\n"); }
			| FLD_CLASS     '=' CLASS 	{ printf("   .class        = %s\n", $3); }
			| FLD_DESC      '=' CSTRING 	{ printf("   .desc         = %s\n", $3); }
			| FLD_DEF       '=' CSTRING 	{ printf("   .def          = %s\n", $3); }
			| FLD_FLAGS     '=' flags	{ printf("   .flags        =\n"); }
			| FLD_NAME      '=' CSTRING 	{ printf("   .name         = %s\n", $3); }
			| FLD_OID       '=' CSTRING 	{ printf("   .oid          = %s\n", $3); }
			| FLD_RE_PCRE   '=' strings 	{ printf("   .re_pcre      =\n"); }
			| FLD_RE_POSIX  '=' strings 	{ printf("   .re_posix     =\n"); }
			| FLD_SPEC      '=' CSTRING 	{ printf("   .spec         = %s\n", $3); }
			| FLD_SPEC_NAME '=' CSTRING 	{ printf("   .spec_name    = %s\n", $3); }
			| FLD_SPEC_SECTION '=' CSTRING 	{ printf("   .spec_section = %s\n", $3); }
			| FLD_SPEC_SOURCE '=' strings	{ printf("   .spec_source  =\n"); }
			| FLD_SPEC_VENDOR '=' string 	{ printf("   .spec_vendor  =\n"); }
			| FLD_SPEC_TYPE '=' SPEC_TYPE 	{ printf("   .spec_type    = %s\n", $3); }
			| FLD_TYPE      '=' TYPE	{ printf("   .type         = %s\n", $3); }
			;

string			:
			| NULLSTR			{ my_append("NULL"); }
			| CSTRING			{ my_append($1); }
			;

strings			:
			| NULLSTR			{ my_append("NULL"); }
			| strings CSTRING		{ my_append($2); }
			;

flags			:
			| FLAG 				{ my_append($1); }
			| flags '|' FLAG 		{ my_append($3); }
			;


%%

void yyerror (char *s)
{
   fprintf(stderr, "%s: %i: %s\n", my_filename, yylineno, s);
   fprintf(stderr, "string: %s\n", yytext);
   return;
}


/* end of yacc */
