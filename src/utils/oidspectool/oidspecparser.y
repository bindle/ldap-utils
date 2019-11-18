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

int my_add_oidspec(void);
int my_append(const char * str);
int my_commit(enum yytokentype type);
int my_commit_str(enum yytokentype type, const char * str);

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
			| '{' fields '}' 		{ my_add_oidspec(); }
			;

fields			:
			| fields field ','
			;

field			:
			| FLD_ABFN      '=' strings 	{ my_commit(FLD_ABFN); }
			| FLD_CLASS     '=' CLASS 	{ my_commit_str(FLD_CLASS, $3); }
			| FLD_DESC      '=' CSTRING 	{ my_commit_str(FLD_DESC, $3); }
			| FLD_DEF       '=' CSTRING 	{ my_commit_str(FLD_DEF, $3); }
			| FLD_FLAGS     '=' flags	{ my_commit(FLD_FLAGS); }
			| FLD_NAME      '=' CSTRING 	{ my_commit_str(FLD_NAME, $3); }
			| FLD_OID       '=' CSTRING 	{ my_commit_str(FLD_OID, $3); }
			| FLD_RE_PCRE   '=' strings 	{ my_commit(FLD_RE_PCRE); }
			| FLD_RE_POSIX  '=' strings 	{ my_commit(FLD_RE_POSIX); }
			| FLD_SPEC      '=' CSTRING 	{ my_commit_str(FLD_SPEC, $3); }
			| FLD_SPEC_NAME '=' CSTRING 	{ my_commit_str(FLD_SPEC_NAME, $3); }
			| FLD_SPEC_SECTION '=' CSTRING 	{ my_commit_str(FLD_SPEC_SECTION, $3); }
			| FLD_SPEC_SOURCE '=' strings	{ my_commit(FLD_SPEC_SOURCE); }
			| FLD_SPEC_VENDOR '=' string 	{ my_commit(FLD_SPEC_VENDOR); }
			| FLD_SPEC_TYPE '=' SPEC_TYPE 	{ my_commit_str(FLD_SPEC_TYPE, $3); }
			| FLD_TYPE      '=' TYPE	{ my_commit_str(FLD_TYPE, $3); }
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


/* end of yacc */
