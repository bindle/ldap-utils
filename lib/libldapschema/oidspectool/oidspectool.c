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
/**
 *  @file lib/libldapschema/oidspectool/oidspectool.c creates compilation of
 *  OID specifications
 */
/*
 *  Simple Build:
 *     export CFLAGS='-DPROGRAM_NAME="oidspectool" -Wall -I../include'
 *     yacc -d          oidspecparser.y
 *     mv   -f  y.tab.c oidspecparser.c
 *     mv       y.tab.h oidspecparser.h
 *     lex  -t          oidspeclexer.l > oidspeclexer.c
 *     gcc ${CFLAGS} -c oidspectool.c
 *     gcc ${CFLAGS} -c oidspecparser.c
 *     gcc ${CFLAGS} -c oidspeclexer.c
 *     gcc ${CFLAGS} -o oidspectool -ll oidspectool.o oidspecparser.o \
 *         oidspeclexer.o
 *
 *  Libtool Build:
 *     export CFLAGS='-DPROGRAM_NAME="oidspectool" -Wall -I../include'
 *     yacc -d          oidspecparser.y
 *     mv   -f  y.tab.c oidspecparser.c
 *     mv       y.tab.h oidspecparser.h
 *     lex  -t          oidspeclexer.l > oidspeclexer.c
 *     libtool --mode=compile --tag=CC gcc ${CFLAGS} -c oidspectool.c
 *     libtool --mode=compile --tag=CC gcc ${CFLAGS} -c oidspecparser.c
 *     libtool --mode=compile --tag=CC gcc ${CFLAGS} -c oidspeclexer.c
 *     libtool --mode=link    --tag=CC gcc ${CFLAGS} -o oidspectool -ll \
 *         oidspectool.o oidspecparser.o oidspeclexer.o
 *
 *  Libtool Clean:
 *     libtool --mode=clean rm -f oidspectool.lo oidspecparser.lo \
 *         oidspeclexer.lo oidspectool
 */
#define _LDAP_UTILS_LIB_LIBLDAPSCHEMA_OIDSPECTOOL 1

///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

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

#include "oidspecparser.h"


///////////////////
//               //
//  Definitions  //
//               //
///////////////////
#pragma mark - Definitions

#ifndef PROGRAM_NAME
#define PROGRAM_NAME "oidspectool"
#endif


/////////////////
//             //
//  Datatypes  //
//             //
/////////////////
#pragma mark - Datatypes


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

extern int errno;


//////////////////
//              //
//  Prototypes  //
//              //
//////////////////
#pragma mark - Prototypes

// main statement
int main(int argc, char * argv[]);

int oidspectool_parse(FILE *);

int yyparse (void);
void yyrestart (FILE *input_file);


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions

/// main statement
/// @param[in] argc   number of arguments
/// @param[in] argv   array of arguments
int main(int argc, char * argv[])
{
   FILE * fs;
   int    rc;

   assert(argc != -1);
   assert(argv != NULL);

   if (argc != 2)
   {
      printf("Usage: %s <file>\n", PROGRAM_NAME);
      return(1);
   };

   if ((fs = fopen(argv[1], "r")) == NULL)
   {
      fprintf(stderr, "%s: fopen(): %s\n", PROGRAM_NAME, strerror(errno));
      return(1);
   };

   yyrestart(fs);
   rc = yyparse();

   fclose(fs);

   printf("Exit code: %i\n", rc);

   return(rc);
}

/* end of source file */
