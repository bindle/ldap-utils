/*
 *  LDAP Utilities
 *  Copyright (C) 2012 Bindle Binaries <syzdek@bindlebinaries.com>.
 *
 *  @BINDLE_BINARIES_BSD_LICENSE_START@
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
 *  @BINDLE_BINARIES_BSD_LICENSE_END@
 */
/**
 *  @file src/ldaputils_config.c contains shared functions and variables
 */
#define _LIB_LIBLDAPUTILS_LPASSWD_C 1
#include "lpasswd.h"

///////////////
//           //
//  Headers  //
//           //
///////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Headers
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <stdlib.h>
#include <fcntl.h>
#include <assert.h>

#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif
#ifdef HAVE_SGTTY_H
#include <sgtty.h>
#endif


/////////////////
//             //
//  Functions  //
//             //
/////////////////
#ifdef __LDAPUTILS_PMARK
#pragma mark - Functions
#endif

/// getpass() replacement -- SUSV 2 deprecated getpass()
/// @param[in] prompt
char * ldaputils_getpass(const char * prompt)
{
   static char    buff[512];
   FILE         * fs;
   int            c;
   size_t         pos;
#if defined(HAVE_TERMIOS_H) || defined(HAVE_SGTTY_H)
   struct termios old;
   struct termios new;
   void          (*sig)( int sig );
#endif

   // prompts for password
   prompt = ((prompt)) ? prompt : "Password: ";
   if (prompt)
      fprintf(stderr, "%s", prompt);
   fflush(stdout);

   // disables ECHO
#ifdef HAVE_TERMIOS_H
   if ((fs = fopen("/dev/tty", "r")) == NULL)
      fs = stdin;
   if(tcgetattr(fileno(fs), &old) == -1)
      return(NULL);
   sig          = signal(SIGINT, SIG_IGN);
   new          = old;
   new.c_lflag &= ~ECHO;
   if(tcsetattr(fileno(fs), TCSANOW, &new))
      return(NULL);
#else
   fs = stdin;
#endif

   // reads buffer
   pos = 0;
   while ( ((c = getc(fs)) != EOF) && (c != '\n') && (c != '\r') )
      if (pos < (sizeof(buff)-1))
         buff[pos++] = (char)c;
   buff[pos] = '\0';
   
   // restores previous terminal
   fprintf(stderr, "\n");
#ifdef HAVE_TERMIOS_H
   fflush(stderr);
   if(tcsetattr(fileno(fs), TCSANOW, &old))
      return(NULL);
   signal(SIGINT, sig);
#endif

   return(buff);
}


/// retrieves password
/// @param[in] file  file containing the password
/// @param[in] buff  pointer to buffer for password
/// @param[in] len   length of the buffer
int ldaputils_pass(LDAPUtils * lud)
{
   char    * str;

   assert(lud != NULL);

   // exitting, already have password
   if ((lud->passwd.bv_len))
      return(LDAP_SUCCESS);

   // prompt for password
   if ((lud->want_pass))
   {
      if ((str = ldaputils_getpass("Enter LDAP Password: ")) == NULL)
      {
         fprintf(stderr, "%s: ldaputils_getpass(): unknown error\n", lud->prog_name);
         return(1);
      };
      if ((lud->passwd.bv_val = strdup(str)) == NULL)
      {
         fprintf(stderr, "%s: out of virtual memory\n", lud->prog_name);
         return(1);
      };
      lud->passwd.bv_len = strlen(str);
      return(LDAP_SUCCESS);
   };

   if ((lud->passfile))
      return(ldaputils_passfile(lud, lud->passfile, &lud->passwd.bv_val, &lud->passwd.bv_len));

   // read password from file
   return(LDAP_SUCCESS);
}



/// retrieves password from file
/// @param[in] file  file containing the password
/// @param[in] buff  pointer to buffer for password
/// @param[in] len   length of the buffer
int ldaputils_passfile(LDAPUtils * lud, const char * file, char ** valp, size_t * lenp)
{
   int           fd;
   ssize_t       len;
   char        * buff;
   struct stat   sb;

   assert(lud  != NULL);
   assert(file != NULL);
   assert(valp != NULL);

   // obtain file information
   if ((stat(file, &sb)) == -1)
   {
      fprintf(stderr, "%s: %s: %s\n", lud->prog_name, file, strerror(errno));
      return(1);
   };
   if (sb.st_mode & 0066)
      fprintf(stderr, "%s: Password file %s is publicly readable/writeable\n", lud->prog_name, file);

   // allocate buffer
   if ((buff = malloc((size_t)sb.st_size+2)) == NULL)
   {
      fprintf(stderr, "%s: malloc(): %s\n", lud->prog_name, strerror(errno));
      return(1);
   };

   // open and read file
   if ((fd = open(file, O_RDONLY)) == -1)
   {
      fprintf(stderr, "%s: %s: %s\n", lud->prog_name, file, strerror(errno));
      free(buff);
      return(1);
   };
   if ((len = read(fd, buff, (size_t)sb.st_size)) == -1)
   {
      fprintf(stderr, "%s: read(): %s\n", lud->prog_name, strerror(errno));
      free(buff);
      return(1);
   };
   close(fd);

   buff[sb.st_size]   = '\0';
   *valp = buff;
   if ((lenp))
      *lenp = (size_t)sb.st_size;
   
   return(LDAP_SUCCESS);
}

/* end of source file */
