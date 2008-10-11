/*
 *  LDAP Utilities
 *  Copyright (c) 2008 David M. Syzdek <ldap-utils-project@syzdek.net>.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
/**
 *  @file src/ldaputils_misc.c contains shared functions and variables
 */
#define _LDAP_UTILS_SRC_LDAPUTILS_MISC_C 1
#include "ldaputils_misc.h"

///////////////
//           //
//  Headers  //
//           //
///////////////

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif


/////////////////
//             //
//  Functions  //
//             //
/////////////////

/// removes newlines and carriage returns
/// @param[in] str
char * ldaputils_chomp(char * str)
{
   char * idx;

   if (!(str))
      return(NULL);

   if ((idx = strchr(str, '\n')))
      idx[0] = '\0';
   if ((idx = strchr(str, '\r')))
      idx[0] = '\0';

   return(str);
}


/// getpass() replacement -- SUSV 2 deprecated getpass()
/// @param[in] prompt
/// @param[in] buff
/// @param[in] len
int ldaputils_getpass(const char * prompt, char * buff, size_t size)
{
   /* declares local vars */
   int len;
#ifdef HAVE_TERMIOS_H
   struct termios old;
   struct termios new;
#endif

   /* clears memory and flusses buffer */
   memset(buff, 0, size);

   /* prompts for password */
   if (prompt)
      printf("%s", prompt);
   fflush(stdout);

   /* disables ECHO */
#ifdef HAVE_TERMIOS_H
   if(tcgetattr(STDIN_FILENO, &old) == -1)
      return(1);
   new          = old;
   new.c_lflag &= ~ECHO;
   if(tcsetattr(STDIN_FILENO, TCSAFLUSH, &new))
      return(1);
#endif

   /* reads buffer */
   if ((len = read(STDIN_FILENO, buff, size-1)) == -1)
      return(1);
   buff[len] = '\0';
   ldaputils_chomp(buff);

   /* restores previous terminal */
#ifdef HAVE_TERMIOS_H
   if(tcsetattr(STDIN_FILENO, TCSAFLUSH, &old))
      return(1);
#endif

   /* prints newline */
   printf("\n");

   /* ends function */
   return(0);
}


/* end of source file */
