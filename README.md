

LDAP Utilities
==============

Copyright (c) 2012, 2015, 2019 David M. Syzdek <david@syzdek.net>

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.

   3. Neither the name of the copyright holder nor the names of its
      contributors may be used to endorse or promote products derived from
      this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


Contents
--------

   * Overview
   * Software Requirements
   * Utilities
     - ldap2csv
     - ldaptree
   * Source Code
   * Package Maintence Notes


Overview
==========

This package contains miscellaneous utilties to assist in fullfilling requests
for data and in performing maintenance on LDAP servers.  When applicable, the
corresponding command line switches from the OpenLDAP tools were used in this
package.


Software Requirements
=====================

   * GNU GCC 4.2.1
   * GNU Libtool 2.4
   * GNU Autoconf 2.65
   * GNU Automake 1.11.1
   * Git 1.7.2.3
   * OpenLDAP 2.4.X


Utilities
=========

ldap2csv
--------

ldap2csv is a shell utilty which performs an LDAP search and prints the results
in CSV format.  ldap2csv requires that a search filter and at least 1 attribute
be specified on the CLI.  Each specified attribute will be used as a field
in the CSV file.  Multiple values for a given attribute are sorted and separated
by a pipe ('|') chracter. Each double quote ('"') character found in a returned
value will be replaced with a single quote ('\'') chracter. Each pipe ('|')
character found in a returned value will be replaced with a colon (':')
character.

Example usage:

      $ ldap2csv -S sn '(uid=*)' uid givenname sn mail
      "dnullman","Devian","Nullman","noreply@example.com"
      "jdough","John","Dough","doughboy42@example.com"
      "syzdek","David M.","Syzdek","david@syzdek.net"
      $


ldaptree
--------

ldaptree is a shell utilty which performs an LDAP search and prints the results
as either an ASCII graph or a bulletted list.  By default the utilty does not
retrieve any attributes from LDAP servers, however if a search filter and
attribute list are provided as command line arguments, then the attribute values
will be displayed inline with the results.  The utility utilizes additional long
options to customize the output of either the ASCII graph or the bulletted list.

ASCII graph eexample with compact output and no leaf nodes:

      $ ldaptree --noleafs --compact
      +--dc=net, o=internet
          +--dc=example
          |  +--ou=Groups
          |  \--ou=People
          \--dc=syzdek
             +--ou=Groups
             \--ou=People

ASCII graph example with attribute values:

      $ ldaptree '(objectclass=*)' givenname sn mail member description
      +--dc=net, o=internet
          +--dc=example
          |  +--ou=Groups
          |  |  +--cn=lug
          |  |  |     description: Linux Users' Group
          |  |  |     member: uid=dnullman,ou=People,dc=example,dc=net,o=internet
          |  |  |     member: uid=doughboy42,ou=People,dc=example,dc=net,o=internet
          |  |  |
          |  |  \--cn=foodie
          |  |        description: People obsessed with good food
          |  |        member: uid=doughboy42,ou=People,dc=example,dc=net,o=internet
          |  |  
          |  \--ou=People
          |     +--uid=dnullman
          |     |     sn: Nullman
          |     |     givenName: Devian
          |     |     mail: noreply@example.com
          |     |
          |     \--uid=jdough
          |           sn: Dough
          |           givenName: John
          |           mail: doughboy42@example.com
          |      
          \--dc=syzdek
             +--ou=Groups
             \--ou=People
                \--uid=syzdek
                      sn: Syzdek
                      givenName: David M.
                      mail: david@syzdek.net

Bulleted list example:

      $ ldaptree --style=bullets --compact '(objectclass=*)' givenname sn \
      > mail member description
      * dc=net, o=internet
        * dc=example
          * ou=Groups
            * cn=lug
              * Attributes
                - description: Linux Users' Group
                - member: uid=dnullman,ou=People,dc=example,dc=net,o=internet
                - member: uid=doughboy42,ou=People,dc=example,dc=net,o=internet
            * cn=foodie
              * Attributes
                - description: People obsessed with good food
                - member: uid=doughboy42,ou=People,dc=example,dc=net,o=internet
          * ou=People
            * uid=dnullman
              * Attributes
                - sn: Nullman
                - givenName: Devian
                - mail: noreply@example.com
            * uid=jdough
                - sn: Dough
                - givenName: John
                - mail: doughboy42@example.com
        * dc=syzdek
          * ou=Groups
          * ou=People
            * uid=syzdek
              * Attributes
                - sn: Syzdek
                - givenName: David M.
                - mail: david@syzdek.net


Source Code
===========

The source code for this project is maintained using git
(http://git-scm.com).  The following contains information to checkout the
source code from the git repository.

Browse Source:

   * https://github.com/bindle/ldap-utils

Git URLs:

   * https://github.com/bindle/ldap-utils.git

Downloading Source:

      $ git clone git://github.com/bindle/ldap-utils.git

Preparing Source:

      $ cd ldap-utils
      $ ./autogen.sh

Compiling Source:

      $ cd build
      $ ./configure
      $ make && make install

For more information on building and installing using configure, please
read the INSTALL file.

Git Branches:

   * master - Current release of packages.
   * next   - changes staged for next release
   * pu     - proposed updates for next release
   * xx/yy+ - branch for testing new changes before merging to 'pu' branch


Package Maintence Notes
=======================

This is a collection of notes for developers to use when maintaining this
package.

New Release Checklist:

   - Switch to 'master' branch in Git repository.
   - Update version in configure.ac.
   - Update date and version in ChangeLog.
   - Commit configure.ac and ChangeLog changes to repository.
   - Create tag in git repository:

           $ git tag -s v${MAJOR}.${MINOR}

   - Push repository to publishing server:

           $ git push --tags origin master:master next:next pu:pu

Creating Source Distribution Archives:

      $ ./configure
      $ make update
      $ make distcheck
      $ make dist-bzip2

Creating Windows Binaries from OS X:

      $ export PATH=/usr/local/i386-mingw32/bin:${PATH}
      $ ./configure --host=i386-mingw32 --prefix=/tmp/ldap-utils \
        --enable-strictwarnings --enable-dependency-tracking
      $ make
      $ rm -fR /tmp/ldap-utils
      $ make install-strip


