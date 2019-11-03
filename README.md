

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
     - ldap2json
     - ldapdebug
     - ldapdn2str
     - ldapinfo
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

ldap2csv supports psuedo attributes which return the DN of returned entries in
various formats.  The following are the supported psuedo attributes and examples
of their format:

   * `dn` (distinguished name of entry)
   * `dce` (DCE-style distinguished name)
   * `adc` (Active Directory canonical name)
   * `rdn` (relative distinguished name of entry)
   * `ufn` (User Friendly Name of DN)

Example usage:

      $ ldap2csv -LLL -x -b o=internet -S sn '(uid=*)' uid givenname sn mail title rdn
      "uid","givenname","sn","mail","title","rdn"
      "dnullman","Devian","Nullman","noreply@example.com","Linux Device : /dev/null","uid=dnullman"
      "jdough","John","Dough","doughboy42@example.com","'Dough' Master","uid=jdough"
      "syzdek","David M.","Syzdek","david@syzdek.net","Slackware Linux Administrator","uid=syzdek"
      $

Example of the same search using `ldapsearch`:

      $ ldapsearch -LLL -x -b o=internet -S sn '(uid=*)' uid givenname sn mail title 
      dn: uid=dnullman,ou=People,dc=example,dc=net,o=internet
      uid: dnullman
      givenname: Devian
      sn: Nullman
      mail: noreply@example.com
      title: Linux Device | /dev/null
       
      dn: uid=jdough,ou=People,dc=example,dc=net,o=internet
      uid: jdough
      givenname: John
      sn: Dough
      mail: doughboy42@example.com
      title: "Dough" Master
      
      dn: uid=syzdek,ou=People,dc=syzdek,dc=net,o=internet
      uid: syzdek
      givenname: David M.
      sn: Syzdek
      mail: david@syzdek.net
      title: Slackware Linux Administrator


ldap2json
---------

ldap2json is a shell utilty which performs an LDAP search and prints the results
in JSON format.  

ldap2json supports psuedo attributes which return the DN of returned entries in
various formats.  The following are the supported psuedo attributes and examples
of their format:

   * `dn` (distinguished name of entry)
   * `dce` (DCE-style distinguished name)
   * `adc` (Active Directory canonical name)
   * `rdn` (relative distinguished name of entry)
   * `ufn` (User Friendly Name of DN)

Example usage:

      $ ldap2json -LLL -x -b o=internet -S sn '(uid=*)' uid givenname sn mail title rdn
      [
         {
            "uid": "jdough",
            "givenname": "John",
            "sn": "Dough",
            "mail": "doughboy42@example.com",
            "title": "'Dough' Master",
            "rdn": "uid=jdough"
         },
         {
            "uid": "dnullman",
            "givenname": "Devian",
            "sn": "Nullman",
            "mail": "noreply@example.com",
            "title": "Linux Device : /dev/null",
            "rdn": "uid=dnullman"
         },
         {
            "uid": "syzdek",
            "givenname": "David M.",
            "sn": "Syzdek",
            "mail": "david@syzdek.net",
            "title": "Slackware Linux Administrator",
            "rdn": "uid=syzdek"
         }
      ]
      $

Example of the same search using `ldapsearch`:

      $ ldapsearch -LLL -x -b o=internet -S sn '(uid=*)' uid givenname sn mail title
      dn: uid=dnullman,ou=People,dc=example,dc=net,o=internet
      uid: dnullman
      givenname: Devian
      sn: Nullman
      mail: noreply@example.com
      title: Linux Device | /dev/null

      dn: uid=jdough,ou=People,dc=example,dc=net,o=internet
      uid: jdough
      givenname: John
      sn: Dough
      mail: doughboy42@example.com
      title: "Dough" Master

      dn: uid=syzdek,ou=People,dc=syzdek,dc=net,o=internet
      uid: syzdek
      givenname: David M.
      sn: Syzdek
      mail: david@syzdek.net
      title: Slackware Linux Administrator


ldapdebug
---------

ldapdebug is a utility which initiates a connection the an LDAP server
and optionally binds to the LDAP server.  Once the LDAP session has been
established, the utility will display the values of various options
available from `ldap_get_option()`.  This utility is useful for debugging
`ldap.conf` and `.ldaprc` files.

ldapdebug is not installed by default.  To enable building and installing
ldapdebug, the flag `--enable-ldapdebug` must be passed to configure.


ldapdn2str
----------

ldapdn2str is a shell-accessible interface to the ldap_dn2str() interface which
outputs user supplied 

ldapdn2str parses LDAP distinguished names and prints the parsed DN using the
requested format.  The OpenLDAP function ldap_dn2str() is used to perform
the formatting the DN presentation for `dn`, `dce`, `adc`, and `ufn`.

The following are example of the output presentations available:

   * dn: distinguished name
     - `uid=dnullman,ou=People,dc=example,dc=net,o=internet`
     - `uid=jdough,ou=People,dc=example,dc=net,o=internet`
     - `uid=syzdek,ou=People,dc=syzdek,dc=net,o=internet`
     - `uid=administrator,ou=People,dc=foo,dc=org`
  
   * dce: DCE-style DN
     - `/o=internet/dc=net/dc=example/ou=People/uid=dnullman`
     - `/o=internet/dc=net/dc=example/ou=People/uid=jdough`
     - `/o=internet/dc=net/dc=syzdek/ou=People/uid=syzdek`
     - `/dc=org/dc=foo/ou=People/uid=administrator`

   * adc: Active Directory canonical name
     - `internet/net/example/People/dnullman/`
     - `internet/example.net/People/jdough`
     - `internet/syzdek.net/People/syzdek`
     - `foo.org/People/administrator`

   * rdn: relative DN
     - `uid=dnullman`
     - `uid=jdough`
     - `uid=syzdek`
     - `uid=administrator`

   * ufn: User Friendly Name of DN
     - `dnullman, People, syzdek, net, internet`
     - `jdough, People, example, net, internet`
     - `syzdek, People, example, net, internet`
     - `administrator, People, foo.org`

   * idn: inverted distinguished name
     - `o=internet,dc=net,dc=example,ou=People,uid=dnullman`
     - `o=internet,dc=net,dc=example,ou=People,uid=jdough`
     - `o=internet,dc=net,dc=syzdek,ou=People,uid=syzdek`
     - `dc=org,dc=foo,ou=People,uid=administrator`


ldapinfo
--------

ldapinfo is a shell utilty which queries the LDAP server for server information and
displays the information in human readble form.


ldaptree
--------

ldaptree is a shell utilty which performs an LDAP search and prints the results
as either an ASCII graph or a bulletted list.  By default the utilty does not
retrieve any attributes from LDAP servers, however if a search filter and
attribute list are provided as command line arguments, then the attribute values
will be displayed inline with the results.  The utility utilizes additional long
options to customize the output of either the ASCII graph or the bulletted list.

ASCII graph eexample with compact output and no leaf nodes:

      $ ldaptree -x -b o=internet --noleafs --compact
      #
      # base: o=internet with scope subtree
      # filter: (objectclass=*)
      #
      +--dc=net, o=internet
          +--dc=example
          |  +--ou=Groups
          |  \--ou=People
          \--dc=syzdek
             +--ou=Groups
             \--ou=People

ASCII graph example with attribute values:

      $ ldaptree -LLL -x -b o=internet '(objectclass=*)' givenname sn mail member description
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

      $ ldaptree -x -b o=internet --style=bullets --compact '(objectclass=*)' givenname sn \
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
   * https://github.com/bindle/ldap-utils.xcodeproj

Git URLs:

   * https://github.com/bindle/ldap-utils.git
   * https://github.com/bindle/ldap-utils.xcodeproj.git

Downloading Source:

      $ git clone git://github.com/bindle/ldap-utils.git
      $ git clone git://github.com/bindle/ldap-utils.xcodeproj.git \
                  ldap-utils/ldap-utils.xcodeproj

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
      $ make dist-xz


