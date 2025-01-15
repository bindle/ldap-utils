

LDAP Utilities
==============

Copyright (c) 2012, 2015, 2019, 2020, 2025 David M. Syzdek <david@syzdek.net>

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
     - ldapconns
     - ldapdebug
     - ldapdn2str
     - ldapinfo
     - ldapppolicy
     - ldapschema
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


ldapconns
---------

ldapconns is a utility which reads the OpenLDAP monitoring context and
displays connections to the slapd process.

Example usage:

      $ ldapconns -W -x -D uid=jdoe,ou=People,dc=foo,dc=org
      Listener   Proto  Mask  Ops R/E/P/C    Local        Peer                Start            Last Activity    AuthzDN
      ldap:///   3      r     13/0/0/13      0.0.0.0:389  192.168.82.16:33114   20241205095502Z  20250107184230Z  uid=ssh-bastion,ou=People,dc=foo,dc=org
      ldap:///   3      rx    3/1/0/2        0.0.0.0:389  192.168.82.212:59724  20241211103315Z  20241211103315Z  uid=vpn-server,ou=People,dc=foo,dc=org
      ldap:///   3      r     82/0/0/82      0.0.0.0:389  192.168.82.32:34866   20241121205959Z  20250114232619Z  uid=imap-server,ou=People,dc=foo,dc=org
      ldap:///   3      r     483/0/0/483    0.0.0.0:389  192.168.82.10:53406   20241120171009Z  20250115004400Z  uid=smtp-server,ou=People,dc=foo,dc=org
      ldap:///   3      r     4/0/0/4        0.0.0.0:389  192.168.82.55:54382   20241121111605Z  20241121111610Z  uid=billing-system,ou=People,dc=foo,dc=org
      ldap:///   3      rx    3/1/0/2        0.0.0.0:389  192.168.82.196:48850  20250108200553Z  20250108200553Z  uid=vpn-server,ou=People,dc=foo,dc=org
      ldap:///   3      rx    3/1/0/2        0.0.0.0:389  192.168.82.55:45860   20241121111546Z  20241121111546Z  uid=billing-system,ou=People,dc=foo,dc=org
      ldap:///   3      r     4/0/0/4        0.0.0.0:389  192.168.82.202:42762  20250115104717Z  20250115104717Z
      ldap:///   3      r     4/0/0/4        0.0.0.0:389  192.168.82.201:50946  20250115104717Z  20250115104717Z
      ldap:///   3      rx    3/1/0/2        0.0.0.0:389  192.168.82.10:39272   20241120101747Z  20241120101747Z  uid=smtp-server,ou=People,dc=foo,dc=org
      ldap:///   3      rx    3/1/0/2        0.0.0.0:389  192.168.82.33:36210   20241120101737Z  20241120101737Z  uid=pop-server,ou=People,dc=foo,dc=org
      ldap:///   3      r     7977/0/0/7977  0.0.0.0:389  192.168.82.161:34790  20241120101727Z  20250115031802Z  uid=jdoe,ou=People,dc=foo,dc=org


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
displays the information in human readable form.

The following example uses a priviledged bind DN to obtain server stats:

      $ ldapinfo -W
      Enter LDAP Password:
      Vendor name:                 OpenLDAP
      Vendor version:              slapd 2.4.46 (Dec  5 2018 16:21:32)
      LDAP version:                3
      Subschema Subentry:          cn=Subschema
      Configuration context:       cn=config
      Monitoring context:          cn=Monitor

      Schema:                      ldapSyntaxes: 32
                                   matchingRules: 37
                                   matchingRuleUse: 31
                                   attributeTypes: 693
                                   objectClasses: 145

      Operations:                  Bind initiated: 529432; completed 529432
                                   Unbind initiated: 378252; completed 378252
                                   Search initiated: 3900266; completed 3900265
                                   Compare initiated: 6254; completed 6254
                                   Modify initiated: 0; completed 0
                                   Modrdn initiated: 0; completed 0
                                   Add initiated: 0; completed 0
                                   Delete initiated: 1; completed 1
                                   Abandon initiated: 174; completed 174
                                   Extended initiated: 439445; completed 439445

      Connections:                 Max File Descriptors: 1024
                                   Total: 459982
                                   Current: 143

      Naming contexts:             cn=config (config)
                                   dc=example,dc=org (mdb) [ memberof ppolicy refint syncprov ]
                                   o=subscribers (mdb) [ memberof ppolicy refint syncprov ]
                                   o=metadata (mdb) [ syncprov ]
                                   o=registry (mdb) [ memberof ppolicy refint syncprov ]

      Supported controls:          1.2.826.0.1.3344810.2.3 (Matched Values Control)
                                   1.2.840.113556.1.4.319 (LDAP Simple Paged Results Control)
                                   1.3.6.1.1.12 (Assertion Control)
                                   1.3.6.1.1.13.1 (LDAP Pre-read Control)
                                   1.3.6.1.1.13.2 (LDAP Post-read Control)
                                   1.3.6.1.1.22 (LDAP Don't Use Copy Control)
                                   1.3.6.1.4.1.4203.1.10.1 (Subentries)
                                   1.3.6.1.4.1.4203.1.9.1.1 (LDAP Content Synchronization Control)
                                   2.16.840.1.113730.3.4.18 (Proxy Authorization Control)
                                   2.16.840.1.113730.3.4.2 (ManageDsaIT)

      Supported extension:         1.3.6.1.1.8 (Cancel Operation)
                                   1.3.6.1.4.1.1466.20037 (StartTLS)
                                   1.3.6.1.4.1.4203.1.11.1 (Modify Password)
                                   1.3.6.1.4.1.4203.1.11.3 (Who am I?)

      Supported features:          1.3.6.1.1.14 (Modify-Increment)
                                   1.3.6.1.4.1.4203.1.5.1 (All Op Attrs)
                                   1.3.6.1.4.1.4203.1.5.2 (OC AD Lists)
                                   1.3.6.1.4.1.4203.1.5.3 (True/False filters)
                                   1.3.6.1.4.1.4203.1.5.4 (Language Tag Options)
                                   1.3.6.1.4.1.4203.1.5.5 (Language Range Options)

      Supported SASL mechanisms:   CRAM-MD5
                                   DIGEST-MD5
                                   LOGIN
                                   OTP
                                   PLAIN
                                   SCRAM-SHA-1


ldapppolicy
-----------

ldapppolicy is a utility which searches an LDAP server for entries containing
the object class `pwdPolicy`.  The utility then displays the attributes from
the IETF Password Policy proposal for LDAP in human readable format.

The following is an example of displaying the password policies found within
the directory:

      $ ldapppolicy
      ppolicy: dc=foo,dc=org
         Password Attribute:       userPassword
         Password Minimum Age:     30s
         Password Maximum Age:     12w 1d
         Password Minimum Length:  16
         Password Syntax Checks:   enabled, fail on errors
         Passwords In History:     40
         Password Expire Warning:  1w
         Expired Grace Binds:      0
         Lockout After Failures:   TRUE
         Lockout Duration:         30m
         Lockout Max Failures:     10
         Lockout Failure Interval: 20m
         Password Must Change:     FALSE
         Password Check Module:    bofh-pwdCheckModules.so

      ppolicy: cn=none,ou=PPolicies,dc=foo,dc=org
         Password Attribute:       userPassword
         Password Minimum Age:     0s
         Password Minimum Length:  1
         Password Syntax Checks:   disabled
         Passwords In History:     1
         Password Expire Warning:  0s
         Expired Grace Binds:      0
         Lockout After Failures:   FALSE
         Lockout Max Failures:     0
         Password Must Change:     FALSE
         Allow User Change:        TRUE

      ppolicy: cn=allow-pwhash,ou=PPolicies,dc=foo,dc=org
         Password Attribute:       userPassword
         Password Minimum Age:     30s
         Password Maximum Age:     12w 1d
         Password Minimum Length:  16
         Password Syntax Checks:   enabled, ignore errors
         Passwords In History:     40
         Password Expire Warning:  1w
         Expired Grace Binds:      0
         Lockout After Failures:   TRUE
         Lockout Duration:         30m
         Lockout Max Failures:     10
         Lockout Failure Interval: 20m
         Password Must Change:     FALSE
         Password Check Module:    bofh-pwdCheckModules.so

The following example looks up a specific password policy DN and displays the
LDAP attribute names instead of descriptions:

      $ ldapppolicy -A cn=none,ou=PPolicies,dc=acsalaska,dc=net
      ppolicy: cn=none,ou=PPolicies,dc=acsalaska,dc=net
         pwdAttribute:             userPassword
         pwdMinAge:                0s
         pwdMinLength:             1
         pwdCheckQuality:          disabled
         pwdInHistory:             1
         pwdExpireWarning:         0s
         pwdGraceAuthnLimit:       0
         pwdLockout:               FALSE
         pwdMaxFailure:            0
         pwdMustChange:            FALSE
         pwdAllowUserChange:       TRUE


ldapschema
----------

ldapschema is a shell utility for searching and displaying the schema of an LDAP
server.  The utility can run in either lint, list, search, or dump mode. In lint
mode the utility will report schema errors it encountered. In list mode, the
utility will list the OID and NAME/DESC of the object types specified. In dump
mode the utility will display detailed information about all objects in the
schema which it understands. In search mode the utility will display detailed
information of the objects requested and any related objects such as superiors.

The following is an example of a schema search for an objectclass:

      $ ldapschema  2.5.6.9
      objectClass:        2.5.6.9
         name(s):         groupOfNames
         description:     RFC2256: a group of names (DNs)
         usage:           abstract
         superior(s):     top
         may:             businessCategory
                          description
                          o
                          ou
                          owner
                          seeAlso
         must:            cn
                          member
         inherited must:  objectClass
         definition:      (  2.5.6.9
                             NAME 'groupOfNames'
                             DESC 'RFC2256: a group of names (DNs)'
                             SUP top
                             STRUCTURAL
                             MUST
                             (  member $ cn
                             )
                             MAY
                             (  businessCategory $ seeAlso $
                                owner $ ou $ o $ description
                             )
                          )


      objectClass:        2.5.6.0
         name(s):         top
         description:     top of the superclass chain
         usage:           abstract
         must:            objectClass
         definition:      (  2.5.6.0
                             NAME 'top'
                             DESC 'top of the superclass chain'
                             ABSTRACT
                             MUST objectClass
                          )

The following is an example of a schema search for an attributeType:

      $ ldapschema  pwdChangedTime
      attributeType:      1.3.6.1.4.1.42.2.27.8.1.16
         name(s):         pwdChangedTime
         description:     The time the password was last changed
         single value:    yes
         readable:        yes
         no user mod:     yes
         usage:           directoryOperation
         syntax:          1.3.6.1.4.1.1466.115.121.1.24 ( Generalized Time )
         data class:      ASCII
         common abnf:     no
         schema abnf:     no
         abnf:            GeneralizedTime = century year month day hour
                                               [ minute [ second / leap-second ] ]
                                               [ fraction ]
                                               g-time-zone

                          century = 2(%x30-39) ; "00" to "99"
                          year    = 2(%x30-39) ; "00" to "99"
                          month   =   ( %x30 %x31-39 ) ; "01" (January) to "09"
                                    / ( %x31 %x30-32 ) ; "10" to "12"
                          day     =   ( %x30 %x31-39 )    ; "01" to "09"
                                    / ( %x31-32 %x30-39 ) ; "10" to "29"
                                    / ( %x33 %x30-31 )    ; "30" to "31"
                          hour    = ( %x30-31 %x30-39 ) / ( %x32 %x30-33 ) ; "00" to "23"
                          minute  = %x30-35 %x30-39                        ; "00" to "59"

                          second      = ( %x30-35 %x30-39 ) ; "00" to "59"
                          leap-second = ( %x36 %x30 )       ; "60"

                          fraction        = ( DOT / COMMA ) 1*(%x30-39)
                          g-time-zone     = %x5A  ; "Z"
                                            / g-differential
                          g-differential  = ( MINUS / PLUS ) hour [ minute ]
                          MINUS           = %x2D  ; minus sign ("-")
                          DOT     = %x2E ; period (".")
                          COMMA   = %x2C ; comma (",")
                          PLUS    = %x2B ; plus sign ("+")
         definition:      (  1.3.6.1.4.1.42.2.27.8.1.16
                             NAME 'pwdChangedTime'
                             DESC 'The time the password was last changed'
                             EQUALITY generalizedTimeMatch
                             ORDERING generalizedTimeOrderingMatch
                             SYNTAX 1.3.6.1.4.1.1466.115.121.1.24
                             SINGLE -VALUE NO -USER -MODIFICATION
                             USAGE directoryOperation
                          )


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


Building Package
================

To build the package using a release source tarball, run the following:

      tar -xvf ldap-utils-x.y.z.tar.xz
      mkdir -p ldap-utils-x.y.z/build
      cd ldap-utils-x.y.z/build
      ../configure
      make all
      make install

For more information on building and installing using configure, please
read the INSTALL file and run `configure --help` for configureation
options.

      
Source Code
===========

The source code for this project is maintained using git
(http://git-scm.com).  The following contains information to checkout the
source code from the git repository.

Browse Source:

   * https://github.com/bindle/ldap-utils

Git URLs:

   * https://github.com/bindle/ldap-utils.git

Release Archives:

   * https://github.com/bindle/ldap-utils/releases

Downloading Source:

      $ git clone git://github.com/bindle/ldap-utils.git

Preparing Source:

      $ cd ldap-utils
      $ ./autogen.sh

Compiling Source:

      $ cd build
      $ ../configure
      $ make src/oidspectool
      $ make all && make install

For more information on building and installing using configure, please
read the INSTALL file and run `configure --help` for configureation
options.


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

