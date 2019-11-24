
LDAP Utilities
==============

Copyright (C) 2012, 2019 David M. Syzdek <david@syzdek.net>

0.4
---
  Released 2019/11/24
  - libldapschema: adding library (syzdek)
  - libldaputils: fixing copyright notice in `ldaputils_version()` (syzdek)
  - ldap2csv: adding ability to specify default values (syzdek)
  - ldap2csv: making search filter optional (syzdek)
  - ldap2json: adding utility (syzdek)
  - ldapinfo: adding utility (syzdek)
  - ldapschema: adding initial utility (syzdek)
  - ldaptree: fixing filter handling when specifing attributes (syzdek)
  - ldaptree: adding comments above graph (syzdek)
  - ldaptree: fixing segfault when displaying linear tree (syzdek)
  - ldaptree: adding --expand option (syzdek)
  - ldaptree: making search filter optional when listing attributes (syzdek)
  - oidspectool: adding internal utility (syzdek)
  - ide: splitting IDE project files into separate project (syzdek)
  - autotools: adding ability to disable all utilities (syzdek)

0.3
---
   Released 2019/10/13
   - copyright: updating copyright with legal name of sole proprietor (syzdek)
   - libldaputils: refactoring source (syzdek)
   - libldaputils: adding TLS support (syzdek)
   - ldapdebug: refactoring source (syzdek)
   - ldapdebug: renaming ldapconfprint to ldapdebug (syzdek)
   - ldapdebug: adding ability to install via make (syzdek)
   - ldaptree: adding utility (syzdek)

0.2
---
   Released 2015/04/23
   - Recreating Xcode project file. (syzdek)
   - Removing files installed by autotools from git repo. (syzdek)
   - Updating autotools files (Makefile.am, configure.ac, etc). (syzdek)
   - Changing versioning scheme. (syzdek)
   - Re-writing README. (syzdek)

0.1.1
-----
   Released 2009/01/19
   - Updating ldaputils_getpass() to use stderr.
   - Modifying behavior of --verbose to set debug level
   - Removing debugging lines for LDAP API Version.
   - Updating version information to include LDAP API information.
   - Adding sorting functions for LDAP searches.
   - Fixing problems compiling with MinGW.
   - Abstracting code for separating multivalue values.
   - Fixing gettext international support.
   - Changing how LDAP host/port/URI values are stored so that values
     from ldap.conf and ldaprc files will be used if they are not
     specified on the command line. (syzdek)
   - Changing default search scope to SUBTREE. (syzdek)
   - Changing version major version from 1.0.0. to 0.1.0 (syzdek)

0.1.0
-----
   Released 2009/01/19.
   - initial release of package (syzdek)

