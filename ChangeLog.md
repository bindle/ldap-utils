
LDAP Utilities
Copyright (C) 2012 Bindle Binaries <syzdek@bindlebinaries.com>.

0.3
---
   - refactoring libldaputils (syzdek)
   - adding TLS support

0.2   
---
   - Recreating Xcode project file. (syzdek)
   - Removing files installed by autotools from git repo. (syzdek)
   - Updating autotools files (Makefile.am, configure.ac, etc). (syzdek)
   - Changing versioning scheme. (syzdek)
   - Re-writing README. (syzdek)

0.1.1
-----
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
   - initial release of package (syzdek)
