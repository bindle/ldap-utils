#
#   $Id$
#
#   LDAP Utilities
#   Copyright (c) 2008 David M. Syzdek <ldap-utils-project@syzdek.net>.
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
#
#   @configure_input@
#
#   Makefile.am - automate compiling on a unix platform
#

# Sub directories
SUBDIRS                                 = po lib
DIST_SUBDIRS                            = po lib


localedir				= $(datadir)/locale


# Global flags
AM_LIBS					=
AM_LDADD				= @LTLIBINTL@
AM_LDFLAGS				=
AM_CFLAGS				= @CFLAGS_WARNINGS@
AM_CPPFLAGS				= -I$(top_srcdir)/include \
					  -I$(top_srcdir)/lib \
					  -DLOCALEDIR=\"$(localedir)\" \
					  -DSYSCONFDIR=\"$(sysconfdir)\"
ACLOCAL_AMFLAGS				= -I m4

# automake targets
bin_PROGRAMS				= src/ldapsetup
noinst_PROGRAMS				= src/ldaputils_test
man_MANS				=


TESTS					=
XFAIL_TESTS				=
EXTRA_DIST				= build-aux/config.rpath include/gettext.h
CLEANFILES				= a.out $(srcdir)/a.out \
					  tests/a.out $(srcdir)/tests/a.out \
					  config.h.in~ $(srcdir)/config.h.in~ \
					  @PACKAGE_TARNAME@-*.tar.* \
					  @PACKAGE_TARNAME@-*.zip


# macros for ldaputils_test
src_ldapsetup_DEPENDENCIES		= Makefile
src_ldapsetup_CPPFLAGS			= -DPROGRAM_NAME="\"ldapsetup\"" $(AM_CPPFLAGS)
src_ldapsetup_CFLAGS			= $(AM_CFLAGS)
src_ldapsetup_LDFLAGS			= $(AM_LDFLAGS)
src_ldapsetup_LDADD			= $(AM_LDADD)
src_ldapsetup_SOURCES			= \
					  src/ldaputils_common.c \
					  src/ldaputils_common.h \
					  src/ldapsetup.c


# macros for ldaputils_test
src_ldaputils_test_DEPENDENCIES		= Makefile
src_ldaputils_test_CPPFLAGS		= -DPROGRAM_NAME="\"ldaputils_test\"" $(AM_CPPFLAGS)
src_ldaputils_test_CFLAGS		= $(AM_CFLAGS)
src_ldaputils_test_LDFLAGS		= $(AM_LDFLAGS)
src_ldaputils_test_LDADD		= $(AM_LDADD)
src_ldaputils_test_SOURCES		= \
					  src/ldaputils_common.c \
					  src/ldaputils_common.h \
					  src/ldaputils_test.c


# substitution routine
do_subst = sed \
	-e 's,[@]configure_input[@],${@}. Generated from ${@}.in by make.,g' \
	-e 's,[@]SHELL[@],@SHELL@,g' \
	-e 's,[@]PACKAGE_VERSION[@],@PACKAGE_VERSION@,g' \
	-e 's![@]PACKAGE_NAME[@]!@PACKAGE_NAME@!g' \
	-e 's,[@]PACKAGE_TARNAME[@],@PACKAGE_TARNAME@,g' \
	-e 's,[@]PACKAGE_BUGREPORT[@],@PACKAGE_BUGREPORT@,g' \
	-e 's,[@]PACKAGE_COPYRIGHT[@],@PACKAGE_COPYRIGHT@,g' \
	-e 's,[@]RELEASE_MONTH[@],@RELEASE_MONTH@,g'


# custom targets


# local targets
install-exec-local:

install-data-local: 

uninstall-local:

distclean-local:
	rm -fR $(srcdir)/autom4te.cache

# end of automake file
