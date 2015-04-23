#
#   LDAP Utilities
#   Copyright (C) 2012 Bindle Binaries <syzdek@bindlebinaries.com>.
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
SUBDIRS					= $(subdirs)
DIST_SUBDIRS				= $(subdirs)


# Global flags
# Global flags
AM_LIBS					=
AM_LDFLAGS				=
AM_CFLAGS				= -O2 $(CFLAGS_WARNINGS)
AM_CXXFLAGS				= -O2 @AM_CXXFLAGS@
AM_OBJCFLAGS				= -O2 @AM_OBJCFLAGS@
AM_CPPFLAGS				= -O2 -DHAVE_CONFIG_H=1 -I$(top_builddir)/include -I$(top_srcdir)/include -DSYSCONFDIR=\"$(sysconfdir)\"
ACLOCAL_AMFLAGS				= -I m4 -W all -W error
AM_MAKEINFOFLAGS                        = --no-split
DEFS					=


# automake targets
bin_PROGRAMS				= src/ldap2csv
check_PROGRAMS				=
doc_DATA				=
EXTRA_PROGRAMS				= src/csv2ldif
include_HEADERS				=
info_TEXINFOS				=
EXTRA_LTLIBRARIES			= lib/libldif.la
man_MANS				=
noinst_HEADERS				=
noinst_PROGRAMS				= src/ldapconfprint


# lists
BUILT_SOURCES				=
TESTS					=
XFAIL_TESTS				=
EXTRA_MANS				=
EXTRA_DIST				= build-aux/autogen.sh \
					  build-aux/git-package-version \
					  build-aux/git-package-version.sh
CLEANFILES				= \
					  $(builddir)/a.out   $(srcdir)/a.out \
					  $(builddir)/*/a.out $(srcdir)/*/a.out \
					  config.h.in~ $(srcdir)/config.h.in~ \
					  @PACKAGE_TARNAME@-*.tar.* \
					  @PACKAGE_TARNAME@-*.zip
DISTCHECK_CONFIGURE_FLAGS		= --enable-strictwarnings


# macros for lib/libldif.la
lib_libldif_la_DEPENDENCIES		= Makefile lib/libldif.sym
lib_libldif_la_CFLAGS			= $(AM_CFLAGS)
lib_libldif_la_LIBADD			= $(AM_LIBS)
lib_libldif_la_LDFLAGS			= -rpath '$(libdir)' \
					  -version-info $(LIB_VERSION_INFO) \
					  $(AM_LDFLAGS) \
					  -export-symbols $(srcdir)/lib/libldif.sym
lib_libldif_la_SOURCES			= include/ldif.h \
					  lib/ldif_api.c \
					  lib/ldif_api.h


# macros for csv2ldif
src_csv2ldif_DEPENDENCIES		= Makefile
src_csv2ldif_CPPFLAGS			= -DPROGRAM_NAME="\"csv2ldif\"" $(AM_CPPFLAGS)
src_csv2ldif_CFLAGS			= $(AM_CFLAGS)
src_csv2ldif_LDFLAGS			= $(AM_LDFLAGS)
src_csv2ldif_LDADD			= $(AM_LDADD)
src_csv2ldif_SOURCES			= \
					  include/ldap-utils.h \
					  src/csv2ldif.c \
					  src/ldaputils_config.c \
					  src/ldaputils_config.h \
					  src/ldaputils_config_opts.c \
					  src/ldaputils_config_opts.h


src_ldap2csv_DEPENDENCIES		= Makefile
src_ldap2csv_CPPFLAGS			= -DPROGRAM_NAME="\"ldap2csv\"" $(AM_CPPFLAGS)
src_ldap2csv_CFLAGS			= $(AM_CFLAGS)
src_ldap2csv_LDFLAGS			= $(AM_LDFLAGS)
src_ldap2csv_LDADD			= $(AM_LDADD) -lldap -llber
src_ldap2csv_SOURCES			= \
					  include/ldap-utils.h \
					  src/ldap2csv.c \
					  src/ldaputils_config.c \
					  src/ldaputils_config.h \
					  src/ldaputils_config_opts.c \
					  src/ldaputils_config_opts.h \
					  src/ldaputils_ldap.c \
					  src/ldaputils_ldap.h


# macros for ldapconfprint
src_ldapconfprint_DEPENDENCIES		= Makefile
src_ldapconfprint_CPPFLAGS		= -DPROGRAM_NAME="\"ldapconfprint\"" $(AM_CPPFLAGS)
src_ldapconfprint_CFLAGS			= $(AM_CFLAGS)
src_ldapconfprint_LDFLAGS		= $(AM_LDFLAGS)
src_ldapconfprint_LDADD			= $(AM_LDADD) -lldap -llber
src_ldapconfprint_SOURCES		= \
					  include/ldap-utils.h \
					  src/ldapconfprint.c \
					  src/ldaputils_config.c \
					  src/ldaputils_config.h \
					  src/ldaputils_config_opts.c \
					  src/ldaputils_config_opts.h


# Makefile includes
GIT_PACKAGE_VERSION_DIR=include
SUBST_EXPRESSIONS =
include $(srcdir)/contrib/bindletools/build-aux/makefile-bindle.am
include $(srcdir)/contrib/bindletools/build-aux/makefile-autotools.am
include $(srcdir)/contrib/bindletools/build-aux/makefile-subst.am
include $(srcdir)/contrib/bindletools/build-aux/makefile-version.am


# custom targets
.PHONY:


# local targets
install-exec-local:

install-data-local:

install-exec-hook:

install-data-hook:

uninstall-local:

clean-local:

distclean-local:
	rm -fR $(srcdir)/autom4te.cache

# end of automake file
