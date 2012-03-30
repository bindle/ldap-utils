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
SUBDIRS					=
DIST_SUBDIRS				=


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
lib_LTLIBRARIES				= lib/libldif.la
man_MANS				=
noinst_HEADERS				=
noinst_PROGRAMS				= src/ldapconfprint


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
src_ldap2csv_LDADD			= $(AM_LDADD) -lldap
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
src_ldapconfprint_LDADD			= $(AM_LDADD) -lldap
src_ldapconfprint_SOURCES		= \
					  include/ldap-utils.h \
					  src/ldapconfprint.c \
					  src/ldaputils_config.c \
					  src/ldaputils_config.h \
					  src/ldaputils_config_opts.c \
					  src/ldaputils_config_opts.h


# substitution routine
do_subst = sed \
	-e 's,[@]SHELL[@],@SHELL@,g' \
	-e 's,[@]PACKAGE_VERSION[@],@PACKAGE_VERSION@,g' \
	-e 's![@]PACKAGE_NAME[@]!@PACKAGE_NAME@!g' \
	-e 's,[@]PACKAGE_TARNAME[@],@PACKAGE_TARNAME@,g' \
	-e 's,[@]PACKAGE_BUGREPORT[@],@PACKAGE_BUGREPORT@,g' \
	-e 's,[@]RELEASE_MONTH[@],@RELEASE_MONTH@,g' \
	-e 's,[@]INSTALL[@],$(INSTALL),g' \
	-e 's,[@]INSTALL_PROGRAM[@],$(INSTALL_PROGRAM),g' \
	-e 's,[@]INSTALL_SCRIPT[@],$(INSTALL_SCRIPT),g' \
	-e 's,[@]INSTALL_DATA[@],$(INSTALL_DATA),g' \
	-e 's,[@]LIB_VERSION_CURRENT[@],@LIB_VERSION_CURRENT@,g' \
	-e 's,[@]LIB_VERSION_REVISION[@],@LIB_VERSION_REVISION@,g' \
	-e 's,[@]LIB_VERSION_AGE[@],@LIB_VERSION_AGE@,g' \
	-e 's,[@]LIB_VERSION_INFO[@],@LIB_VERSION_INFO@,g' \
	-e 's,[@]LIB_RELEASE_INFO[@],@LIB_RELEASE_INFO@,g' \
	-e 's,[@]prefix[@],$(prefix),g' \
	-e 's,[@]datadir[@],$(datadir),g' \
	-e 's,[@]sbindir[@],$(sbindir),g' \
	-e 's,[@]sysconfdir[@],$(sysconfdir),g' \
	-e 's,[@]localstatedir[@],$(localstatedir),g'
do_subst_fn = \
		echo "do_subst < ${@}.in > ${@}"; \
		mkdir -p `dirname ${@}` || exit 1; \
		${do_subst} < $(srcdir)/${@}.in > ${@} || exit 1; \
		chmod 0755 ${@}
do_subst_dt = \
		echo "do_subst < ${@}.in > ${@}"; \
		mkdir -p `dirname ${@}` || exit 1; \
		${do_subst} < $(srcdir)/${@}.in > ${@} || exit 1; \
		chmod 0644 ${@}


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


# custom targets
.PHONY: autogen update gitclean build-aux/git-package-version

build-aux/git-package-version:
	$(top_srcdir)/build-aux/git-package-version.sh $(top_srcdir)

autogen:
	$(top_srcdir)/build-aux/autogen.sh
	test -x ./config.status && { ./config.status --recheck || exit $?; } || exit 0

update:
	git --git-dir=$(top_srcdir)/.git pull 2> /dev/null || exit 0
	$(MAKE) -f Makefile autogen

gitclean:
	$(MAKE) -f Makefile distclean
	rm -f  $(top_srcdir)/INSTALL
	rm -f  $(top_srcdir)/Makefile.in
	rm -f  $(top_srcdir)/aclocal.m4
	rm -f  $(top_srcdir)/config.h.in
	rm -f  $(top_srcdir)/configure
	rm -f  $(top_srcdir)/m4/*
	rm -f  $(top_srcdir)/build-aux/c* $(top_srcdir)/build-aux/d*
	rm -f  $(top_srcdir)/build-aux/i* $(top_srcdir)/build-aux/l*
	rm -f  $(top_srcdir)/build-aux/m*
	rm -f  $(top_srcdir)/build-aux/git-package-version


# local targets
install-exec-local:

install-data-local:

install-exec-hook:

install-data-hook:

uninstall-local:

clean-local:

distclean-local:
	rm -fR $(srcdir)/autom4te.cache
	rm -f  $(srcdir)/GTAGS $(srcdir)/GRTAGS $(srcdir)/GPATH

# end of automake file
