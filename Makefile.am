#
#   LDAP Utilities
#   Copyright (C) 2008 David M. Syzdek <david@syzdek.net>.
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
SUBDIRS                                 = po
DIST_SUBDIRS                            = po


# custom directories
localedir				= $(datadir)/locale


# Global flags
AM_LIBS					=
AM_LDADD				= $(LTLIBINTL)
AM_LDFLAGS				=
AM_CFLAGS				=
AM_CPPFLAGS				= \
					  -I$(top_srcdir)/include \
					  -I$(top_srcdir)/lib \
					  -DLOCALEDIR="\"$(localedir)\"" \
					  -DSYSCONFDIR="\"$(sysconfdir)\""
ACLOCAL_AMFLAGS				= -W syntax -W unsupported -W error


# automake targets
bin_PROGRAMS				= src/ldap2csv src/csv2ldif
lib_LTLIBRARIES				= lib/libldif.la
noinst_PROGRAMS				= src/ldapconfprint
noinst_HEADERS				= include/gettext.h
man_MANS				=


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


# miscellaneous lists
CLEANFILES				= $(builddir)/a.out        $(srcdir)/a.out \
                                          $(builddir)/*/a.out      $(srcdir)/*/a.out \
					  $(builddir)/config.h.in~ $(srcdir)/config.h.in~ \
					  $(builddir)/po/stamp-po  $(srcdir)/po/stamp-po\
					  $(builddir)/stamp-vti    $(srcdir)/stamp-vti \
					  @PACKAGE_TARNAME@-*.tar.* \
					  @PACKAGE_TARNAME@-*.zip
EXTRA_DIST				=
EXTRA_PROGRAMS				=
EXTRA_TEXINFOS				=
TESTS					=
XFAIL_TESTS				=


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
do_subst_fn = \
		echo "do_subst < ${@}.in > ${@}"; \
		mkdir -p `dirname ${@}` || exit 1; \
		${do_subst} < $(srcdir)/${@}.in > ${@} || exit 1; \
		chmod 0644 ${@}
do_subst_dt = \
		echo "do_subst < ${@}.in > ${@}"; \
		mkdir -p `dirname ${@}` || exit 1; \
		${do_subst} < $(srcdir)/${@}.in > ${@} || exit 1; \
		chmod 0644 ${@}


# custom targets


# local targets
install-exec-local:

install-data-local:

install-exec-hook:

install-data-hook:

uninstall-local:

distclean-local:
	rm -fR $(srcdir)/autom4te.cache

# end of automake file
