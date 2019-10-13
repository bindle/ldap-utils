#
#   LDAP Utilities
#   Copyright (C) 2012, 2019 David M. Syzdek <david@syzdek.net>.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are
#   met:
#
#      1. Redistributions of source code must retain the above copyright
#         notice, this list of conditions and the following disclaimer.
#
#      2. Redistributions in binary form must reproduce the above copyright
#         notice, this list of conditions and the following disclaimer in the
#         documentation and/or other materials provided with the distribution.
#
#      3. Neither the name of the copyright holder nor the names of its
#         contributors may be used to endorse or promote products derived from
#         this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
#   IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
#   THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
#   PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
#   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
#   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
#   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
#   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
#   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
#   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#   @configure_input@
#
#   Makefile.am - automate compiling on a unix platform
#

# Sub directories
SUBDIRS					= $(subdirs)
DIST_SUBDIRS				= $(subdirs)

# GNU make options
V					= 0


# Global flags
AM_LIBS					=
AM_LDFLAGS				=
AM_CFLAGS				= -O2 $(CFLAGS_WARNINGS)
AM_CXXFLAGS				= -O2 @AM_CXXFLAGS@
AM_OBJCFLAGS				= -O2 @AM_OBJCFLAGS@
AM_CPPFLAGS				= -O2 \
					  -UPMARK \
					  -DHAVE_CONFIG_H=1 \
					  -I$(top_builddir)/include \
					  -I$(top_srcdir)/include \
					  -DSYSCONFDIR=\"$(sysconfdir)\"
ACLOCAL_AMFLAGS				= -I m4 -W all -W error
AM_MAKEINFOFLAGS                        = --no-split
AM_DISTCHECK_CONFIGURE_FLAGS		= CFLAGS="$(CFLAGS)" CPPFLAGS="$(CPPFLAGS)" LDFLAGS="$(LDFLAGS)"
DEFS					=
LDADD					= $(lib_LTLIBRARIES) \
					  $(noinst_LTLIBRARIES)


# automake targets
bin_PROGRAMS				=
check_PROGRAMS				=
doc_DATA				=
EXTRA_PROGRAMS				=
include_HEADERS				=
info_TEXINFOS				=
EXTRA_LTLIBRARIES			=
man_MANS				=
noinst_HEADERS				= include/ldaputils.h \
					  include/ldaputils_cdefs.h
noinst_PROGRAMS				= src/ldapdebug
noinst_LIBRARIES			= lib/libldaputils.a


# lists
AM_INSTALLCHECK_STD_OPTIONS_EXEMPT	=
BUILT_SOURCES				=
TESTS					=
XFAIL_TESTS				=
EXTRA_MANS				=
EXTRA_DIST				= $(noinst_HEADERS) \
					  ChangeLog.md \
					  NEWS.md \
					  README.md \
					  TODO.md \
					  lib/libldaputils/libldaputils.sym
CLEANFILES				= \
					  $(builddir)/a.out   $(srcdir)/a.out \
					  $(builddir)/*/a.out $(srcdir)/*/a.out \
					  config.h.in~ $(srcdir)/config.h.in~ \
					  $(man_MANS) \
					  $(pkgdata_DATA) \
					  $(bin_SCRIPTS) \
					  $(sbin_SCRIPTS) \
					  @PACKAGE_TARNAME@-*.tar.* \
					  @PACKAGE_TARNAME@-*.txz \
					  @PACKAGE_TARNAME@-*.zip
DISTCHECK_CONFIGURE_FLAGS		= --enable-strictwarnings


# macros for lib/libutil.la
lib_libldaputils_a_DEPENDENCIES		= Makefile lib/libldaputils/libldaputils.sym
lib_libldaputils_a_CFLAGS		= $(AM_CFLAGS)
lib_libldaputils_a_LIBADD		= $(AM_LIBS)
lib_libldaputils_a_SOURCES		= $(noinst_HEADERS) \
					  lib/libldaputils/libldaputils.h \
					  lib/libldaputils/lconfig.c \
					  lib/libldaputils/lconfig.h \
					  lib/libldaputils/lentry.c \
					  lib/libldaputils/lentry.h \
					  lib/libldaputils/lldap.c \
					  lib/libldaputils/lldap.h \
					  lib/libldaputils/lmemory.c \
					  lib/libldaputils/lmemory.h \
					  lib/libldaputils/lpasswd.c \
					  lib/libldaputils/lpasswd.h \
					  lib/libldaputils/ltree.c \
					  lib/libldaputils/ltree.h


# macros for ldap2csv
if LDAPUTILS_LDAP2CSV
bin_PROGRAMS                            += src/ldap2csv
endif
src_ldap2csv_DEPENDENCIES		= Makefile lib/libldaputils.a
src_ldap2csv_CPPFLAGS			= -DPROGRAM_NAME="\"ldap2csv\"" $(AM_CPPFLAGS)
src_ldap2csv_CFLAGS			= $(AM_CFLAGS)
src_ldap2csv_LDFLAGS			= $(AM_LDFLAGS)
src_ldap2csv_LDADD			= $(AM_LDADD) -lldap -llber lib/libldaputils.a
src_ldap2csv_SOURCES			= \
					  src/ldap2csv.c


# macros for ldaptree
if LDAPUTILS_LDAPTREE
bin_PROGRAMS                            += src/ldaptree
endif
src_ldaptree_DEPENDENCIES		= Makefile lib/libldaputils.a
src_ldaptree_CPPFLAGS			= -DPROGRAM_NAME="\"ldaptree\"" $(AM_CPPFLAGS)
src_ldaptree_CFLAGS			= $(AM_CFLAGS)
src_ldaptree_LDFLAGS			= $(AM_LDFLAGS)
src_ldaptree_LDADD			= $(AM_LDADD) -lldap -llber lib/libldaputils.a
src_ldaptree_SOURCES			= \
					  src/ldaptree.c


# macros for ldapdebug
src_ldapdebug_DEPENDENCIES		= Makefile lib/libldaputils.a
src_ldapdebug_CPPFLAGS			= -DPROGRAM_NAME="\"ldapdebug\"" $(AM_CPPFLAGS)
src_ldapdebug_CFLAGS			= $(AM_CFLAGS)
src_ldapdebug_LDFLAGS			= $(AM_LDFLAGS)
src_ldapdebug_LDADD			= $(AM_LDADD) -lldap -llber lib/libldaputils.a
src_ldapdebug_SOURCES			= \
					  src/ldapdebug.c


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
