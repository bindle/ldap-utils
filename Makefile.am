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
AM_DISTCHECK_CONFIGURE_FLAGS		= --enable-strictwarnings \
					  --enable-libldapschema \
					  --enable-ldapschema \
					  --enable-ldapdebug \
					  CFLAGS="$(CFLAGS)" \
					  CPPFLAGS="$(CPPFLAGS)" \
					  LDFLAGS="$(LDFLAGS)"
AM_YFLAGS				= -d
DEFS					=
LDADD					=


# automake targets
bin_PROGRAMS				=
check_PROGRAMS				=
doc_DATA				=
EXTRA_PROGRAMS				=
include_HEADERS				=
info_TEXINFOS				=
lib_LIBRARIES				=
lib_LTLIBRARIES				=
EXTRA_LIBRARIES				=
EXTRA_LTLIBRARIES			=
man_MANS				=
noinst_HEADERS				= include/ldapschema.h \
					  include/ldaputils.h \
					  include/ldaputils_cdefs.h
noinst_PROGRAMS				=
noinst_LIBRARIES			= lib/libldaputils.a


# lists
OIDSPEC_FILES				= $(srcdir)/doc/oidspecs/iana-ldap-parameters.oidspec \
					  $(srcdir)/doc/oidspecs/rfc/rfc2252.oidspec \
					  $(srcdir)/doc/oidspecs/rfc/rfc4517.oidspec \
					  $(srcdir)/doc/oidspecs/rfc/rfc4523.oidspec \
					  $(srcdir)/doc/oidspecs/rfc/rfc4530.oidspec
MY_OIDSPECFLAGS				= --include=lspecdata.h \
					  --include=lspec.h \
					  --sparse \
					  $(OIDSPEC_FILES)
AM_INSTALLCHECK_STD_OPTIONS_EXEMPT	=
BUILT_SOURCES				= lib/libldapschema/lspecdata.c \
					  lib/libldapschema/lspecdata.h \
					  src/utils/oidspectool/oidspecparser.h
TESTS					=
XFAIL_TESTS				=
EXTRA_MANS				=
EXTRA_DIST				= $(noinst_HEADERS) \
					  ChangeLog.md \
					  NEWS.md \
					  README.md \
					  TODO.md \
					  lib/libldapschema/libldapschema.sym \
					  $(srcdir)/doc/ldap2csv.1.in \
					  $(srcdir)/doc/ldap2json.1.in \
					  $(srcdir)/doc/ldapinfo.1.in \
					  $(srcdir)/doc/ldapdebug.1.in \
					  $(srcdir)/doc/ldaptree.1.in \
					  lib/libldaputils/libldaputils.sym \
					  lib/libldapschema/lspecdata.c \
					  lib/libldapschema/lspecdata.h \
					  doc/oidspecs/template.oidspec \
					  $(OIDSPEC_FILES)
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


# macros for lib/libldapschema.a
if LDAPUTILS_LIBLDAPSCHEMA
   noinst_LIBRARIES			+= lib/libldapschema.a
endif
if LDAPUTILS_LTLIBLDAPSCHEMA
   lib_LIBRARIES			+= lib/libldapschema.a
   include_HEADERS			+= include/ldapschema.h
endif
lib_libldapschema_a_DEPENDENCIES	= Makefile lib/libldapschema/libldapschema.sym
lib_libldapschema_a_CPPFLAGS		= $(AM_CPPFLAGS) -I$(srcdir)/lib/libldapschema
lib_libldapschema_a_CFLAGS		= $(AM_CFLAGS)
lib_libldapschema_a_LIBADD		= $(AM_LIBS)
lib_libldapschema_a_SOURCES		= $(noinst_HEADERS) \
					  lib/libldapschema/libldapschema.h \
					  lib/libldapschema/lerror.c \
					  lib/libldapschema/lerror.h \
					  lib/libldapschema/lldap.c \
					  lib/libldapschema/lldap.h \
					  lib/libldapschema/llexer.c \
					  lib/libldapschema/llexer.h \
					  lib/libldapschema/lmemory.c \
					  lib/libldapschema/lmemory.h \
					  lib/libldapschema/loutput.c \
					  lib/libldapschema/loutput.h \
					  lib/libldapschema/lspec.c \
					  lib/libldapschema/lspec.h \
					  lib/libldapschema/lspecdata.c \
					  lib/libldapschema/lspecdata.h \
					  lib/libldapschema/lsort.c \
					  lib/libldapschema/lsort.h


# macros for lib/libldapschema.la
if LDAPUTILS_LTLIBLDAPSCHEMA
   lib_LTLIBRARIES			+= lib/libldapschema.la
endif
lib_libldapschema_la_DEPENDENCIES	= Makefile lib/libldapschema/libldapschema.sym
lib_libldapschema_la_CPPFLAGS		= $(AM_CPPFLAGS) -I$(srcdir)/lib/libldapschema
lib_libldapschema_la_CFLAGS		= $(AM_CFLAGS)
lib_libldapschema_la_LDFLAGS		= -rpath'$(libdir)' \
					  -version-info $(LIB_VERSION_INFO) \
					  $(AM_LDFLAGS) \
					  -export-symbols $(srcdir)/lib/libldapschema/libldapschema.sym
lib_libldapschema_la_LIBADD		= $(AM_LIBS)
lib_libldapschema_la_SOURCES		= $(noinst_HEADERS) \
					  lib/libldapschema/libldapschema.h \
					  lib/libldapschema/lerror.c \
					  lib/libldapschema/lerror.h \
					  lib/libldapschema/lldap.c \
					  lib/libldapschema/lldap.h \
					  lib/libldapschema/llexer.c \
					  lib/libldapschema/llexer.h \
					  lib/libldapschema/lmemory.c \
					  lib/libldapschema/lmemory.h \
					  lib/libldapschema/loutput.c \
					  lib/libldapschema/loutput.h \
					  lib/libldapschema/lspec.c \
					  lib/libldapschema/lspec.h \
					  lib/libldapschema/lspecdata.c \
					  lib/libldapschema/lspecdata.h \
					  lib/libldapschema/lsort.c \
					  lib/libldapschema/lsort.h


# macros for lib/libldaputils.a
if LDAPUTILS_LIBLDAPUTILS
   noinst_LIBRARIES			+= lib/libldaputils.a
endif
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


# macros for src/ldap2csv
if LDAPUTILS_LDAP2CSV
   bin_PROGRAMS				+= src/ldap2csv
   man_MANS				+= doc/ldap2csv.1
endif
src_ldap2csv_DEPENDENCIES		= Makefile lib/libldaputils.a
src_ldap2csv_CPPFLAGS			= -DPROGRAM_NAME="\"ldap2csv\"" $(AM_CPPFLAGS)
src_ldap2csv_CFLAGS			= $(AM_CFLAGS)
src_ldap2csv_LDFLAGS			= $(AM_LDFLAGS)
src_ldap2csv_LDADD			= $(AM_LDADD) -lldap -llber lib/libldaputils.a
src_ldap2csv_SOURCES			= src/ldap2csv.c


# macros for src/ldap2json
if LDAPUTILS_LDAP2JSON
   bin_PROGRAMS				+= src/ldap2json
   man_MANS				+= doc/ldap2json.1
endif
src_ldap2json_DEPENDENCIES		= Makefile lib/libldaputils.a
src_ldap2json_CPPFLAGS			= -DPROGRAM_NAME="\"ldap2json\"" $(AM_CPPFLAGS)
src_ldap2json_CFLAGS			= $(AM_CFLAGS)
src_ldap2json_LDFLAGS			= $(AM_LDFLAGS)
src_ldap2json_LDADD			= $(AM_LDADD) -lldap -llber lib/libldaputils.a
src_ldap2json_SOURCES			= src/ldap2json.c


# macros for src/ldapdebug
if LDAPUTILS_LDAPDEBUG
   bin_PROGRAMS				+= src/ldapdebug
   man_MANS				+= doc/ldapdebug.1
endif
src_ldapdebug_DEPENDENCIES		= Makefile lib/libldaputils.a
src_ldapdebug_CPPFLAGS			= -DPROGRAM_NAME="\"ldapdebug\"" $(AM_CPPFLAGS)
src_ldapdebug_CFLAGS			= $(AM_CFLAGS)
src_ldapdebug_LDFLAGS			= $(AM_LDFLAGS)
src_ldapdebug_LDADD			= $(AM_LDADD) -lldap -llber lib/libldaputils.a
src_ldapdebug_SOURCES			= src/ldapdebug.c


# macros for src/ldapdn2str
if LDAPUTILS_LDAPDN2STR
   bin_PROGRAMS				+= src/ldapdn2str
endif
src_ldapdn2str_DEPENDENCIES		= Makefile lib/libldaputils.a
src_ldapdn2str_CPPFLAGS			= -DPROGRAM_NAME="\"ldapdn2str\"" $(AM_CPPFLAGS)
src_ldapdn2str_CFLAGS			= $(AM_CFLAGS)
src_ldapdn2str_LDFLAGS			= $(AM_LDFLAGS)
src_ldapdn2str_LDADD			= $(AM_LDADD) -lldap -llber lib/libldaputils.a
src_ldapdn2str_SOURCES			= src/ldapdn2str.c


# macros for src/ldapinfo
if LDAPUTILS_LDAPINFO
   bin_PROGRAMS				+= src/ldapinfo
   man_MANS				+= doc/ldapinfo.1
endif
src_ldapinfo_DEPENDENCIES		= Makefile lib/libldaputils.a lib/libldapschema.a
src_ldapinfo_CPPFLAGS			= -DPROGRAM_NAME="\"ldapinfo\"" $(AM_CPPFLAGS)
src_ldapinfo_CFLAGS			= $(AM_CFLAGS)
src_ldapinfo_LDFLAGS			= $(AM_LDFLAGS)
src_ldapinfo_LDADD			= $(AM_LDADD) -lldap -llber lib/libldaputils.a lib/libldapschema.a
src_ldapinfo_SOURCES			= src/ldapinfo.c


# macros for src/ldapschema
if LDAPUTILS_LDAPSCHEMA
   bin_PROGRAMS                         += src/ldapschema
endif
src_ldapschema_DEPENDENCIES		= Makefile lib/libldapschema.a lib/libldaputils.a lib/libldapschema.a
src_ldapschema_CPPFLAGS			= -DPROGRAM_NAME="\"ldapschema\"" $(AM_CPPFLAGS)
src_ldapschema_CFLAGS			= $(AM_CFLAGS)
src_ldapschema_LDFLAGS			= $(AM_LDFLAGS)
src_ldapschema_LDADD			= $(AM_LDADD) -lldap -llber lib/libldaputils.a lib/libldapschema.a
src_ldapschema_SOURCES			= src/ldapschema.c


# macros for src/ldaptree
if LDAPUTILS_LDAPTREE
   bin_PROGRAMS				+= src/ldaptree
   man_MANS				+= doc/ldaptree.1
endif
src_ldaptree_DEPENDENCIES		= Makefile lib/libldaputils.a
src_ldaptree_CPPFLAGS			= -DPROGRAM_NAME="\"ldaptree\"" $(AM_CPPFLAGS)
src_ldaptree_CFLAGS			= $(AM_CFLAGS)
src_ldaptree_LDFLAGS			= $(AM_LDFLAGS)
src_ldaptree_LDADD			= $(AM_LDADD) -lldap -llber lib/libldaputils.a
src_ldaptree_SOURCES			= src/ldaptree.c


# macros for src/oidspectool
if LDAPUTILS_OIDSPECTOOL
   noinst_PROGRAMS			+= src/oidspectool
endif
src_oidspectool_DEPENDENCIES		= Makefile
src_oidspectool_CPPFLAGS		= -DPROGRAM_NAME="\"oidspectool\"" -Isrc/utils/oidspectool -I$(srcdir)/src/utils/oidspectool -DHAVE_CONFIG_H=1
src_oidspectool_CFLAGS			= -O2 -W
src_oidspectool_SOURCES			= src/utils/oidspectool/oidspecparser.y \
					  src/utils/oidspectool/oidspeclexer.l \
					  src/utils/oidspectool/oidspectool.c \
					  src/utils/oidspectool/oidspectool.h


# Makefile includes
GIT_PACKAGE_VERSION_DIR=include
SUBST_EXPRESSIONS =
include $(srcdir)/contrib/bindletools/build-aux/makefile-bindle.am
include $(srcdir)/contrib/bindletools/build-aux/makefile-autotools.am
include $(srcdir)/contrib/bindletools/build-aux/makefile-subst.am
include $(srcdir)/contrib/bindletools/build-aux/makefile-version.am


# custom silent rules
MY_V_OIDSPEC				= $(my__v_OIDSPEC_$(V))
my__v_OIDSPEC_				=
my__v_OIDSPEC_0				= @echo "  OIDSPEC " $@;
my__v_OIDSPEC_1				=


# custom targets
.PHONY:

doc/ldap2csv.1: Makefile $(srcdir)/doc/ldap2csv.1.in
	@$(do_subst_dt)

doc/ldap2json.1: Makefile $(srcdir)/doc/ldap2json.1.in
	@$(do_subst_dt)

doc/ldapdebug.1: Makefile $(srcdir)/doc/ldapdebug.1.in
	@$(do_subst_dt)

doc/ldapinfo.1: Makefile $(srcdir)/doc/ldapinfo.1.in
	@$(do_subst_dt)

doc/ldaptree.1: Makefile $(srcdir)/doc/ldaptree.1.in
	@$(do_subst_dt)

lib/libldapschema/lspecdata.c: $(OIDSPEC_FILES)
	@$(MAKE) -s src/oidspectool
	@mkdir -p lib/libldapschema
	$(MY_V_OIDSPEC)src/oidspectool -o $(srcdir)/$(@) --source $(MY_OIDSPECFLAGS)
	@touch $(srcdir)/$(@)

lib/libldapschema/lspecdata.h: $(OIDSPEC_FILES)
	@$(MAKE) -s src/oidspectool
	@mkdir -p lib/libldapschema
	$(MY_V_OIDSPEC)src/oidspectool -o $(srcdir)/$(@) --header $(MY_OIDSPECFLAGS)
	@touch $(srcdir)/$(@)


# local targets
install-exec-local:

install-data-local:

install-exec-hook:

install-data-hook:

uninstall-local:

clean-local:

distclean-local:
	rm -fR $(srcdir)/autom4te.cache

maintainer-clean-local:
	rm -f lib/libldapschema/lspecdata.c $(srcdir)/lib/libldapschema/lspecdata.c
	rm -f lib/libldapschema/lspecdata.h $(srcdir)/lib/libldapschema/lspecdata.h

# end of automake file
