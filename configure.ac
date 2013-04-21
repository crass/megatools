AC_PREREQ(2.60)
AC_INIT([megatools],[1.9.92],[megous@megous.com],[megatools])
AC_CONFIG_SRCDIR([Makefile.am])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE([foreign -Wno-portability])
AM_MAINTAINER_MODE
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_PROG_CC
AM_PROG_CC_C_O
AC_LIBTOOL_WIN32_DLL
AM_PROG_LIBTOOL
AC_HEADER_STDC

# Before making a release, the version string should be modified.
# The string is of the form C:R:A.
# - If interfaces have been changed or added, but binary compatibility has
#   been preserved, change to C+1:0:A+1
# - If binary compatibility has been broken (eg removed or changed interfaces)
#   change to C+1:0:0
# - If the interface is the same as the previous version, change to C:R+1:A

LIB_MEGA_VERSION=0:0:0
AC_SUBST(LIB_MEGA_VERSION)

# Define requirements

GLIB_VERSION="2.32.0"
GOBJECT_INTROSPECTION_VERSION="1.30"
NETTLE_REQUIRES="nettle >= 2.5 hogweed >= 2.5"
OPENSSL_REQUIRES="openssl"
CURL_REQUIRES="libcurl"
FUSE_REQUIRES="fuse"
MEGA_REQUIRES="gio-2.0 >= $GLIB_VERSION $NETTLE_REQUIRES"

# for libmega.pc
AC_SUBST(MEGA_REQUIRES)

# check for glib/gio
AM_PATH_GLIB_2_0([$GLIB_VERSION],,AC_MSG_ERROR([Glib $GLIB_VERSION or later is required to build megatools]),[gobject gio])
GLIB_MAKEFILE='$(top_srcdir)/Makefile.glib'
AC_SUBST(GLIB_MAKEFILE)

# check gobject-introspection
GOBJECT_INTROSPECTION_CHECK([$GOBJECT_INTROSPECTION_VERSION])

# check nettle
PKG_CHECK_MODULES(NETTLE, [$NETTLE_REQUIRES])
AC_SUBST(NETTLE_CFLAGS)
AC_SUBST(NETTLE_LIBS)

# check openssl
PKG_CHECK_MODULES(OPENSSL, [$OPENSSL_REQUIRES])
AC_SUBST(OPENSSL_CFLAGS)
AC_SUBST(OPENSSL_LIBS)

# check curl
PKG_CHECK_MODULES(CURL, [$CURL_REQUIRES])
AC_SUBST(CURL_CFLAGS)
AC_SUBST(CURL_LIBS)

# check fuse
PKG_CHECK_MODULES(FUSE, [$FUSE_REQUIRES], [enable_fuse=yes], [enable_fuse=no])
AM_CONDITIONAL([ENABLE_FUSE], [test x$enable_fuse = xyes])
AC_SUBST(FUSE_CFLAGS)
AC_SUBST(FUSE_LIBS)

# check if we can build tests
PKG_CHECK_MODULES(GLIBTESTS, [glib-2.0 >= 2.34.0], [enable_tests=yes], [enable_tests=no])
AM_CONDITIONAL([ENABLE_TESTS], [test x$enable_tests = xyes])

# enable dev compiler warnings
AC_ARG_ENABLE([warnings], AC_HELP_STRING([--enable-warnings], [Build with compiler warnings enabled.]))
AS_IF([test "x$enable_warnings" = "xyes"], [
  CFLAGS="$CFLAGS -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable -Wno-unused-local-typedefs -Wno-sign-compare -Wno-pointer-sign -Wno-missing-field-initializers"

  AS_IF([$CC --version | head -n1 | grep '(GCC) 4\.8' &>/dev/null], [CFLAGS="$CFLAGS -Wno-unused-local-typedefs"])
], [
  CFLAGS="$CFLAGS -Wno-pointer-sign -Wno-unused-variable"
  enable_warnings=no
])

# enable docs building
AC_ARG_ENABLE([docs-build], AC_HELP_STRING([--enable-docs-build], [Build man pages instead of using bundled ones.]))
AM_CONDITIONAL([ENABLE_DOCS_BUILD], [test "x$enable_docs_build" = xyes])
AS_IF([test "x$enable_docs_build" = "xyes"], [], [enable_docs_build=no])

AC_CONFIG_FILES([
  Makefile
  libmega.pc
  mega/Makefile
  mega/gjs/Makefile
  tools/Makefile
  tests/Makefile
  docs/Makefile
])

AC_OUTPUT

cat << EOF

Configured features:

  docs build: $enable_docs_build
  warnings: $enable_warnings
  megafs: $enable_fuse (requires fuse)
  tests: $enable_tests (requires glib-2.0 >= 2.34.0)

Run make now.

NOTE: On FreeBSD, you need to use GNU make (gmake)

EOF
