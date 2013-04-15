AC_PREREQ(2.60)
AC_INIT([megatools],[1.9.91],[megous@megous.com],[megatools])
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

GLIB_REQUIRED=2.32.0
AM_PATH_GLIB_2_0($GLIB_REQUIRED,,,gobject gio)
if test "$GLIB_LIBS" = ""; then
   AC_MSG_ERROR(GLIB $GLIB_REQUIRED or later is required to build libmega)
fi
GLIB_CFLAGS="$GLIB_CFLAGS"

MEGA_REQUIRES="gio-2.0 >= 2.32.0 libcurl openssl"
FUSE_REQUIRES="fuse"

GOBJECT_INTROSPECTION_CHECK([1.30])

PKG_CHECK_MODULES(MEGA, [$MEGA_REQUIRES])
AC_SUBST(MEGA_REQUIRES)
AC_SUBST(MEGA_CFLAGS)
AC_SUBST(MEGA_LIBS)

PKG_CHECK_MODULES(FUSE, [$FUSE_REQUIRES], [ENABLE_FUSE=yes], [ENABLE_FUSE=no])
AC_SUBST(FUSE_CFLAGS)
AC_SUBST(FUSE_LIBS)
AM_CONDITIONAL([ENABLE_FUSE], [test x$ENABLE_FUSE = xyes])

GLIB_MAKEFILE='$(top_srcdir)/Makefile.glib'
AC_SUBST(GLIB_MAKEFILE)

PKG_CHECK_MODULES(GLIBTESTS, [glib-2.0 >= 2.34.0], [ENABLE_TESTS=yes], [ENABLE_TESTS=no])
AM_CONDITIONAL([ENABLE_TESTS], [test x$ENABLE_TESTS = xyes])

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
  megafs: $ENABLE_FUSE (requires fuse)
  tests: $ENABLE_TESTS (requires glib-2.0 >= 2.34.0)

Run make now.

NOTE: On FreeBSD, you need to use GNU make (gmake)

EOF
