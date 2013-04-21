SUBDIRS = gjs

AM_CFLAGS = \
  -DG_LOG_DOMAIN=\"Mega\" \
  $(GLIB_CFLAGS) \
  $(NETTLE_CFLAGS) \
  -I$(top_srcdir) \
  -I$(srcdir)

lib_LTLIBRARIES = \
  libmega.la

libmega_la_LIBADD = \
  $(GLIB_LIBS) \
  $(NETTLE_LIBS)

libmega_la_LDFLAGS = -version-info $(LIB_MEGA_VERSION) -no-undefined

libmega_la_SOURCES = \
  mega-aes-key.c \
  mega-aes-key.h \
  mega-rsa-key.c \
  mega-rsa-key.h \
  mega-chunked-cbc-mac.c \
  mega-chunked-cbc-mac.h \
  mega-http-client.c \
  mega-http-client.h \
  mega-http-io-stream.c \
  mega-http-io-stream.h \
  mega-http-input-stream.c \
  mega-http-input-stream.h \
  mega-http-output-stream.c \
  mega-http-output-stream.h \
  mega-aes-ctr-encryptor.c \
  mega-aes-ctr-encryptor.h \
  utils.c \
  utils.h \
  megatypes.h \
  mega.h \
  $(GLIB_GENERATED)

include $(GLIB_MAKEFILE)

GLIB_GENERATED = mega-marshal.c mega-marshal.h
GLIB_GENERATED += mega-enum-types.c mega-enum-types.h

mega_marshal_sources = $(libmega_la_SOURCES)
mega_enum_types_sources = $(libmega_la_SOURCES)

BUILT_SOURCES = $(GLIB_GENERATED)

pkginclude_HEADERS = $(filter-out mega-marshal.h,$(filter %.h,$(libmega_la_SOURCES)))
pkgincludedir = $(includedir)/mega

CLEANFILES =

include $(INTROSPECTION_MAKEFILE)
INTROSPECTION_GIRS = Mega-1.0.gir
INTROSPECTION_SCANNER_ARGS = --add-include-path=.
INTROSPECTION_COMPILER_ARGS = --includedir=.

if HAVE_INTROSPECTION

gi_libmega_files = $(filter-out mega-enum-types.% mega-marshal.%,$(libmega_la_SOURCES))
gi_built_libmega_files = mega-enum-types.h

Mega-1.0.gir: libmega.la
Mega_1_0_gir_INCLUDES = Gio-2.0
Mega_1_0_gir_CFLAGS = $(AM_CFLAGS)
Mega_1_0_gir_LIBS = libmega.la
Mega_1_0_gir_EXPORT_PACKAGES = libmega
Mega_1_0_gir_SCANNERFLAGS = --c-include "mega/mega.h" --warn-all
Mega_1_0_gir_FILES = \
	$(addprefix $(srcdir)/, $(gi_libmega_files)) \
        $(foreach f,$(gi_built_libmega_files), \
	   $(if $(shell test -f $(addprefix $(srcdir)/,$(f)) && echo yes), \
	      $(addprefix $(srcdir)/,$(f)), \
	      $(f)))

girdir = $(datadir)/gir-1.0
gir_DATA = $(INTROSPECTION_GIRS)

typelibdir = $(libdir)/girepository-1.0
typelib_DATA = $(INTROSPECTION_GIRS:.gir=.typelib)

CLEANFILES += $(gir_DATA) $(typelib_DATA)

endif
