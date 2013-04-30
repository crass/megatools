AM_CFLAGS = \
  $(GLIB_CFLAGS) \
  -I$(top_srcdir)

noinst_LTLIBRARIES = libsjson.la

libsjson_la_SOURCES = \
  sjson.gen.c \
  sjson.h

LDADD = \
  $(GLIB_LIBS)

EXTRA_DIST = sjson.c
