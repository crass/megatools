AM_CFLAGS = \
  $(MEGA_CFLAGS) \
  -I$(srcdir)/libtools \
  -I$(top_srcdir)

noinst_LTLIBRARIES = libtools.la

libtools_la_SOURCES = \
  libtools/sjson.gen.c \
  libtools/sjson.h \
  libtools/http.c \
  libtools/http.h \
  libtools/oldmega.c \
  libtools/oldmega.h \
  libtools/tools.c \
  libtools/tools.h

LDADD = \
  $(MEGA_LIBS) \
  libtools.la \
  $(top_builddir)/mega/libmega.la

megafs_LDADD = \
  $(LDADD) \
  $(FUSE_LIBS)

megafs_CFLAGS = \
  $(AM_CFLAGS) \
  $(FUSE_CFLAGS)

bin_PROGRAMS = megadf megadl megaget megals megamkdir megaput megareg megarm megamv megastream megasync

megadf_SOURCES     = df.c
megadl_SOURCES     = dl.c
megaget_SOURCES    = get.c
megals_SOURCES     = ls.c
megamkdir_SOURCES  = mkdir.c
megaput_SOURCES    = put.c
megareg_SOURCES    = reg.c
megarm_SOURCES     = rm.c
megamv_SOURCES     = mv.c
megastream_SOURCES = stream.c
megasync_SOURCES   = sync.c

if ENABLE_FUSE
bin_PROGRAMS += megafs
megafs_SOURCES     = fs.c
endif
