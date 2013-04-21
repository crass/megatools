AM_CFLAGS = \
  -DG_LOG_DOMAIN=\"Mega\" \
  $(GLIB_CFLAGS) \
  -I$(top_srcdir)

LDADD = \
  $(GLIB_LIBS) \
  $(top_builddir)/mega/libmega.la

if ENABLE_TESTS
noinst_PROGRAMS = test-aes test-rsa
endif

test_aes_SOURCES = test-aes.c
test_rsa_SOURCES = test-rsa.c

EXTRA_DIST = \
  config.js \
  test-bindings.js \
  test-bindings.py \
  test-bindings.lua \
  test-bindings.rb \
  test-bindings.sh \
  test-http.sh \
  test-http.js \
  test-server.sh \
  test-server.js \
  test-api.sh \
  test-api.js
