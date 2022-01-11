ACLOCAL_AMFLAGS=-I m4

# noinst_bin_PROGRAMS=test-match

# test_match_SOURCES=test.c

lib_LTLIBRARIES=libnss_filter.la

# libnss_filter_la_CPPFLAGS=-DETCDIR="\"$(prefix)/etc\"" $(AM_CPPFLAGS)
libnss_filter_la_LDFLAGS=-version-info 2:0:0 $(AM_LDFLAGS)
libnss_filter_la_SOURCES=nss-filter.c

# sysconf_DATA = hosts.blacklist
pkgdata_DATA = hosts.blacklist
