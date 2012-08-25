bin_PROGRAMS = conmon
conmon_SOURCES = conmon.cc conmon.h rtp.h

PKG_CHECK_MODULES([DEPS], [libpcap-1.2.1 >=1.2 libevent-2.0.19 >=2.0.19 libpthread])
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS}
AM_CPPFLAGS = $(DEPS_CFLAGS)
conmon_LDADD = $(DEPS_LIBS)
dist_noinst_SCRIPTS = autogen.sh
