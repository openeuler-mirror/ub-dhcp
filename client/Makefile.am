# We want to build this directory first, before descending into tests subdir.
# The reason is that ideally the tests should link existing objects from this
# directory. That eliminates any discrepancies between tested code and
# production code. Sadly, we are not there yet.
SUBDIRS = . tests

AM_CPPFLAGS = -DCLIENT_PATH='"PATH=$(sbindir):/sbin:/bin:/usr/sbin:/usr/bin"'
AM_CPPFLAGS += -DLOCALSTATEDIR='"$(localstatedir)"'

dist_sysconf_DATA = ub-dhclient.conf.example
sbin_PROGRAMS = ub-dhclient
dhclient_SOURCES = client_tables.c clparse.c dhclient.c dhc6.c \
		   scripts/linux
dhclient_LDADD = ../common/libub-dhcp.@A@ ../omapip/libub-omapi.@A@ \
		 @BINDLIBIRSDIR@/libirs.@A@ \
		 @BINDLIBDNSDIR@/libdns.@A@ \
		 @BINDLIBISCCFGDIR@/libisccfg.@A@ \
		 @BINDLIBISCDIR@/libisc.@A@ \
		 $(CAPNG_LDADD)
man_MANS = ub-dhclient.8 ub-dhclient-script.8 ub-dhclient.conf.5 ub-dhclient.leases.5
EXTRA_DIST = $(man_MANS)
