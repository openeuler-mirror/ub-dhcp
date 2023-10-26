SUBDIRS = . tests

AM_CPPFLAGS = -DLOCALSTATEDIR='"@localstatedir@"'

sbin_PROGRAMS = ub-dhcrelay
dhcrelay_SOURCES = dhcrelay.c
dhcrelay_LDADD = ../common/libub-dhcp.@A@ ../omapip/libub-omapi.@A@ \
		 @BINDLIBIRSDIR@/libirs.@A@ \
		 @BINDLIBDNSDIR@/libdns.@A@ \
		 @BINDLIBISCCFGDIR@/libisccfg.@A@ \
		 @BINDLIBISCDIR@/libisc.@A@ \
		 $(CAPNG_LDADD)
man_MANS = ub-dhcrelay.8
EXTRA_DIST = $(man_MANS)
