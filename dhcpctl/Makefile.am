BINDLIBIRSDIR=@BINDLIBIRSDIR@
BINDLIBDNSDIR=@BINDLIBDNSDIR@
BINDLIBISCCFGDIR=@BINDLIBISCCFGDIR@
BINDLIBISCDIR=@BINDLIBISCDIR@

bin_PROGRAMS = ub-omshell
lib_LIBRARIES = libub-dhcpctl.a
noinst_PROGRAMS = cltest cltest2
man_MANS = ub-omshell.1 ub-dhcpctl.3
EXTRA_DIST = $(man_MANS)

omshell_SOURCES = omshell.c
omshell_LDADD = libub-dhcpctl.a ../common/libub-dhcp.a ../omapip/libub-omapi.a \
		$(BINDLIBIRSDIR)/libirs.a \
		$(BINDLIBDNSDIR)/libdns.a \
	        $(BINDLIBISCCFGDIR)/libisccfg.a \
		$(BINDLIBISCDIR)/libisc.a

libdhcpctl_a_SOURCES = dhcpctl.c callback.c remote.c

cltest_SOURCES = cltest.c
cltest_LDADD = libub-dhcpctl.a ../common/libub-dhcp.a ../omapip/libub-omapi.a \
	       $(BINDLIBIRSDIR)/libirs.a \
	       $(BINDLIBDNSDIR)/libdns.a \
	       $(BINDLIBISCCFGDIR)/libisccfg.a \
	       $(BINDLIBISCDIR)/libisc.a

cltest2_SOURCES = cltest2.c
cltest2_LDADD = libub-dhcpctl.a ../common/libub-dhcp.a ../omapip/libub-omapi.a \
	       $(BINDLIBIRSDIR)/libirs.a \
	       $(BINDLIBDNSDIR)/libdns.a \
	       $(BINDLIBISCCFGDIR)/libisccfg.a \
	       $(BINDLIBISCDIR)/libisc.a
