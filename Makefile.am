#
# automake adds dependencies that we don't like, so we explicitly remove them
#
Makefile:

#
# for libtool
#
ACLOCAL_AMFLAGS = -I m4

#
# We have a lot of files that we want shipped with the distribution.
#
EXTRA_DIST = RELNOTES LICENSE configure.ac+lt config+lt \
	     contrib/3.0b1-lease-convert contrib/dhclient-tz-exithook.sh \
	     contrib/ub-dhcp.spec contrib/sethostname.sh contrib/solaris.init \
	     contrib/ms2isc/Registry.pm contrib/ms2isc/ms2isc.pl \
	     contrib/ms2isc/readme.txt contrib/ldap/ub-dhcpd-conf-to-ldap \
	     contrib/ldap/ub-dhcp.schema contrib/ldap/README.ldap \
             contrib/ub-dhcp-lease-list.pl \
	     doc/BIND-libraries doc/DHCPv4-over-DHCPv6 \
	     doc/IANA-arp-parameters doc/Makefile doc/References.html \
	     doc/References.txt doc/References.xml doc/api+protocol \
	     doc/ja_JP.eucJP/ub-dhclient-script.8 doc/ja_JP.eucJP/ub-dhclient.8 \
	     doc/ja_JP.eucJP/ub-dhclient.conf.5 doc/ja_JP.eucJP/ub-dhclient.leases.5 \
	     doc/ja_JP.eucJP/ub-dhcp-eval.5 doc/ja_JP.eucJP/ub-dhcp-options.5 \
	     doc/examples/ub-dhclient-dhcpv6.conf doc/examples/ub-dhcpd-dhcpv6.conf \
	     doc/devel/arch.dox doc/devel/atf.dox doc/devel/contrib.dox \
	     doc/devel/debug.dox doc/devel/isc-logo.jpg doc/devel/libtool.dox \
	     doc/devel/mainpage.dox doc/devel/omapi.dox doc/devel/qa.dox \
	     client/tests/Atffile common/tests/Atffile server/tests/Atffile \
	     client/tests/Kyuafile common/tests/Kyuafile server/tests/Kyuafile \
         m4/README CONTRIBUTING.md

if HAVE_BINDDIR
EXTRA_DIST += bind/Makefile.in bind/bind.tar.gz bind/version.tmp
endif

# Use an autoconf substitution vs an automake conditional here
# to fool automake when the bind directory does not exist.
SUBDIRS = @BINDSUBDIR@ includes tests common omapip client dhcpctl relay server

DIST_SUBDIRS = $(SUBDIRS) keama

nobase_include_HEADERS = dhcpctl/dhcpctl.h

#
# distcheck tuning
#

DISTCHECK_CONFIGURE_FLAGS =  @DISTCHECK_ATF_CONFIGURE_FLAG@
DISTCHECK_CONFIGURE_FLAGS += @DISTCHECK_LIBBIND_CONFIGURE_FLAG@
DISTCHECK_CONFIGURE_FLAGS += @DISTCHECK_LIBTOOL_CONFIGURE_FLAG@

distcheck-hook:
if HAVE_BINDDIR
	chmod u+w $(distdir)/bind
endif

distclean-local:
	rm -f config.report
