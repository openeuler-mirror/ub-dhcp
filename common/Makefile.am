AM_CPPFLAGS = -I$(top_srcdir) -DLOCALSTATEDIR='"@localstatedir@"'
AM_CFLAGS = $(LDAP_CFLAGS)

lib_LIBRARIES = libub-dhcp.a
libdhcp_a_SOURCES = alloc.c bpf.c comapi.c conflex.c ctrace.c dhcp4o6.c \
		      discover.c dispatch.c dns.c execute.c \
		      icmp.c inet.c lpf.c memory.c ns_name.c \
		      options.c packet.c parse.c print.c raw.c resolv.c \
		      socket.c tables.c tree.c
man_MANS = ub-dhcp-eval.5 ub-dhcp-options.5
EXTRA_DIST = $(man_MANS)

# We want to build this directory first, before descending into tests subdir.
# The reason is that ideally the tests should link existing objects from this
# directory. That eliminates any discrepancies between tested code and
# production code. Sadly, we are not there yet.
SUBDIRS = . tests
