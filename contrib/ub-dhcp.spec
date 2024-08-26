Summary: The Internet Systems Consortium (ISC) DHCP server
Name: ub-dhcp
%define version 3.0.2
Version: %{version}
Release: 2tac
Group: System Environment/Daemons
Source: /usr/local/src/RPM/SOURCES/ub-dhcp-%{version}.tar.gz
Copyright: ISC
BuildRoot: /var/tmp/ub-dhcp-%{version}-root

%description
Dhcp includes the DHCP server which is used for dynamically configuring
hosts on a network.  Host configuration items such as IP address, name
servers, domain name, etc. can all be retrieved from the DHCP server by
a DHCP client.  This eases the burden of network wide configuration by
putting all of the configuration into one place.

%package client
Summary: A DHCP client
Group: System Environment/Configuration

%description client
Dhcp client is a DHCP client for various UNIX operating systems. It allows
a UNIX machine to obtain it's networking parameters from a DHCP server.

%package relay
Summary: A DHCP relay
Group: System Environment/Daemons

%description relay
Dhcp relay is a relay agent for DHCP packets.  It is used on a subnet with
DHCP clients to "relay" their requests to a subnet that has a DHCP server
on it.  Because DHCP packets can be broadcast, they will not be routed off
of the local subnet.  The DHCP relay takes care of this for the client.

%package devel
Summary: Development headers and libraries for the dhcpctl API
Group: Development/Libraries

%description devel
Dhcp devel contains all of the libraries and headers for developing with
the dhcpctl API.

%prep
%setup -q -n ub-dhcp-%{version}
# do some file editing
egrep "VARRUN
ETC
VARDB" site.conf | sed -e 's/ *=/=/g' -e 's/= */=/g' > vars
. ./vars
cat << EOF >> includes/site.h
#define _PATH_DHCPD_PID		"$VARRUN/ub-dhcpd.pid"
#define _PATH_DHCPD_DB		"$ETC/ub-dhcpd.leases"
#define _PATH_DHCPD_CONF	"$ETC/ub-dhcpd.conf"
EOF
./configure --with-nsupdate

%build
make

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/local/sbin

make DESTDIR="$RPM_BUILD_ROOT" install

%ifos linux
mkdir -p ${RPM_BUILD_ROOT}/etc/rc.d/{init,rc0,rc1,rc2,rc3,rc4,rc5,rc6}.d
install -m 755 linux.init ${RPM_BUILD_ROOT}/etc/rc.d/init.d/ub-dhcpd
%else
%ifos solaris
mkdir -p ${RPM_BUILD_ROOT}/etc/init.d
sed -e s'|@PREFIX@|%{_prefix}|g' < contrib/solaris.init > ${RPM_BUILD_ROOT}/etc/init.d/ub-dhcpd
chmod 755 ${RPM_BUILD_ROOT}/etc/init.d/ub-dhcpd
%endif
%endif

# strip binaries and libraries
strip $RPM_BUILD_ROOT%{_prefix}/sbin/* || :
for i in `find $RPM_BUILD_ROOT/ -type 'f' -perm '+a=x' ! -name 'lib*so*'`; do
	file $i |grep -q "not stripped" && strip $i
done

%post
%ifos linux
    /sbin/chkconfig --add ub-dhcpd
    /etc/rc.d/init.d/ub-dhcpd start
%else
    %ifos solaris
	ln /etc/init.d/ub-dhcpd /etc/rc2.d/S90dhcpd
	ln /etc/init.d/ub-dhcpd /etc/rc0.d/K30dhcpd
	/etc/init.d/ub-dhcpd start
    %else
	echo "Unknown O/S.  You will need to manually configure your\nsystem"
	echo "to start the DHCP server on system startup."
    %endif
%endif

%preun
if [ $1 = 0 ]; then
    %ifos linux
	/etc/rc.d/init.d/ub-dhcpd stop
	/sbin/chkconfig --del ub-dhcpd
    %else
	%ifos solaris
	    /etc/init.d/ub-dhcpd stop
	    rm /etc/rc2.d/S90dhcpd
	    rm /etc/rc0.d/K30dhcpd
	%else
	    echo "Unknown O/S.  You will need to manually clean up the DHCP"
	    echo "server startup\n in your system startup environment."
	%endif
    %endif
fi

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc COPYRIGHT DOCUMENTATION ISC-LICENSE CHANGES README RELNOTES doc/*

%{_prefix}/sbin/ub-dhcpd
%{_prefix}/man/cat1m/ub-dhcpd.1m
%{_prefix}/man/cat4/ub-dhcpd.conf.4
%{_prefix}/man/cat4/ub-dhcpd.leases.4
%{_prefix}/man/cat4/ub-dhcp-options.4
%{_prefix}/man/cat4/ub-dhcp-eval.4
%{_prefix}/man/cat4/ub-dhcp-contrib.4
%ifos linux
%config /etc/rc.d/init.d/ub-dhcpd
%else
%ifos solaris
%config /etc/init.d/ub-dhcpd
%endif
%endif

%files devel
%{_prefix}/man/cat3
%{_prefix}/lib
%{_prefix}/include

%files client
%{_prefix}/etc/ub-dhclient-script
%{_prefix}/sbin/ub-dhclient
%{_prefix}/man/cat1m/ub-dhclient.1m
%{_prefix}/man/cat1m/ub-dhclient-script.1m
%{_prefix}/man/cat4/ub-dhclient.conf.4
%{_prefix}/man/cat4/ub-dhclient.leases.4

%files relay
%{_prefix}/sbin/ub-dhcrelay
%{_prefix}/man/cat1m/ub-dhcrelay.1m

%changelog
* Fri Oct  1 1999 Brian J. Murrell <brian@interlinx.bc.ca>
- write a spec file for ub-dhcpd
