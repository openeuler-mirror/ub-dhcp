/* lpf.c

   Linux packet filter code, contributed by Brian Murrel at Interlinx
   Support Services in Vancouver, B.C. */

/*
 * Copyright (C) 2004-2022 Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1996-2003 by Internet Software Consortium
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *   Internet Systems Consortium, Inc.
 *   PO Box 360
 *   Newmarket, NH 03857 USA
 *   <info@isc.org>
 *   https://www.isc.org/
 */

#include "dhcpd.h"
#if defined (USE_LPF_SEND) || defined (USE_LPF_RECEIVE)
#include <sys/uio.h>
#include <errno.h>

#include <asm/types.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/in_systm.h>
#include "includes/netinet/ip.h"
#include "includes/netinet/udp.h"
#include "includes/netinet/if_ether.h"
#endif

#if defined (USE_LPF_RECEIVE) || defined (USE_LPF_HWADDR)
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <ifaddrs.h>

/* Default broadcast address for IPoIB */
static unsigned char default_ib_bcast_addr[20] = {
 	0x00, 0xff, 0xff, 0xff,
	0xff, 0x12, 0x40, 0x1b,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff
};

#endif

#if defined (USE_LPF_SEND) || defined (USE_LPF_RECEIVE)
/* Reinitializes the specified interface after an address change.   This
   is not required for packet-filter APIs. */

#ifdef USE_LPF_SEND
void if_reinitialize_send (info)
	struct interface_info *info;
{
}
#endif

#ifdef USE_LPF_RECEIVE
void if_reinitialize_receive (info)
	struct interface_info *info;
{
}
#endif

/* Called by get_interface_list for each interface that's discovered.
   Opens a packet filter for each interface and adds it to the select
   mask. */

int if_register_lpf (info)
	struct interface_info *info;
{
	int sock;
	union {
		struct sockaddr_ll ll;
		struct sockaddr common;
		} sa;
	struct ifreq ifr;
	int type;
	int protocol;

	get_hw_addr(info);
	if (info->hw_address.hbuf[0] == HTYPE_INFINIBAND) {
		type = SOCK_DGRAM;
		protocol = ETHERTYPE_IP;
	} else {
		type = SOCK_RAW;
		protocol = ETH_P_ALL;
	}

	/* Make an LPF socket. */
	if ((sock = socket(PF_PACKET, type, htons((short)protocol))) < 0) {
		if (errno == ENOPROTOOPT || errno == EPROTONOSUPPORT ||
		    errno == ESOCKTNOSUPPORT || errno == EPFNOSUPPORT ||
		    errno == EAFNOSUPPORT || errno == EINVAL) {
			log_error ("socket: %m - make sure");
			log_error ("CONFIG_PACKET (Packet socket) %s",
				   "and CONFIG_FILTER");
			log_error ("(Socket Filtering) are enabled %s",
				   "in your kernel");
			log_fatal ("configuration!");
		}
		log_fatal ("Open a socket for LPF: %m");
	}

	memset (&ifr, 0, sizeof ifr);
	strncpy (ifr.ifr_name, (const char *)info -> ifp, sizeof ifr.ifr_name);
	ifr.ifr_name[IFNAMSIZ-1] = '\0';
	if (ioctl (sock, SIOCGIFINDEX, &ifr))
		log_fatal ("Failed to get interface index: %m");

	/* Bind to the interface name */
	memset (&sa, 0, sizeof sa);
	sa.ll.sll_family = AF_PACKET;
	sa.ll.sll_protocol = htons(protocol);
	sa.ll.sll_ifindex = ifr.ifr_ifindex;
	if (bind (sock, &sa.common, sizeof sa)) {
		if (errno == ENOPROTOOPT || errno == EPROTONOSUPPORT ||
		    errno == ESOCKTNOSUPPORT || errno == EPFNOSUPPORT ||
		    errno == EAFNOSUPPORT || errno == EINVAL) {
			log_error ("socket: %m - make sure");
			log_error ("CONFIG_PACKET (Packet socket) %s",
				   "and CONFIG_FILTER");
			log_error ("(Socket Filtering) are enabled %s",
				   "in your kernel");
			log_fatal ("configuration!");
		}
		log_fatal ("Bind socket to interface: %m");

	}

	return sock;
}
#endif /* USE_LPF_SEND || USE_LPF_RECEIVE */

#ifdef USE_LPF_SEND
void if_register_send (info)
	struct interface_info *info;
{
	/* If we're using the lpf API for sending and receiving,
	   we don't need to register this interface twice. */
#ifndef USE_LPF_RECEIVE
	info -> wfdesc = if_register_lpf (info);
#else
	info -> wfdesc = info -> rfdesc;
#endif
	if (!quiet_interface_discovery)
		log_info ("Sending on   LPF/%s/%s%s%s",
		      info -> name,
		      print_hw_addr (info -> hw_address.hbuf [0],
				     info -> hw_address.hlen - 1,
				     &info -> hw_address.hbuf [1]),
		      (info -> shared_network ? "/" : ""),
		      (info -> shared_network ?
		       info -> shared_network -> name : ""));
}

void if_deregister_send (info)
	struct interface_info *info;
{
	/* don't need to close twice if we are using lpf for sending and
	   receiving */
#ifndef USE_LPF_RECEIVE
	/* for LPF this is simple, packet filters are removed when sockets
	   are closed */
	close (info -> wfdesc);
#endif
	info -> wfdesc = -1;
	if (!quiet_interface_discovery)
		log_info ("Disabling output on LPF/%s/%s%s%s",
		      info -> name,
		      print_hw_addr (info -> hw_address.hbuf [0],
				     info -> hw_address.hlen - 1,
				     &info -> hw_address.hbuf [1]),
		      (info -> shared_network ? "/" : ""),
		      (info -> shared_network ?
		       info -> shared_network -> name : ""));
}
#endif /* USE_LPF_SEND */

#ifdef USE_LPF_RECEIVE
/* Defined in bpf.c.   We can't extern these in dhcpd.h without pulling
   in bpf includes... */
extern struct sock_filter dhcp_bpf_filter [];
extern int dhcp_bpf_filter_len;
extern struct sock_filter dhcp_ib_bpf_filter [];
extern int dhcp_ib_bpf_filter_len;

#if defined(RELAY_PORT)
extern struct sock_filter dhcp_bpf_relay_filter [];
extern int dhcp_bpf_relay_filter_len;
#endif

#if defined (HAVE_TR_SUPPORT)
extern struct sock_filter dhcp_bpf_tr_filter [];
extern int dhcp_bpf_tr_filter_len;
static void lpf_tr_filter_setup (struct interface_info *);
#endif

static void lpf_gen_filter_setup (struct interface_info *);

void if_register_receive (info)
	struct interface_info *info;
{
	/* Open a LPF device and hang it on this interface... */
	info -> rfdesc = if_register_lpf (info);

#ifdef PACKET_AUXDATA
	{
	int val = 1;
	if (info->hw_address.hbuf[0] != HTYPE_INFINIBAND) {
		if (setsockopt(info->rfdesc, SOL_PACKET, PACKET_AUXDATA,
			      &val, sizeof(val)) < 0) {
			if (errno != ENOPROTOOPT) {
				log_fatal ("Failed to set auxiliary packet data: %m");
			}
		}
	}
	}
#endif


#if defined (HAVE_TR_SUPPORT)
	if (info -> hw_address.hbuf [0] == HTYPE_IEEE802)
		lpf_tr_filter_setup (info);
	else
#endif
		lpf_gen_filter_setup (info);

	if (!quiet_interface_discovery)
		log_info ("Listening on LPF/%s/%s%s%s",
			  info -> name,
			  print_hw_addr (info -> hw_address.hbuf [0],
					 info -> hw_address.hlen - 1,
					 &info -> hw_address.hbuf [1]),
			  (info -> shared_network ? "/" : ""),
			  (info -> shared_network ?
			   info -> shared_network -> name : ""));
}

void if_deregister_receive (info)
	struct interface_info *info;
{
	/* for LPF this is simple, packet filters are removed when sockets
	   are closed */
	close (info -> rfdesc);
	info -> rfdesc = -1;
	if (!quiet_interface_discovery)
		log_info ("Disabling input on LPF/%s/%s%s%s",
			  info -> name,
			  print_hw_addr (info -> hw_address.hbuf [0],
					 info -> hw_address.hlen - 1,
					 &info -> hw_address.hbuf [1]),
			  (info -> shared_network ? "/" : ""),
			  (info -> shared_network ?
			   info -> shared_network -> name : ""));
}

static void lpf_gen_filter_setup (info)
	struct interface_info *info;
{
	struct sock_fprog p;

	memset(&p, 0, sizeof(p));

	if (info->hw_address.hbuf[0] == HTYPE_INFINIBAND) {
		p.len = dhcp_ib_bpf_filter_len;
		p.filter = dhcp_ib_bpf_filter;

		/* Patch the server port into the LPF program...
		   XXX
		   changes to filter program may require changes
		   to the insn number(s) used below!
		   XXX */
		dhcp_ib_bpf_filter[6].k = ntohs (local_port);
	} else {

	/* Set up the bpf filter program structure.    This is defined in
	   bpf.c */
	p.len = dhcp_bpf_filter_len;
	p.filter = dhcp_bpf_filter;

        /* Patch the server port into the LPF  program...
	   XXX changes to filter program may require changes
	   to the insn number(s) used below! XXX */
#if defined(RELAY_PORT)
	if (relay_port) {
		/*
		 * If user defined relay UDP port, we need to filter
		 * also on the user UDP port.
		 */
		p.len = dhcp_bpf_relay_filter_len;
		p.filter = dhcp_bpf_relay_filter;

		dhcp_bpf_relay_filter [10].k = ntohs (relay_port);
	}
#endif
	dhcp_bpf_filter [8].k = ntohs (local_port);

	}

	if (setsockopt (info -> rfdesc, SOL_SOCKET, SO_ATTACH_FILTER, &p,
			sizeof p) < 0) {
		if (errno == ENOPROTOOPT || errno == EPROTONOSUPPORT ||
		    errno == ESOCKTNOSUPPORT || errno == EPFNOSUPPORT ||
		    errno == EAFNOSUPPORT) {
			log_error ("socket: %m - make sure");
			log_error ("CONFIG_PACKET (Packet socket) %s",
				   "and CONFIG_FILTER");
			log_error ("(Socket Filtering) are enabled %s",
				   "in your kernel");
			log_fatal ("configuration!");
		}
		log_fatal ("Can't install packet filter program: %m");
	}
}

#if defined (HAVE_TR_SUPPORT)
static void lpf_tr_filter_setup (info)
	struct interface_info *info;
{
	struct sock_fprog p;

	memset(&p, 0, sizeof(p));

	/* Set up the bpf filter program structure.    This is defined in
	   bpf.c */
	p.len = dhcp_bpf_tr_filter_len;
	p.filter = dhcp_bpf_tr_filter;

        /* Patch the server port into the LPF  program...
	   XXX changes to filter program may require changes
	   XXX to the insn number(s) used below!
	   XXX Token ring filter is null - when/if we have a filter
	   XXX that's not, we'll need this code.
	   XXX dhcp_bpf_filter [?].k = ntohs (local_port); */

	if (setsockopt (info -> rfdesc, SOL_SOCKET, SO_ATTACH_FILTER, &p,
			sizeof p) < 0) {
		if (errno == ENOPROTOOPT || errno == EPROTONOSUPPORT ||
		    errno == ESOCKTNOSUPPORT || errno == EPFNOSUPPORT ||
		    errno == EAFNOSUPPORT) {
			log_error ("socket: %m - make sure");
			log_error ("CONFIG_PACKET (Packet socket) %s",
				   "and CONFIG_FILTER");
			log_error ("(Socket Filtering) are enabled %s",
				   "in your kernel");
			log_fatal ("configuration!");
		}
		log_fatal ("Can't install packet filter program: %m");
	}
}
#endif /* HAVE_TR_SUPPORT */
#endif /* USE_LPF_RECEIVE */

#ifdef USE_LPF_SEND
ssize_t send_packet_ib(interface, packet, raw, len, from, to, hto)
	struct interface_info *interface;
	struct packet *packet;
	struct dhcp_packet *raw;
	size_t len;
	struct in_addr from;
	struct sockaddr_in *to;
	struct hardware *hto;
{
	unsigned ibufp = 0;
	double ih [1536 / sizeof (double)];
	unsigned char *buf = (unsigned char *)ih;
	ssize_t result;

	union sockunion {
		struct sockaddr sa;
		struct sockaddr_ll sll;
		struct sockaddr_storage ss;
	} su;

	assemble_udp_ip_header (interface, buf, &ibufp, from.s_addr,
				to->sin_addr.s_addr, to->sin_port,
				(unsigned char *)raw, len);
	memcpy (buf + ibufp, raw, len);

	memset(&su, 0, sizeof(su));
	su.sll.sll_family = AF_PACKET;
	su.sll.sll_protocol = htons(ETHERTYPE_IP);

	if (!(su.sll.sll_ifindex = if_nametoindex(interface->name))) {
		errno = ENOENT;
		log_error ("send_packet_ib: %m - failed to get if index");
		return -1;
	}

	su.sll.sll_hatype = htons(HTYPE_INFINIBAND);
	su.sll.sll_halen = sizeof(interface->bcast_addr);
	memcpy(&su.sll.sll_addr, interface->bcast_addr, 20);

	result = sendto(interface->wfdesc, buf, ibufp + len, 0,
			&su.sa, sizeof(su));

	if (result < 0)
		log_error ("send_packet_ib: %m");

	return result;
}

ssize_t send_packet (interface, packet, raw, len, from, to, hto)
	struct interface_info *interface;
	struct packet *packet;
	struct dhcp_packet *raw;
	size_t len;
	struct in_addr from;
	struct sockaddr_in *to;
	struct hardware *hto;
{
	unsigned hbufp = 0, ibufp = 0;
	double hh [16];
	double ih [1536 / sizeof (double)];
	unsigned char *buf = (unsigned char *)ih;
	int result;
	int fudge;

	if (!strcmp (interface -> name, "fallback"))
		return send_fallback (interface, packet, raw,
				      len, from, to, hto);

	if (interface->hw_address.hbuf[0] == HTYPE_INFINIBAND) {
		return send_packet_ib(interface, packet, raw, len, from,
				      to, hto);
	}

	if (hto == NULL && interface->anycast_mac_addr.hlen)
		hto = &interface->anycast_mac_addr;

	/* Assemble the headers... */
	assemble_hw_header (interface, (unsigned char *)hh, &hbufp, hto);
	fudge = hbufp % 4;	/* IP header must be word-aligned. */
	memcpy (buf + fudge, (unsigned char *)hh, hbufp);
	ibufp = hbufp + fudge;
	assemble_udp_ip_header (interface, buf, &ibufp, from.s_addr,
				to -> sin_addr.s_addr, to -> sin_port,
				(unsigned char *)raw, len);
	memcpy (buf + ibufp, raw, len);
	result = write(interface->wfdesc, buf + fudge, ibufp + len - fudge);
	if (result < 0)
		log_error ("send_packet: %m");
	return result;
}
#endif /* USE_LPF_SEND */

#ifdef USE_LPF_RECEIVE
ssize_t receive_packet_ib (interface, buf, len, from, hfrom)
	struct interface_info *interface;
	unsigned char *buf;
	size_t len;
	struct sockaddr_in *from;
	struct hardware *hfrom;
{
	int length = 0;
	int offset = 0;
	unsigned char ibuf [1536];
	unsigned bufix = 0;
	unsigned paylen;

	length = read(interface->rfdesc, ibuf, sizeof(ibuf));

	if (length <= 0)
		return length;

	offset = decode_udp_ip_header(interface, ibuf, bufix, from,
				       (unsigned)length, &paylen, 0);

	if (offset < 0)
		return 0;

	bufix += offset;
	length -= offset;

	if (length < paylen)
		log_fatal("Internal inconsistency at %s:%d.", MDL);

	/* Copy out the data in the packet... */
	memcpy(buf, &ibuf[bufix], paylen);

	return (ssize_t)paylen;
}

ssize_t receive_packet (interface, buf, len, from, hfrom)
	struct interface_info *interface;
	unsigned char *buf;
	size_t len;
	struct sockaddr_in *from;
	struct hardware *hfrom;
{
	int length = 0;
	int offset = 0;
	int csum_ready = 1;
	unsigned char ibuf [1536];
	unsigned bufix = 0;
	unsigned paylen;
	struct iovec iov = {
		.iov_base = ibuf,
		.iov_len = sizeof ibuf,
	};
#ifdef PACKET_AUXDATA
	/*
	 * We only need cmsgbuf if we are getting the aux data and we
	 * only get the auxdata if it is actually defined
	 */
	unsigned char cmsgbuf[CMSG_LEN(sizeof(struct tpacket_auxdata))];
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cmsgbuf,
		.msg_controllen = sizeof(cmsgbuf),
	};
#else
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = NULL,
		.msg_controllen = 0,
	};
#endif /* PACKET_AUXDATA */

	if (interface->hw_address.hbuf[0] == HTYPE_INFINIBAND) {
		return receive_packet_ib(interface, buf, len, from, hfrom);
	}

	length = recvmsg (interface->rfdesc, &msg, 0);
	if (length <= 0)
		return length;

#ifdef PACKET_AUXDATA
	{
	/*  Use auxiliary packet data to:
	 *
	 *  a. Weed out extraneous VLAN-tagged packets - If the NIC driver is
	 *  handling VLAN encapsulation (i.e. stripping/adding VLAN tags),
	 *  then an inbound VLAN packet will be seen twice: Once by
	 *  the parent interface (e.g. eth0) with a VLAN tag != 0; and once
	 *  by the vlan interface (e.g. eth0.n) with a VLAN tag of 0 (i.e none).
	 *  We want to discard the packet sent to the parent and thus respond
	 *  only over the vlan interface.  (Drivers for Intel PRO/1000 series
	 *  NICs perform VLAN encapsulation, while drivers for PCnet series
	 *  do not, for example. The linux kernel makes stripped vlan info
	 *  visible to user space via CMSG/auxdata, this appears to not be
	 *  true for BSD OSs.).  NOTE: this is only supported on linux flavors
	 *  which define the tpacket_auxdata.tp_vlan_tci.
	 *
	 *  b. Determine if checksum is valid for use. It may not be if
	 *  checksum offloading is enabled on the interface.  */
	struct cmsghdr *cmsg;

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_PACKET &&
		    cmsg->cmsg_type == PACKET_AUXDATA) {
			struct tpacket_auxdata *aux = (void *)CMSG_DATA(cmsg);
#ifdef VLAN_TCI_PRESENT
			/* Discard packets with stripped vlan id */
			/* VLAN ID is only bottom 12-bits of TCI */
			if (aux->tp_vlan_tci & 0x0fff)
				return 0;
#endif

			csum_ready = ((aux->tp_status & TP_STATUS_CSUMNOTREADY)
				      ? 0 : 1);
		}
	}

	}
#endif /* PACKET_AUXDATA */

	bufix = 0;
	/* Decode the physical header... */
	offset = decode_hw_header (interface, ibuf, bufix, hfrom);

	/* If a physical layer checksum failed (dunno of any
	   physical layer that supports this, but WTH), skip this
	   packet. */
	if (offset < 0) {
		return 0;
	}

	bufix += offset;
	length -= offset;

	/* Decode the IP and UDP headers... */
	offset = decode_udp_ip_header (interface, ibuf, bufix, from,
				       (unsigned)length, &paylen, csum_ready);

	/* If the IP or UDP checksum was bad, skip the packet... */
	if (offset < 0)
		return 0;

	bufix += offset;
	length -= offset;

	if (length < paylen)
		log_fatal("Internal inconsistency at %s:%d.", MDL);

	/* Copy out the data in the packet... */
	memcpy(buf, &ibuf[bufix], paylen);
	return paylen;
}

int can_unicast_without_arp (ip)
	struct interface_info *ip;
{
	return 1;
}

int can_receive_unicast_unconfigured (ip)
	struct interface_info *ip;
{
	return 1;
}

int supports_multiple_interfaces (ip)
	struct interface_info *ip;
{
	return 1;
}

void maybe_setup_fallback ()
{
	isc_result_t status;
	struct interface_info *fbi = (struct interface_info *)0;
	if (setup_fallback (&fbi, MDL)) {
		if_register_fallback (fbi);
		status = omapi_register_io_object ((omapi_object_t *)fbi,
						   if_readsocket, 0,
						   fallback_discard, 0, 0);
		if (status != ISC_R_SUCCESS)
			log_fatal ("Can't register I/O handle for \"%s\": %s",
				   fbi -> name, isc_result_totext (status));
		interface_dereference (&fbi, MDL);
	}
}
#endif

#if defined (USE_LPF_RECEIVE) || defined (USE_LPF_HWADDR)
struct sockaddr_ll *
get_ll (struct ifaddrs *ifaddrs, struct ifaddrs **ifa, char *name)
{
	for (*ifa = ifaddrs; *ifa != NULL; *ifa = (*ifa)->ifa_next) {
		if ((*ifa)->ifa_addr == NULL)
			continue;

		if ((*ifa)->ifa_addr->sa_family != AF_PACKET)
			continue;

		if ((*ifa)->ifa_flags & IFF_LOOPBACK)
			continue;

		if (strcmp((*ifa)->ifa_name, name) == 0)
			return (struct sockaddr_ll *)(void *)(*ifa)->ifa_addr;
	}
	*ifa = NULL;
	return NULL;
}

struct sockaddr_ll *
ioctl_get_ll(char *name)
{
	int sock;
	struct ifreq tmp;
	struct sockaddr *sa = NULL;
	struct sockaddr_ll *sll = NULL;

	if (strlen(name) >= sizeof(tmp.ifr_name)) {
		log_fatal("Device name too long: \"%s\"", name);
	}

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		log_fatal("Can't create socket for \"%s\": %m", name);
	}

	memset(&tmp, 0, sizeof(tmp));
	strcpy(tmp.ifr_name, name);
	if (ioctl(sock, SIOCGIFHWADDR, &tmp) < 0) {
		log_fatal("Error getting hardware address for \"%s\": %m",
			  name);
	}
	close(sock);

	sa = &tmp.ifr_hwaddr;
	// needs to be freed outside this function
	sll = dmalloc (sizeof (struct sockaddr_ll), MDL);
	if (!sll)
		log_fatal("Unable to allocate memory for link layer address");
	memcpy(&sll->sll_hatype, &sa->sa_family, sizeof (sll->sll_hatype));
	memcpy(sll->sll_addr, sa->sa_data, sizeof (sll->sll_addr));
	switch (sll->sll_hatype) {
		case ARPHRD_INFINIBAND:
			sll->sll_halen = HARDWARE_ADDR_LEN_IOCTL;
			break;
		default:
			break;
	}
	return sll;
}

isc_result_t
get_hw_addr3(struct interface_info *info, struct ifaddrs *ifaddrs_start)
{
	struct hardware *hw = &info->hw_address;
	char *name = info->name;
	struct ifaddrs *ifaddrs = ifaddrs_start;
	struct ifaddrs *ifa = NULL;
	struct sockaddr_ll *sll = NULL;
	int sll_allocated = 0;
	char *dup = NULL;
	char *colon = NULL;
        isc_result_t result = ISC_R_SUCCESS;
        
	if (ifaddrs == NULL)
		log_fatal("Failed to get interfaces");

	if ((sll = get_ll(ifaddrs, &ifa, name)) == NULL) {
		/*
		 * We were unable to get link-layer address for name.
		 * Fall back to ioctl(SIOCGIFHWADDR).
		 */
		sll = ioctl_get_ll(name);
		if (sll != NULL)
			sll_allocated = 1;
		else
			// shouldn't happen
			log_fatal("Unexpected internal error");
	}

	switch (sll->sll_hatype) {
		case ARPHRD_ETHER:
			hw->hlen = 7;
			hw->hbuf[0] = HTYPE_ETHER;
			memcpy(&hw->hbuf[1], sll->sll_addr, 6);
			break;
		case ARPHRD_IEEE802:
#ifdef ARPHRD_IEEE802_TR
		case ARPHRD_IEEE802_TR:
#endif /* ARPHRD_IEEE802_TR */
			hw->hlen = 7;
			hw->hbuf[0] = HTYPE_IEEE802;
			memcpy(&hw->hbuf[1], sll->sll_addr, 6);
			break;
		case ARPHRD_FDDI:
			hw->hlen = 7;
			hw->hbuf[0] = HTYPE_FDDI;
			memcpy(&hw->hbuf[1], sll->sll_addr, 6);
			break;
		case ARPHRD_INFINIBAND:
			dup = strdup(name);
			/* Aliased infiniband interface is special case where
			 * neither get_ll() nor ioctl_get_ll() get's correct hw
			 * address, so we have to truncate the :0 and run
			 * get_ll() again for the rest.
			*/
			if ((colon = strchr(dup, ':')) != NULL) {
				*colon = '\0';

				if (sll_allocated) {
					dfree(sll, MDL);
					sll_allocated = 0;
				}
				if ((sll = get_ll(ifaddrs, &ifa, dup)) == NULL)
					log_fatal("Error getting hardware address for \"%s\": %m", name);
			}
			free (dup);
			/* For Infiniband, save the broadcast address and store
			 * the port GUID into the hardware address.
			 */
			if (ifa && (ifa->ifa_flags & IFF_BROADCAST)) {
				struct sockaddr_ll *bll;

				bll = (struct sockaddr_ll *)ifa->ifa_broadaddr;
				memcpy(&info->bcast_addr, bll->sll_addr, 20);
			} else {
				memcpy(&info->bcast_addr, default_ib_bcast_addr,
				       20);
			}

			hw->hlen = HARDWARE_ADDR_LEN_IOCTL + 1;
			hw->hbuf[0] = HTYPE_INFINIBAND;
			memcpy(&hw->hbuf[1],
			       &sll->sll_addr[sll->sll_halen - HARDWARE_ADDR_LEN_IOCTL],
			       HARDWARE_ADDR_LEN_IOCTL);
			break;
#if defined(ARPHRD_PPP)
		case ARPHRD_PPP:
			if (local_family != AF_INET6)
				log_fatal("local_family != AF_INET6 for \"%s\"",
					  name);
			hw->hlen = 0;
			hw->hbuf[0] = HTYPE_RESERVED;
			/* 0xdeadbeef should never occur on the wire,
			 * and is a signature that something went wrong.
			 */
			hw->hbuf[1] = 0xde;
			hw->hbuf[2] = 0xad;
			hw->hbuf[3] = 0xbe;
			hw->hbuf[4] = 0xef;
			break;
#endif
        default:
          log_error("Unsupported device type %hu for \"%s\"",
                      sll->sll_hatype, name);
          result = ISC_R_NOTFOUND;

	}

	if (sll_allocated)
		dfree(sll, MDL);
        return result;
}

void try_hw_addr2(struct interface_info *info, struct ifaddrs *ifaddrs_start){
  get_hw_addr3(info, ifaddrs_start);
}

// define ? 
void try_hw_addr(struct interface_info *info){
  get_hw_addr2(info);
};

void
get_hw_addr(struct interface_info *info)
{
  if (get_hw_addr2(info) == ISC_R_NOTFOUND){
    log_fatal("Unsupported device type for \"%s\"",
              info->name);
  }
}

isc_result_t
get_hw_addr2(struct interface_info *info)
{
	struct hardware *hw = &info->hw_address;
	char *name = info->name;
	struct ifaddrs *ifaddrs = NULL;
	struct ifaddrs *ifa = NULL;
	struct sockaddr_ll *sll = NULL;
	int sll_allocated = 0;
	char *dup = NULL;
	char *colon = NULL;
        isc_result_t result = ISC_R_SUCCESS;
        
	if (getifaddrs(&ifaddrs) == -1)
		log_fatal("Failed to get interfaces");

	if ((sll = get_ll(ifaddrs, &ifa, name)) == NULL) {
		/*
		 * We were unable to get link-layer address for name.
		 * Fall back to ioctl(SIOCGIFHWADDR).
		 */
		sll = ioctl_get_ll(name);
		if (sll != NULL)
			sll_allocated = 1;
		else
			// shouldn't happen
			log_fatal("Unexpected internal error");
	}

	switch (sll->sll_hatype) {
		case ARPHRD_ETHER:
			hw->hlen = 7;
			hw->hbuf[0] = HTYPE_ETHER;
			memcpy(&hw->hbuf[1], sll->sll_addr, 6);
			break;
		case ARPHRD_IEEE802:
#ifdef ARPHRD_IEEE802_TR
		case ARPHRD_IEEE802_TR:
#endif /* ARPHRD_IEEE802_TR */
			hw->hlen = 7;
			hw->hbuf[0] = HTYPE_IEEE802;
			memcpy(&hw->hbuf[1], sll->sll_addr, 6);
			break;
		case ARPHRD_FDDI:
			hw->hlen = 7;
			hw->hbuf[0] = HTYPE_FDDI;
			memcpy(&hw->hbuf[1], sll->sll_addr, 6);
			break;
		case ARPHRD_INFINIBAND:
			dup = strdup(name);
			/* Aliased infiniband interface is special case where
			 * neither get_ll() nor ioctl_get_ll() get's correct hw
			 * address, so we have to truncate the :0 and run
			 * get_ll() again for the rest.
			*/
			if ((colon = strchr(dup, ':')) != NULL) {
				*colon = '\0';
				if ((sll = get_ll(ifaddrs, &ifa, dup)) == NULL)
					log_fatal("Error getting hardware address for \"%s\": %m", name);
			}
			free (dup);
			/* For Infiniband, save the broadcast address and store
			 * the port GUID into the hardware address.
			 */
			if (ifa && (ifa->ifa_flags & IFF_BROADCAST)) {
				struct sockaddr_ll *bll;

				bll = (struct sockaddr_ll *)ifa->ifa_broadaddr;
				memcpy(&info->bcast_addr, bll->sll_addr, 20);
			} else {
				memcpy(&info->bcast_addr, default_ib_bcast_addr,
				       20);
			}

			hw->hlen = HARDWARE_ADDR_LEN_IOCTL + 1;
			hw->hbuf[0] = HTYPE_INFINIBAND;
			memcpy(&hw->hbuf[1],
			       &sll->sll_addr[sll->sll_halen - HARDWARE_ADDR_LEN_IOCTL],
			       HARDWARE_ADDR_LEN_IOCTL);
			break;
#if defined(ARPHRD_PPP)
		case ARPHRD_PPP:
			if (local_family != AF_INET6)
				log_fatal("local_family != AF_INET6 for \"%s\"",
					  name);
			hw->hlen = 0;
			hw->hbuf[0] = HTYPE_RESERVED;
			/* 0xdeadbeef should never occur on the wire,
			 * and is a signature that something went wrong.
			 */
			hw->hbuf[1] = 0xde;
			hw->hbuf[2] = 0xad;
			hw->hbuf[3] = 0xbe;
			hw->hbuf[4] = 0xef;
			break;
#endif
        default:
          log_error("Unsupported device type %hu for \"%s\"",
                      sll->sll_hatype, name);
          result = ISC_R_NOTFOUND;

	}

	if (sll_allocated)
		dfree(sll, MDL);
	freeifaddrs(ifaddrs);
        return result;
}
#endif
