/* packet.c

   Packet assembly code, originally contributed by Archie Cobbs. */

/*
 * Copyright (c) 2023-2023 Hisilicon Limited.
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
 *
 * This code was originally contributed by Archie Cobbs, and is still
 * very similar to that contribution, although the packet checksum code
 * has been hacked significantly with the help of quite a few ISC DHCP
 * users, without whose gracious and thorough help the checksum code would
 * still be disabled.
 */

#include "dhcpd.h"

#if defined (PACKET_ASSEMBLY) || defined (PACKET_DECODING)
#include "includes/netinet/ip.h"
#include "includes/netinet/udp.h"
#include "includes/netinet/if_ether.h"
#endif /* PACKET_ASSEMBLY || PACKET_DECODING */

#define IPV6_BASEHD_LEN 40
const u_int8_t ub_dguid_v4[GUID_LEN] = {0xFF, 0xFF, 0xFF, 0xFF,
										0xFF, 0xFF, 0xFF, 0xFF,
										0xFF, 0xFF, 0xFF, 0xFF,
										0xFF, 0xFF, 0x01, 0x00};

const u_int8_t ub_dguid_v6[GUID_LEN] = {0xFF, 0xFF, 0xFF, 0xFF,
										0xFF, 0xFF, 0xFF, 0xFF,
										0xFF, 0xFF, 0xFF, 0xFF,
										0xFF, 0xFF, 0x01, 0x01};

/* Compute the easy part of the checksum on a range of bytes. */

u_int32_t checksum (buf, nbytes, sum)
	unsigned char *buf;
	unsigned nbytes;
	u_int32_t sum;
{
	unsigned i;

#ifdef DEBUG_CHECKSUM
	log_debug ("checksum (%x %d %x)", (unsigned)buf, nbytes, sum);
#endif

	/* Checksum all the pairs of bytes first... */
	for (i = 0; i < (nbytes & ~1U); i += 2) {
#ifdef DEBUG_CHECKSUM_VERBOSE
		log_debug ("sum = %x", sum);
#endif
		sum += (u_int16_t) ntohs(*((u_int16_t *)(buf + i)));
		/* Add carry. */
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}

	/* If there's a single byte left over, checksum it, too.   Network
	   byte order is big-endian, so the remaining byte is the high byte. */
	if (i < nbytes) {
#ifdef DEBUG_CHECKSUM_VERBOSE
		log_debug ("sum = %x", sum);
#endif
		sum += buf [i] << 8;
		/* Add carry. */
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}

	return sum;
}

/* Finish computing the checksum, and then put it into network byte order. */

u_int32_t wrapsum (sum)
	u_int32_t sum;
{
#ifdef DEBUG_CHECKSUM
	log_debug ("wrapsum (%x)", sum);
#endif

	sum = ~sum & 0xFFFF;
#ifdef DEBUG_CHECKSUM_VERBOSE
	log_debug ("sum = %x", sum);
#endif

#ifdef DEBUG_CHECKSUM
	log_debug ("wrapsum returns %x", htons (sum));
#endif
	return htons(sum);
}

#ifdef PACKET_ASSEMBLY
void assemble_hw_header (interface, buf, bufix, to)
	struct interface_info *interface;
	unsigned char *buf;
	unsigned *bufix;
	struct hardware *to;
{
	switch (interface->hw_address.hbuf[0]) {
	case HTYPE_UB:
		assemble_ub_header(interface, buf, bufix, to);
		break;
	default:
		log_error("Attempt to assemble hw header for non-ub device");
		break;
	}
}

/* UDP header and IP header assembled together for convenience. */

void assemble_udp_ip_header (interface, buf, bufix,
			     from, to, port, data, len)
	struct interface_info *interface;
	unsigned char *buf;
	unsigned *bufix;
	u_int32_t from;
	u_int32_t to;
	u_int32_t port;
	unsigned char *data;
	unsigned len;
{
	struct ip ip;
	struct udphdr udp;

	memset (&ip, 0, sizeof ip);

	/* Fill out the IP header */
	IP_V_SET (&ip, 4);
	IP_HL_SET (&ip, 20);
	ip.ip_tos = IPTOS_LOWDELAY;
	ip.ip_len = htons(sizeof(ip) + sizeof(udp) + len);
	ip.ip_id = 0;
	ip.ip_off = 0;
	ip.ip_ttl = 128;
	ip.ip_p = IPPROTO_UDP;
	ip.ip_sum = 0;
	ip.ip_src.s_addr = from;
	ip.ip_dst.s_addr = to;

	/* Checksum the IP header... */
	ip.ip_sum = wrapsum (checksum ((unsigned char *)&ip, sizeof ip, 0));

	/* Copy the ip header into the buffer... */
	memcpy (&buf [*bufix], &ip, sizeof ip);
	*bufix += sizeof ip;

	/* Fill out the UDP header */
	udp.uh_sport = local_port;		/* XXX */
	udp.uh_dport = port;			/* XXX */
#if defined(RELAY_PORT)
	/* Change to relay port defined if sending to server */
	if (relay_port && (port == htons(67))) {
		udp.uh_sport = relay_port;
	}
#endif
	udp.uh_ulen = htons(sizeof(udp) + len);
	memset (&udp.uh_sum, 0, sizeof udp.uh_sum);

	/* Compute UDP checksums, including the ``pseudo-header'', the UDP
	   header and the data. */

	udp.uh_sum =
		wrapsum (checksum ((unsigned char *)&udp, sizeof udp,
				   checksum (data, len,
					     checksum ((unsigned char *)
						       &ip.ip_src,
						       2 * sizeof ip.ip_src,
						       IPPROTO_UDP +
						       (u_int32_t)
						       ntohs (udp.uh_ulen)))));

	/* Copy the udp header into the buffer... */
	memcpy (&buf [*bufix], &udp, sizeof udp);
	*bufix += sizeof udp;
}
#endif /* PACKET_ASSEMBLY */

void assemble_udp_ipv6_header (interface, buf, bufix,
				from, to, port, data, len)
	struct interface_info *interface;
	unsigned char *buf;
	unsigned *bufix;
	u_int8_t *from;
	u_int8_t *to;
	u_int32_t port;
	unsigned char *data;
	unsigned len;
{
	struct ipv6 ipv6;
	struct udphdr udp;

	memset(&ipv6, 0, sizeof(ipv6));
	memset(&udp, 0, sizeof(udp));

	/* Fill out the IP header */
	IPV6_V_SET(&ipv6, IPV6);
	IPV6_T_SET(&ipv6, 0);
	IPV6_FLO(&ipv6, 0x9dc2a);
	ipv6.ipv6_fvhl = htonl(ipv6.ipv6_fvhl);
	ipv6.ipv6_len = htons(len + sizeof(struct udphdr));
	ipv6.ipv6_nhea = 0x11;
	ipv6.ipv6_hlim = 0x01;
	memcpy(ipv6.ipv6_src.s6_addr, from, sizeof(ipv6.ipv6_src.s6_addr));
	memcpy(ipv6.ipv6_dst.s6_addr, to, sizeof(ipv6.ipv6_dst.s6_addr));
	/* Copy the ip header into the buffer */
	memcpy(&buf[*bufix], &ipv6, sizeof(ipv6));
	*bufix += sizeof(ipv6);

	/* Fill out the UDP header */
	udp.uh_sport = local_port;
	udp.uh_dport = port;
#if defined(RELAY_PORT)
	/* Change to relay port defined if sending to server */
	if (relay_port && (port == htons(546)))
		udp.uh_sport = relay_port;
#endif
	udp.uh_ulen = htons(sizeof(udp) + len);
	/* Copy the udp header into the buffer*/
	memcpy(&buf [*bufix], &udp, sizeof(udp));
	*bufix += sizeof(udp);
}

#ifdef PACKET_DECODING
/* Decode a hardware header... */
/* Support for ethernet, TR and FDDI
 * Doesn't support infiniband yet as the supported oses shouldn't get here
 */

ssize_t decode_hw_header (interface, buf, bufix, from)
     struct interface_info *interface;
     unsigned char *buf;
     unsigned bufix;
     struct hardware *from;
{
	switch (interface->hw_address.hbuf[0]) {
	case HTYPE_UB:
		return (decode_ub_header(interface, buf, bufix, from));
	default:
		log_error("Attempt to decode hw header for non-ub device");
		return (0);
	}
}

ssize_t
decode_udp_ipv6_header(struct interface_info *interface,
			unsigned char *buf, unsigned bufix, unsigned buflen,
			unsigned *rbuflen, struct sockaddr_in6 *from, struct in6_addr *to)
{
	struct ipv6 ipv6;
	struct udphdr udp;
	unsigned char *upp;
	u_int32_t ulen;
	unsigned len;

	if (sizeof(ipv6) > buflen)
		return -1;

	upp = buf + bufix;
	memcpy(&ipv6, upp, sizeof(ipv6));
	memcpy(&from->sin6_addr, &ipv6.ipv6_src, sizeof(struct in6_addr));
	memcpy(to, &ipv6.ipv6_dst, sizeof(struct in6_addr));
	upp += IPV6_BASEHD_LEN;

	/* Copy the UDP header into a stack aligned structure for inspection. */
	memcpy(&udp, upp, sizeof(udp));
	from->sin6_port = udp.uh_sport;

	ulen = ntohs(udp.uh_ulen);
	if (ulen < sizeof(udp))
		return -1;

	len = ulen - sizeof(udp);

	/* Save the length of the UDP payload. */
	if (rbuflen != NULL)
		*rbuflen = len;

	/* Return the index to the UDP payload. */
	return (IPV6_BASEHD_LEN + sizeof(udp));
}

/*!
 *
 * \brief UDP header and IP header decoded together for convenience.
 *
 * Attempt to decode the UDP and IP headers and, if necessary, checksum
 * the packet.
 *
 * \param inteface - the interface on which the packet was recevied
 * \param buf - a pointer to the buffer for the received packet
 * \param bufix - where to start processing the buffer, previous
 *                routines may have processed parts of the buffer already
 * \param from - space to return the address of the packet sender
 * \param buflen - remaining length of the buffer, this will have been
 *                 decremented by bufix by the caller
 * \param rbuflen - space to return the length of the payload from the udp
 *                  header
 * \param csum_ready - indication if the checksum is valid for use
 *                     non-zero indicates the checksum should be validated
 *
 * \return - the index to the first byte of the udp payload (that is the
 *           start of the DHCP packet
 */

ssize_t
decode_udp_ip_header(struct interface_info *interface,
		     unsigned char *buf, unsigned bufix,
		     struct sockaddr_in *from, unsigned buflen,
		     unsigned *rbuflen, int csum_ready)
{
  unsigned char *data;
  struct ip ip;
  struct udphdr udp;
  unsigned char *upp;
  u_int32_t ip_len, ulen, pkt_len;
  static unsigned int ip_packets_seen = 0;
  static unsigned int ip_packets_bad_checksum = 0;
  static unsigned int udp_packets_seen = 0;
  static unsigned int udp_packets_bad_checksum = 0;
  static unsigned int udp_packets_length_checked = 0;
  static unsigned int udp_packets_length_overflow = 0;
  unsigned len;

  /* Assure there is at least an IP header there. */
  if (sizeof(ip) > buflen)
	  return -1;

  /* Copy the IP header into a stack aligned structure for inspection.
   * There may be bits in the IP header that we're not decoding, so we
   * copy out the bits we grok and skip ahead by ip.ip_hl * 4.
   */
  upp = buf + bufix;
  memcpy(&ip, upp, sizeof(ip));
  ip_len = (*upp & 0x0f) << 2;
  upp += ip_len;

  /* Check packet lengths are within the buffer:
   * first the ip header (ip_len)
   * then the packet length from the ip header (pkt_len)
   * then the udp header (ip_len + sizeof(udp)
   * We are liberal in what we accept, the udp payload should fit within
   * pkt_len, but we only check against the full buffer size.
   */
  pkt_len = ntohs(ip.ip_len);
  if ((ip_len > buflen) ||
      (pkt_len > buflen) ||
      ((ip_len + sizeof(udp)) > buflen))
	  return -1;

  /* Copy the UDP header into a stack aligned structure for inspection. */
  memcpy(&udp, upp, sizeof(udp));

#ifdef USERLAND_FILTER
  /* Is it a UDP packet? */
  if (ip.ip_p != IPPROTO_UDP)
	  return -1;

  /* Is it to the port we're serving? */
#if defined(RELAY_PORT)
  if ((udp.uh_dport != local_port) &&
      ((relay_port == 0) || (udp.uh_dport != relay_port)))
#else
  if (udp.uh_dport != local_port)
#endif
	  return -1;
#endif /* USERLAND_FILTER */

  ulen = ntohs(udp.uh_ulen);
  if (ulen < sizeof(udp))
	return -1;

  udp_packets_length_checked++;
  /* verify that the payload length from the udp packet fits in the buffer */
  if ((ip_len + ulen) > buflen) {
	udp_packets_length_overflow++;
	if (((udp_packets_length_checked > 4) &&
	     (udp_packets_length_overflow != 0)) &&
	    ((udp_packets_length_checked / udp_packets_length_overflow) < 2)) {
		log_info("%u udp packets in %u too long - dropped",
			 udp_packets_length_overflow,
			 udp_packets_length_checked);
		udp_packets_length_overflow = 0;
		udp_packets_length_checked = 0;
	}
	return -1;
  }

  /* If at least 5 with less than 50% bad, start over */
  if (udp_packets_length_checked > 4) {
	udp_packets_length_overflow = 0;
	udp_packets_length_checked = 0;
  }

  /* Check the IP header checksum - it should be zero. */
  ip_packets_seen++;
  if (wrapsum (checksum (buf + bufix, ip_len, 0))) {
	  ++ip_packets_bad_checksum;
	  if (((ip_packets_seen > 4) && (ip_packets_bad_checksum != 0)) &&
	      ((ip_packets_seen / ip_packets_bad_checksum) < 2)) {
		  log_info ("%u bad IP checksums seen in %u packets",
			    ip_packets_bad_checksum, ip_packets_seen);
		  ip_packets_seen = ip_packets_bad_checksum = 0;
	  }
	  return -1;
  }

  /* If at least 5 with less than 50% bad, start over */
  if (ip_packets_seen > 4) {
	ip_packets_bad_checksum = 0;
	ip_packets_seen = 0;
  }

  /* Copy out the IP source address... */
  memcpy(&from->sin_addr, &ip.ip_src, 4);

  data = upp + sizeof(udp);
  len = ulen - sizeof(udp);

  /* UDP check sum may be optional (udp.uh_sum == 0) or not ready if checksum
   * offloading is in use */
  udp_packets_seen++;
  if (udp.uh_sum && csum_ready) {
	/* Check the UDP header checksum - since the received packet header
	 * contains the UDP checksum calculated by the transmitter, calculating
	 * it now should come out to zero. */
	if (wrapsum(checksum((unsigned char *)&udp, sizeof(udp),
			       checksum(data, len,
				        checksum((unsigned char *)&ip.ip_src,
					         8, IPPROTO_UDP + ulen))))) {
		udp_packets_bad_checksum++;
		if (((udp_packets_seen > 4) && (udp_packets_bad_checksum != 0))
		    && ((udp_packets_seen / udp_packets_bad_checksum) < 2)) {
			log_debug ("%u bad udp checksums in %u packets",
			           udp_packets_bad_checksum, udp_packets_seen);
			udp_packets_seen = udp_packets_bad_checksum = 0;
		}

		return -1;
	}
  }

  /* If at least 5 with less than 50% bad, start over */
  if (udp_packets_seen > 4) {
	udp_packets_bad_checksum = 0;
	udp_packets_seen = 0;
  }

  /* Copy out the port... */
  memcpy (&from -> sin_port, &udp.uh_sport, sizeof udp.uh_sport);

  /* Save the length of the UDP payload. */
  if (rbuflen != NULL)
	*rbuflen = len;

  /* Return the index to the UDP payload. */
  return ip_len + sizeof udp;
}
#endif /* PACKET_DECODING */

void assemble_ub_header (struct interface_info *interface,
						 unsigned char *buf,
						 unsigned *bufix,
						 struct hardware *to)
{
	struct ub_link_header ub_header;
	unsigned int proto = htons(DHCPV4_PROTO);
	int ub_header_len = sizeof(struct ub_link_header);

	memset(&ub_header, 0x0, sizeof(struct ub_link_header));
	ub_header.ub_cfg = DHCP_CFG;
	ub_header.ub_protocol = proto;
	memcpy(ub_header.ub_dguid, ub_dguid_v4, GUID_LEN);
	if (interface->hw_address.hlen - 1 == sizeof(ub_header.ub_sguid)) {
		memcpy(ub_header.ub_sguid, &interface->hw_address.hbuf[1],
			interface->hw_address.hlen - 1);
	}
	memcpy(&buf [*bufix], &ub_header, ub_header_len);
	*bufix += ub_header_len;
}

void assemble_ub_header6 (struct interface_info *interface,
						  unsigned char *buf,
						  unsigned *bufix)
{
	struct ub_link_header ub_header;
	unsigned int proto = htons(DHCPV6_PROTO);
	int ub_header_len = sizeof(struct ub_link_header);

	memset(&ub_header, 0x0, sizeof(struct ub_link_header));
	ub_header.ub_cfg = DHCP_CFG;
	ub_header.ub_protocol = proto;
	memcpy(ub_header.ub_dguid, ub_dguid_v6, GUID_LEN);
	if (interface->hw_address.hlen - 1 == sizeof(ub_header.ub_sguid)) {
		memcpy(ub_header.ub_sguid, &interface->hw_address.hbuf[1],
			interface->hw_address.hlen - 1);
	}
	memcpy(&buf[*bufix], &ub_header, ub_header_len);
	*bufix += ub_header_len ;
}

ssize_t decode_ub_header (struct interface_info *interface,
						  unsigned char *buf,
						  unsigned bufix,
						  struct hardware *from)
{
	struct ub_link_header *ub_header = NULL;
	int ub_header_len  = sizeof(struct ub_link_header);

	ub_header = (struct ub_link_header *)(buf + bufix);
	memcpy(&from -> hbuf[1], ub_header->ub_sguid, sizeof (ub_header->ub_sguid));
	from -> hbuf [0] = HTYPE_UB;
	from -> hlen = sizeof (ub_header->ub_sguid) + 1;

	return ub_header_len;
}

ssize_t decode_ub_header6 (interface, buf, bufix)
						   struct interface_info *interface;
						   unsigned char *buf;
						   unsigned bufix;
{
	struct ub_link_header *ub_header = NULL;
	int ub_header_len  = sizeof(struct ub_link_header);

	ub_header = (struct ub_link_header *)(buf + bufix);
	if (ntohs(ub_header->ub_protocol) != DHCPV6_PROTO)
		return -1;
	return ub_header_len;
}
