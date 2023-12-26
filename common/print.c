/* print.c

   Turn data structures into printable text. */

/*
 * Copyright (c) 2023-2023 Hisilicon Limited.
 * Copyright (C) 2004-2022 Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1995-2003 by Internet Software Consortium
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
 */

#include "dhcpd.h"
#include "includes/netinet/ip.h"
#include "includes/netinet/udp.h"
#include "includes/netinet/if_ether.h"

int db_time_format = DEFAULT_TIME_FORMAT;

char *quotify_string (const char *s, const char *file, int line)
{
	unsigned len = 0;
	const char *sp;
	char *buf, *nsp;

	for (sp = s; sp && *sp; sp++) {
		if (*sp == ' ')
			len++;
		else if (!isascii ((int)*sp) || !isprint ((int)*sp))
			len += 4;
		else if (*sp == '"' || *sp == '\\')
			len += 2;
		else
			len++;
	}

	buf = dmalloc (len + 1, file, line);
	if (buf) {
		nsp = buf;
		for (sp = s; sp && *sp; sp++) {
			if (*sp == ' ')
				*nsp++ = ' ';
			else if (!isascii ((int)*sp) || !isprint ((int)*sp)) {
				sprintf (nsp, "\\%03o",
					 *(const unsigned char *)sp);
				nsp += 4;
			} else if (*sp == '"' || *sp == '\\') {
				*nsp++ = '\\';
				*nsp++ = *sp;
			} else
				*nsp++ = *sp;
		}
		*nsp++ = 0;
	}
	return buf;
}

char *quotify_buf (const unsigned char *s, unsigned len, char enclose_char,
		   const char *file, int line)
{
	unsigned nulen = 0;
	char *buf, *nsp;
	int i;

	for (i = 0; i < len; i++) {
		if (s [i] == ' ')
			nulen++;
		else if (!isascii (s [i]) || !isprint (s [i]))
			nulen += 4;
		else if (s [i] == '"' || s [i] == '\\')
			nulen += 2;
		else
			nulen++;
	}

	if (enclose_char) {
		nulen +=2 ;
	}

	buf = dmalloc (nulen + 1, MDL);
	if (buf) {
		nsp = buf;
		if (enclose_char) {
			*nsp++ = enclose_char;
		}

		for (i = 0; i < len; i++) {
			if (s [i] == ' ')
				*nsp++ = ' ';
			else if (!isascii (s [i]) || !isprint (s [i])) {
				sprintf (nsp, "\\%03o", s [i]);
				nsp += 4;
			} else if (s [i] == '"' || s [i] == '\\') {
				*nsp++ = '\\';
				*nsp++ = s [i];
			} else
				*nsp++ = s [i];
		}

		if (enclose_char) {
			*nsp++ = enclose_char;
		}
		*nsp++ = 0;
	}
	return buf;
}

char *print_base64 (const unsigned char *buf, unsigned len,
		    const char *file, int line)
{
	char *s, *b;
	unsigned bl;
	int i;
	unsigned val, extra;
	static char to64 [] =
	   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	bl = ((len * 4 + 2) / 3) + 1;
	b = dmalloc (bl + 1, file, line);
	if (!b)
		return (char *)0;

	i = 0;
	s = b;
	while (i != len) {
		val = buf [i++];
		extra = val & 3;
		val = val >> 2;
		*s++ = to64 [val];
		if (i == len) {
			*s++ = to64 [extra << 4];
			*s++ = '=';
			break;
		}
		val = (extra << 8) + buf [i++];
		extra = val & 15;
		val = val >> 4;
		*s++ = to64 [val];
		if (i == len) {
			*s++ = to64 [extra << 2];
			*s++ = '=';
			break;
		}
		val = (extra << 8) + buf [i++];
		extra = val & 0x3f;
		val = val >> 6;
		*s++ = to64 [val];
		*s++ = to64 [extra];
	}
	if (!len)
		*s++ = '=';
	*s++ = 0;
	if (s > b + bl + 1)
		abort ();
	return b;
}

char *print_hw_addr (htype, hlen, data)
	const int htype;
	const int hlen;
	const unsigned char *data;
{
	static char habuf [49];
	char *s;
	int i;

	if (hlen <= 0)
		habuf [0] = 0;
	else {
		s = habuf;
		for (i = 0; i < hlen; i++) {
			sprintf (s, "%02x", data [i]);
			s += strlen (s);
			*s++ = ':';
		}
		*--s = 0;
	}
	return habuf;
}

void print_lease (lease)
	struct lease *lease;
{
	struct tm *t;
	char tbuf [32];

	log_debug ("  Lease %s",
	       piaddr (lease -> ip_addr));

	t = gmtime (&lease -> starts);
	strftime (tbuf, sizeof tbuf, "%Y/%m/%d %H:%M:%S", t);
	log_debug ("  start %s", tbuf);

	t = gmtime (&lease -> ends);
	strftime (tbuf, sizeof tbuf, "%Y/%m/%d %H:%M:%S", t);
	log_debug ("  end %s", tbuf);

	if (lease -> hardware_addr.hlen)
		log_debug ("    hardware addr = %s",
			   print_hw_addr (lease -> hardware_addr.hbuf [0],
					  lease -> hardware_addr.hlen - 1,
					  &lease -> hardware_addr.hbuf [1]));
	log_debug ("  host %s  ",
	       lease -> host ? lease -> host -> name : "<none>");
}

#if defined (DEBUG_PACKET)
void dump_packet_option (struct option_cache *oc,
			 struct packet *packet,
			 struct lease *lease,
			 struct client_state *client,
			 struct option_state *in_options,
			 struct option_state *cfg_options,
			 struct binding_scope **scope,
			 struct universe *u, void *foo)
{
	const char *name, *dot;
	struct data_string ds;
	memset (&ds, 0, sizeof ds);

	if (u != &dhcp_universe) {
		name = u -> name;
		dot = ".";
	} else {
		name = "";
		dot = "";
	}
	if (evaluate_option_cache (&ds, packet, lease, client,
				   in_options, cfg_options, scope, oc, MDL)) {
		log_debug ("  option %s%s%s %s;\n",
			   name, dot, oc -> option -> name,
			   pretty_print_option (oc -> option,
						ds.data, ds.len, 1, 1));
		data_string_forget (&ds, MDL);
	}
}

void dump_packet (tp)
	struct packet *tp;
{
	struct dhcp_packet *tdp = tp -> raw;

	log_debug ("\nStart to parse packets:");
	log_debug ("op \t= %u", tdp -> op);
	log_debug ("htype \t= %u", tdp -> htype);
	log_debug ("hlen \t= %u", tdp -> hlen);
	log_debug ("hops \t= %u", tdp -> hops);
	log_debug ("xid \t= %u", ntohl (tdp -> xid));
	log_debug ("secs \t= %u", ntohs (tdp -> secs));
	log_debug ("flags \t= %u", ntohs (tdp -> flags));
	log_debug ("ciaddr \t= %s", inet_ntoa (tdp -> ciaddr));
	log_debug ("yiaddr \t= %s", inet_ntoa (tdp -> yiaddr));
	log_debug ("siaddr \t= %s", inet_ntoa (tdp -> siaddr));
	log_debug ("giaddr \t= %s", inet_ntoa (tdp -> giaddr));
	dump_addr (tdp);
	log_debug ("filename \t= %s", tdp -> file);
	log_debug ("server_name \t= %s", tdp -> sname);

	if (tp -> options_valid) {
		int i;

		for (i = 0; i < tp -> options -> universe_count; i++) {
			if (tp -> options -> universes [i]) {
				option_space_foreach (tp, (struct lease *)0,
						      (struct client_state *)0,
						      (struct option_state *)0,
						      tp -> options,
						      &global_scope,
						      universes [i], 0,
						      dump_packet_option);
			}
		}
	}
	log_debug ("%s", "");
}

void dump_addr (tdp)
	struct dhcp_packet *tdp;
{
	if (tdp -> htype == HTYPE_UB) {
		log_debug ("chaddr \t= %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:"
							   "%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x",
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR0],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR1],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR2],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR3],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR4],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR5],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR6],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR7],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR8],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR9],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR10],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR11],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR12],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR13],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR14],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR15]);
	} else {
		log_debug ("chaddr \t= %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x",
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR0],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR1],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR2],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR3],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR4],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR5]);
	}
}

void dump_packet_send (tp_send)
	struct dhcp_packet *tp_send;
{
	log_debug ("\nStart to parse packets:");
	log_debug ("op \t= %u", tp_send -> op);
	log_debug ("htype \t= %u", tp_send -> htype);
	log_debug ("hlen \t= %u", tp_send->hlen);
	log_debug ("hops \t= %u", tp_send -> hops);
	log_debug ("xid \t= %u", ntohl(tp_send -> xid));
	log_debug ("secs \t= %u", ntohs(tp_send -> secs));
	log_debug ("flags \t= %u", ntohs(tp_send -> flags));
	log_debug ("ciaddr \t= %s", inet_ntoa (tp_send -> ciaddr));
	log_debug ("yiaddr \t= %s", inet_ntoa (tp_send -> yiaddr));
	log_debug ("siaddr \t= %s", inet_ntoa (tp_send -> siaddr));
	log_debug ("giaddr \t= %s", inet_ntoa (tp_send -> giaddr));
	dump_addr (tp_send);
	log_debug ("filename \t= %s", tp_send -> file);
	log_debug ("server_name \t= %s", tp_send -> sname);
	log_debug ("%s", "");
}
#endif

void log_show(const char *cmd, ...)
{
	va_list args;

	va_start(args, cmd);
	vprintf(cmd, args);
	va_end(args);
	printf("\n");
}

void show_ub_hdr(struct ub_link_header *ubh)
{
	log_show("ub_protocol \t= 0x%x", ntohs(ubh->ub_protocol));
	log_show("ub_dguid \t= "
			 "%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:"
			 "%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x",
	    ubh->ub_dguid[UB_GUID0],
	    ubh->ub_dguid[UB_GUID1],
	    ubh->ub_dguid[UB_GUID2],
	    ubh->ub_dguid[UB_GUID3],
	    ubh->ub_dguid[UB_GUID4],
	    ubh->ub_dguid[UB_GUID5],
	    ubh->ub_dguid[UB_GUID6],
	    ubh->ub_dguid[UB_GUID7],
	    ubh->ub_dguid[UB_GUID8],
	    ubh->ub_dguid[UB_GUID9],
	    ubh->ub_dguid[UB_GUID10],
	    ubh->ub_dguid[UB_GUID11],
	    ubh->ub_dguid[UB_GUID12],
	    ubh->ub_dguid[UB_GUID13],
	    ubh->ub_dguid[UB_GUID14],
	    ubh->ub_dguid[UB_GUID15]);
	log_show("ub_sguid \t= "
			 "%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:"
			 "%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x",
	    ubh->ub_sguid[UB_GUID0],
	    ubh->ub_sguid[UB_GUID1],
	    ubh->ub_sguid[UB_GUID2],
	    ubh->ub_sguid[UB_GUID3],
	    ubh->ub_sguid[UB_GUID4],
	    ubh->ub_sguid[UB_GUID5],
	    ubh->ub_sguid[UB_GUID6],
	    ubh->ub_sguid[UB_GUID7],
	    ubh->ub_sguid[UB_GUID8],
	    ubh->ub_sguid[UB_GUID9],
	    ubh->ub_sguid[UB_GUID10],
	    ubh->ub_sguid[UB_GUID11],
	    ubh->ub_sguid[UB_GUID12],
	    ubh->ub_sguid[UB_GUID13],
	    ubh->ub_sguid[UB_GUID14],
	    ubh->ub_sguid[UB_GUID15]);
}

void show_ipv4_hdr(struct ip *iph)
{
	log_show("ip_fvhl \t= 0x%x", iph->ip_fvhl);
	log_show("ip_tos \t= 0x%x", iph->ip_tos);
	log_show("ip_len \t= 0x%x", ntohs(iph->ip_len));
	log_show("ip_id \t= 0x%x", ntohs(iph->ip_id));
	log_show("ip_off \t= 0x%x", ntohs(iph->ip_off));
	log_show("ip_ttl \t= 0x%x", iph->ip_ttl);
	log_show("ip_p \t= 0x%x", iph->ip_p);
	log_show("ip_sum \t= 0x%x", ntohs(iph->ip_sum));
	log_show("ip_src \t= %s", inet_ntoa(iph->ip_src));
	log_show("ip_dst \t= %s", inet_ntoa(iph->ip_dst));
}

void show_ipv6_hdr(struct ipv6 *ipv6h)
{
	char addr_buf[sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")];

	log_show("ipv6_fvhl \t= 0x%x", ntohl(ipv6h->ipv6_fvhl));
	log_show("ipv6_len \t= %u", ntohs(ipv6h->ipv6_len));
	log_show("ipv6_nhea \t= %u", ipv6h->ipv6_nhea);
	log_show("ipv6_hlim \t= %u", ipv6h->ipv6_hlim);

	inet_ntop(AF_INET6, &ipv6h->ipv6_src, addr_buf, sizeof(addr_buf));
	log_show("ipv6_src \t= %s", addr_buf);
	inet_ntop(AF_INET6, &ipv6h->ipv6_dst, addr_buf, sizeof(addr_buf));
	log_show("ipv6_dst \t= %s", addr_buf);
}

void show_udp_hdr(struct udphdr *udph)
{
	log_show("uh_sport \t= %u", ntohs(udph->uh_sport));
	log_show("uh_dport \t= %u", ntohs(udph->uh_dport));
	log_show("uh_ulen \t= %u", ntohs(udph->uh_ulen));
	log_show("uh_sum \t= %u", ntohs(udph->uh_sum));
}

void show_raw_hdr(struct ub_link_header *ubh, struct ip *iph,
				  struct udphdr *udph)
{
	show_ub_hdr(ubh);
	show_ipv4_hdr(iph);
	show_udp_hdr(udph);
}

void show_raw_hdr6(struct ub_link_header *ubh, struct ipv6 *ipv6h,
				   struct udphdr *udph)
{
	show_ub_hdr(ubh);
	show_ipv6_hdr(ipv6h);
	show_udp_hdr(udph);
}

void show_raw_ub_pdu(struct dhcp_packet *tdp)
{
	log_show("op \t= %u", tdp -> op);
	log_show("htype \t= %u", tdp -> htype);
	log_show("hlen \t= %u", tdp -> hlen);
	log_show("hops \t= %u", tdp -> hops);
	log_show("xid \t= %u", ntohl(tdp -> xid));
	log_show("secs \t= %u", ntohs(tdp -> secs));
	log_show("flags \t= %u", ntohs(tdp -> flags));
	log_show("ciaddr \t= %s", inet_ntoa(tdp -> ciaddr));
	log_show("yiaddr \t= %s", inet_ntoa(tdp -> yiaddr));
	log_show("siaddr \t= %s", inet_ntoa(tdp -> siaddr));
	log_show("giaddr \t= %s", inet_ntoa(tdp -> giaddr));
	log_show("chaddr \t= %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:"
						"%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x",
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR0],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR1],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR2],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR3],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR4],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR5],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR6],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR7],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR8],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR9],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR10],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR11],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR12],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR13],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR14],
			((unsigned char *)(tdp -> chaddr)) [UB_ADDR15]);
	log_show("filename \t= %s", tdp -> file);
	log_show("server_name \t= %s", tdp -> sname);
	log_show("%s", "");
}

#define DATA_LEN_BYTES  2
#define D6O_CLIENTID    1
#define CHAR_BITS       8
unsigned int get_option1_msg(unsigned char *option_start,
							 unsigned int option_len,
							 unsigned char *option1_data_start)
{
	unsigned short option1_data_len;
	unsigned short option_data_len;
	unsigned char char_bits;
	int buf_index = 0;

	char_bits = sizeof(char) * CHAR_BITS;

	while (buf_index < option_len) {
		unsigned short option_code = 0;

		option_code =
			option_start[buf_index] << char_bits | option_start[buf_index + 1];
		if (option_code == D6O_CLIENTID) {
			buf_index += DATA_LEN_BYTES;
			memcpy(&option1_data_len, &option_start[buf_index], sizeof(option1_data_len));
			option1_data_len = ntohs(option1_data_len);
			buf_index += DATA_LEN_BYTES;
			memcpy(option1_data_start, option_start + buf_index, option1_data_len);
			return option1_data_len;
		} else {
			/* go to next option start */
			buf_index++;
			memcpy(&option_data_len, &option_start[buf_index], sizeof(option_data_len));
			option_data_len = ntohs(option_data_len);
			buf_index += DATA_LEN_BYTES;
			buf_index += option_data_len;
		}
	}
	return 0;
}

void show_client_id(unsigned char *client_id_start)
{
	log_show("client_id \t= %2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:"
						"%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x",
			((unsigned char *)(client_id_start)) [UB_ADDR0],
			((unsigned char *)(client_id_start)) [UB_ADDR1],
			((unsigned char *)(client_id_start)) [UB_ADDR2],
			((unsigned char *)(client_id_start)) [UB_ADDR3],
			((unsigned char *)(client_id_start)) [UB_ADDR4],
			((unsigned char *)(client_id_start)) [UB_ADDR5],
			((unsigned char *)(client_id_start)) [UB_ADDR6],
			((unsigned char *)(client_id_start)) [UB_ADDR7],
			((unsigned char *)(client_id_start)) [UB_ADDR8],
			((unsigned char *)(client_id_start)) [UB_ADDR9],
			((unsigned char *)(client_id_start)) [UB_ADDR10],
			((unsigned char *)(client_id_start)) [UB_ADDR11],
			((unsigned char *)(client_id_start)) [UB_ADDR12],
			((unsigned char *)(client_id_start)) [UB_ADDR13],
			((unsigned char *)(client_id_start)) [UB_ADDR14],
			((unsigned char *)(client_id_start)) [UB_ADDR15]);
}

void show_duid_llt_msg(unsigned char *client_id_start)
{
	unsigned short hardware_type = 0;
	unsigned short type_field = 0;
	unsigned char *index = NULL;
	unsigned int time = 0;

	index = client_id_start;
	memcpy(&type_field, index, sizeof(type_field));
	type_field = ntohs(type_field);

	index += sizeof(type_field);
	memcpy(&hardware_type, index, sizeof(hardware_type));
	hardware_type = ntohs(hardware_type);

	index += sizeof(hardware_type);
	memcpy(&time, index, sizeof(time));
	time = ntohl(time);
	index += sizeof(time);

	log_show("duid_type \t= %u", type_field);
	log_show("hardware_type \t= %u", hardware_type);
	log_show("time \t= %u", time);
	show_client_id(index);
}

void show_duid_ll_msg(unsigned char *client_id_start)
{
	unsigned short hardware_type = 0;
	unsigned short type_field = 0;
	unsigned char *index = NULL;

	index = client_id_start;
	memcpy(&type_field, index, sizeof(type_field));
	type_field = ntohs(type_field);

	index += sizeof(type_field);
	memcpy(&hardware_type, index, sizeof(hardware_type));
	hardware_type = ntohs(type_field);

	index += sizeof(hardware_type);

	log_show("duid_type \t= %u", type_field);
	log_show("hardware_type \t= %u", hardware_type);
	show_client_id(index);
}

#define DUID_TYPE_OFFSET	4
#define DUID_LLT_BYTES		24
#define DUID_LL_BYTES		20
void show_raw_ub_pdu6(struct dhcpv6_packet *tdp6, int len)
{
	unsigned char *option_start, *client_id_start, *p;
	unsigned int option_len, option1_data_len;
	unsigned int duid_bytes = 0;
	unsigned char dhcp6_len;
	int duid_type = 0;

	p = (unsigned char *)&duid_type;
	*p = tdp6->options[DUID_TYPE_OFFSET + 1];
	*(p + 1) = tdp6->options[DUID_TYPE_OFFSET];

	if (duid_type == DUID_LLT) {
		duid_bytes = DUID_LLT_BYTES;
	} else if (duid_type == DUID_LL) {
		duid_bytes = DUID_LL_BYTES;
	} else {
		log_error("Not suit duid type : %d", duid_type);
		return;
	}

	client_id_start = (unsigned char *)malloc(sizeof(unsigned char) * (duid_bytes + 1));
	if (client_id_start == NULL) {
		log_fatal("%s:%d failed to alloc memory.", MDL);
		return;
	}

	dhcp6_len = sizeof(struct dhcpv6_packet);
	option_start = (unsigned char *)tdp6 + dhcp6_len;
	option_len = len - dhcp6_len;
	option1_data_len =
		get_option1_msg(option_start, option_len, client_id_start);
	if (option1_data_len != duid_bytes) {
		log_error("Wrong option1_data_len : %u, "
				  "duid_type : %d"
				  "duid_bytes : %u",
				  option1_data_len,
				  duid_type,
				  duid_bytes);
		free (client_id_start);
		return;
	}

	log_show("msg_type \t= %u", tdp6->msg_type);
	log_show("transaction_id \t= %u", (tdp6->transaction_id[T_INDEX0] << DELOCALIZE16) +
		 (tdp6->transaction_id[T_INDEX1] << DELOCALIZE8) + (tdp6->transaction_id[T_INDEX2]));
	log_show("option 1 message: ");
	log_show("[ option-code \t= %d ]", D6O_CLIENTID);
	log_show("[ option-len \t= %u ]", option1_data_len);
	if (duid_type == DUID_LLT)
		show_duid_llt_msg(client_id_start);
	else
		show_duid_ll_msg(client_id_start);
	free (client_id_start);
}

void print_ub_packet (unsigned char *buff, u_int32_t buf_len, unsigned char print_level)
{
	int ubh_len = sizeof(struct ub_link_header);
	int ip_len = sizeof(struct ip);
	int udp_len = sizeof(struct udphdr);
	int pkt_len = ubh_len + ip_len + udp_len + BOOTP_MIN_LEN;
	struct dhcp_packet *tdp = (struct dhcp_packet *)(buff + pkt_len - BOOTP_MIN_LEN);
	u_int8_t pkt_type = 0;
	char *msg_type = " ";

	if (print_level != PRINT_TXPKTS)
		return;

	if (buff == NULL) {
		log_show("Ub packet buff is NULL.\n");
		return;
	}

	pkt_type = get_message_type(tdp);
	switch (pkt_type) {
		case DHCPDISCOVER:
			msg_type = "DHCPDISCOVER";
			break;
		case DHCPREQUEST:
			msg_type = "DHCPREQUEST";
			break;
		case DHCPDECLINE:
			msg_type = "DHCPDECLINE";
			break;
		case DHCPRELEASE:
			msg_type = "DHCPRELEASE";
			break;
		case DHCPINFORM:
			msg_type = "DHCPINFORM";
			break;
		default:
			break;
	}

	log_show("\nstart parse %s \n", msg_type);
	if (pkt_len > buf_len) {
		log_show("Unable to parse complete ub packet: ");
		log_show("pktlen[%d], buf_len[%u]\n", pkt_len, buf_len);
		return;
	}

	struct ub_link_header *ubh = (struct ub_link_header *)buff;
	struct ip *iph = (struct ip *)(buff + ubh_len);
	struct udphdr *udph = (struct udphdr *)(buff + ubh_len + ip_len);

	show_raw_hdr(ubh, iph, udph);
	show_raw_ub_pdu(tdp);
	log_show("end parse %s\n", msg_type);
}

void print_ub_packet6 (unsigned char *buff, u_int32_t buf_len, unsigned char print_level)
{
	int ubh_len = sizeof(struct ub_link_header);
	int iph_len = sizeof(struct ipv6);
	int udp_len = sizeof(struct udphdr);
	int hdr_len = ubh_len + iph_len + udp_len;
	unsigned char *dhcpv6_pkt = buff + hdr_len;
	unsigned char dhcpv6_msg_type = 0;
	int value;

	if (print_level != PRINT_TXPKTS)
		return;

	if (buff == NULL) {
		log_show("Ub packet buff is NULL.\n");
		return;
	}

	if (!packet6_len_okay((const char *)(char *)dhcpv6_pkt, buf_len)) {
		log_info("print_ub_packet6 : short packet len %u, dropped", buf_len);
		return;
	}

	dhcpv6_msg_type = dhcpv6_pkt[0];
	value = dhcpv6_message_values[dhcpv6_msg_type - 1].value;
	if (dhcpv6_msg_type != value) {
		log_error("Mismatching message type : %u,"
					"which should be : %d.",
					dhcpv6_msg_type, value);
		return;
	}

	log_show("\nStart parse ub_packet6 %s.\n", dhcpv6_message_values[dhcpv6_msg_type - 1].name);

	struct ub_link_header *ubh = (struct ub_link_header *)buff;
	struct ipv6 *iph = (struct ipv6 *)(buff + ubh_len);
	struct udphdr *udph = (struct udphdr *)(buff + ubh_len + iph_len);
	struct dhcpv6_packet *tdp6 = (struct dhcpv6_packet *)(buff + hdr_len);

	show_raw_hdr6(ubh, iph, udph);
	show_raw_ub_pdu6(tdp6, buf_len);
	log_show("\nEnd parse ub_packet6 %s\n", dhcpv6_message_values[dhcpv6_msg_type - 1].name);
}

unsigned char get_message_type (struct dhcp_packet *packet)
{
	unsigned char ret = 0;
	unsigned char option_header_len = 4;
	int dhcp_packet_len = sizeof(struct dhcp_packet);
	int option_start = dhcp_packet_len - DHCP_MAX_OPTION_LEN;
	unsigned char *buf = (unsigned char *)malloc(dhcp_packet_len);
	unsigned char *src_buf;

	if (buf == NULL) {
		log_fatal("%s:%d failed to alloc memory.\n", MDL);
		return ret;
	}

	src_buf = buf;
	if (packet == NULL) {
		log_info("DHCP packet is NULL.\n");
		free(src_buf);
		return ret;
	}

	memcpy(buf, packet, dhcp_packet_len);
	buf = (unsigned char *)((unsigned char *)buf + option_start);
	if (buf[B_INDEX0] == 0x63 && buf[B_INDEX1] == 0x82 &&
		buf[B_INDEX2] == 0x53 && buf[B_INDEX3] == 0x63) {
		int max_option_len;
		int buf_index;

		buf += option_header_len;
		buf_index = 0;
		max_option_len = DHCP_MAX_OPTION_LEN - option_header_len;

		while (buf_index < max_option_len) {
			if (buf[buf_index] != DHO_DHCP_MESSAGE_TYPE) {
				/* go to next option start */
				buf_index = B_INDEX2 + buf[buf_index + B_INDEX1];
				continue;
			}
			/* check option53 message len */
			buf_index++;
			if (buf[buf_index] == 1) {
				ret = buf[buf_index + 1];
				free(src_buf);
				return ret;
			} else {
				log_info("Wrong message type len : [%u]\n", buf[buf_index]);
				free(src_buf);
				return ret;
			}
		}
	}
	free(src_buf);
	return ret;
}

void record_packet_info (struct packet_record *pkt_record_info,
						 struct dhcp_packet *packet)
{
	struct send_receive_counter *tx_rx_cnt = NULL;
	u_int8_t dhcp_packet_op = 0;
	u_int8_t pkt_type = 0;
	u_int32_t xid = 0;

	pkt_type = get_message_type(packet);
	if (pkt_type < DHCPDISCOVER || pkt_type > PACKET_TYPE_NUM) {
		log_error("Packet type [%u] out of range\n", pkt_type);
		return;
	}
	dhcp_packet_op = packet->op;
	xid = ntohl(packet->xid);

	if (dhcp_packet_op == BOOTREQUEST) {
		pkt_record_info->last_sent_request_type = pkt_type;
		pkt_record_info->last_sent_request_xid = xid;
	} else {
		pkt_record_info->new_recv_pkt_type = pkt_type;
		pkt_record_info->new_recv_pkt_xid = xid;
	}

	tx_rx_cnt = pkt_record_info->pkt_record_list[pkt_type - 1];
	if (tx_rx_cnt == NULL) {
		log_error("error, tx_rx_cnt is NULL\n");
		free(packet);
		return;
	}

	tx_rx_cnt->packet_type = pkt_type;
	if (dhcp_packet_op == BOOTREQUEST) {
		tx_rx_cnt->last_sent_xid = xid;
		tx_rx_cnt->total_sent_count++;
	} else {
		tx_rx_cnt->total_recv_count++;
		tx_rx_cnt->new_recv_xid = xid;
	}
}

void record_packet_info6 (struct packet_record *pkt_record_info,
						  unsigned char *pkt)
{
	u_int32_t xid = 0;
	u_int8_t msg_type = 0;
	int ubh_len = sizeof(struct ub_link_header);
	int iph_len = sizeof(struct ipv6);
	int udp_len = sizeof(struct udphdr);
	int hdr_len = ubh_len + iph_len + udp_len;
	struct dhcpv6_packet *tdp6 = (struct dhcpv6_packet *)(pkt + hdr_len);
	struct send_receive_counter *tx_rx_cnt = NULL;

	msg_type = tdp6->msg_type;
	if (msg_type < DHCPV6_SOLICIT || msg_type > PACKET_TYPE_NUM) {
		log_error("Message type [%u] out of range\n", msg_type);
		return;
	}
	xid = (tdp6->transaction_id[T_INDEX0] << DELOCALIZE16) \
		+ (tdp6->transaction_id[T_INDEX1] << DELOCALIZE8) + (tdp6->transaction_id[T_INDEX2]);
	tx_rx_cnt = pkt_record_info->pkt_record_list[msg_type - 1];
	if (tx_rx_cnt == NULL) {
		log_error("error, tx_rx_cnt6 is NULL\n");
		return;
	}
	tx_rx_cnt->packet_type = msg_type;
	if (msg_type == DHCPV6_ADVERTISE ||
		msg_type == DHCPV6_REPLY ||
		msg_type == DHCPV6_RECONFIGURE) {
		pkt_record_info->new_recv_pkt_type = msg_type;
		pkt_record_info->new_recv_pkt_xid = xid;
		tx_rx_cnt->total_recv_count++;
		tx_rx_cnt->new_recv_xid = xid;
	} else {
		pkt_record_info->last_sent_request_type = msg_type;
		pkt_record_info->last_sent_request_xid = xid;
		tx_rx_cnt->last_sent_xid = xid;
		tx_rx_cnt->total_sent_count++;
	}
}

void print_dhcpv4_pkt_type (u_int32_t pkt_type)
{
	switch (pkt_type) {
		case DHCP_DISCOVER_IDX:
			log_show("|*****Message type : [DHCPDISCOVER]*****|\n");
			break;
		case DHCP_OFFER_IDX:
			log_show("|*******Message type : [DHCPOFFER]******|\n");
			break;
		case DHCP_REQUEST_IDX:
			log_show("|******Message type : [DHCPREQUEST]*****|\n");
			break;
		case DHCP_DECLINE_IDX:
			log_show("|*****Message type : [DHCPDECLINE]******|\n");
			break;
		case DHCP_ACK_IDX:
			log_show("|********Message type : [DHCPACK]*******|\n");
			break;
		case DHCP_NAK_IDX:
			log_show("|********Message type : [DHCPNAK]*******|\n");
			break;
		case DHCP_RELEASE_IDX:
			log_show("|*****Message type : [DHCPRELEASE]******|\n");
			break;
		case DHCP_INFORM_IDX:
			log_show("|******Message type : [DHCPINFORM]******|\n");
			break;
		default:
			break;
	}
}

void print_dhcpv6_pkt_type (u_int32_t pkt_type)
{
	log_show("|********* Message type : [%s] start**********|",
		dhcpv6_message_values[pkt_type].name);
}

void print_packet_type (u_int32_t pkt_type)
{
	if (local_family == AF_INET) {
		print_dhcpv4_pkt_type(pkt_type);
	} else if (local_family == AF_INET6) {
		print_dhcpv6_pkt_type(pkt_type);
	} else {
		log_show("No such message type [%u] for now.\n", pkt_type);
	}
}

void print_record_info (struct packet_record *pkt_record_info, unsigned char print_level)
{
	u_int32_t i;

	if (print_level != PRINT_UBPKT_INFO)
		return;

	log_show("|********packet record info*************|\n");
	log_show("last_sent_request_xid \t= %u\n", pkt_record_info->last_sent_request_xid);
	log_show("new_recv_pkt_xid \t= %u\n", pkt_record_info->new_recv_pkt_xid);
	for (i = 0; i < PACKET_TYPE_NUM4; i++) {
		struct send_receive_counter *tx_rx_cnt = NULL;

		tx_rx_cnt = pkt_record_info->pkt_record_list[i];
		print_packet_type(i);
		if (tx_rx_cnt) {
			log_show("packet_type \t= %u\n", tx_rx_cnt->packet_type);
			log_show("total_sent_count \t= %u\n", tx_rx_cnt->total_sent_count);
			log_show("last_sent_xid \t= %u\n", tx_rx_cnt->last_sent_xid);
			log_show("total_recv_count \t= %u\n", tx_rx_cnt->total_recv_count);
			log_show("new_recv_xid \t= %u\n", tx_rx_cnt->new_recv_xid);
		}
		log_show("|**********Message info end*************|\n\n");
	}
	log_show("|*********packet record info end********|\n\n");
}

void print_record_info6(struct packet_record *pkt_record_info, unsigned char print_level)
{
	u_int32_t i;

	if (print_level != PRINT_UBPKT_INFO)
		return;

	log_show("|********packet dhcpv6 record info start*************|\n");
	log_show("last_sent_request_transaction_id \t= %u", pkt_record_info->last_sent_request_xid);
	log_show("new_recv_pkt_transaction_id \t= %u", pkt_record_info->new_recv_pkt_xid);
	for (i = 0; i < PACKET_TYPE_NUM6; i++) {
		struct send_receive_counter *tx_rx_cnt = NULL;

		tx_rx_cnt = pkt_record_info->pkt_record_list[i];
		print_packet_type(i);
		if (tx_rx_cnt) {
			log_show("packet_type \t= %u", tx_rx_cnt->packet_type);
			log_show("total_sent_count \t= %u", tx_rx_cnt->total_sent_count);
			log_show("last_sent_transaction_id \t= %u", tx_rx_cnt->last_sent_xid);
			log_show("total_recv_count \t= %u", tx_rx_cnt->total_recv_count);
			log_show("new_recv_transaction_id \t= %u", tx_rx_cnt->new_recv_xid);
		}
		log_show("|**********Message info end*************|\n");
	}
	log_show("|*********packet dhcpv6 record info end********|\n\n");
}

void dump_raw (buf, len)
	const unsigned char *buf;
	unsigned len;
{
	int i;
	char lbuf [80];
	int lbix = 0;

/*
          1         2         3         4         5         6         7
01234567890123456789012345678901234567890123456789012345678901234567890123
280: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   .................
*/

	memset(lbuf, ' ', 79);
	lbuf [79] = 0;

	for (i = 0; i < len; i++) {
		if ((i & 15) == 0) {
		  if (lbix) {
		    	lbuf[53]=' ';
			lbuf[54]=' ';
			lbuf[55]=' ';
			lbuf[73]='\0';
			log_info ("%s", lbuf);
		  }
		  memset(lbuf, ' ', 79);
		  lbuf [79] = 0;
		  sprintf (lbuf, "%03x:", i);
		  lbix = 4;
		} else if ((i & 7) == 0)
			lbuf [lbix++] = ' ';

		if(isprint(buf[i])) {
		  lbuf[56+(i%16)]=buf[i];
		} else {
		  lbuf[56+(i%16)]='.';
		}

		sprintf (&lbuf [lbix], " %02x", buf [i]);
		lbix += 3;
		lbuf[lbix]=' ';

	}
	lbuf[53]=' ';
	lbuf[54]=' ';
	lbuf[55]=' ';
	lbuf[73]='\0';
	log_info ("%s", lbuf);
}

void hash_dump (table)
	struct hash_table *table;
{
	int i;
	struct hash_bucket *bp;

	if (!table)
		return;

	for (i = 0; i < table -> hash_count; i++) {
		if (!table -> buckets [i])
			continue;
		log_info ("hash bucket %d:", i);
		for (bp = table -> buckets [i]; bp; bp = bp -> next) {
			if (bp -> len)
				dump_raw (bp -> name, bp -> len);
			else
				log_info ("%s", (const char *)bp -> name);
		}
	}
}

/*
 * print a string as hex.  This only outputs
 * colon separated hex list no matter what
 * the input looks like.  See print_hex
 * for a function that prints either cshl
 * or a string if all bytes are printible
 * It only uses limit characters from buf
 * and doesn't do anything if buf == NULL
 *
 * len - length of data
 * data - input data
 * limit - length of buf to use
 * buf - output buffer
 */
void print_hex_only (len, data, limit, buf)
	unsigned len;
	const u_int8_t *data;
	unsigned limit;
	char *buf;
{
	char *bufptr = buf;
	int byte = 0;

	if (data == NULL || bufptr == NULL || limit == 0) {
		return;
	}

	if (((len == 0) || ((len * 3) > limit))) {
		*bufptr = 0x0;
		return;
	}

	for ( ; byte < len; ++byte) {
		if (byte > 0) {
			*bufptr++ = ':';
		}

		sprintf(bufptr, "%02x", data[byte]);
		bufptr += 2;
	}

	return;
}

/*
 * print a string as either text if all the characters
 * are printable or colon separated hex if they aren't
 *
 * len - length of data
 * data - input data
 * limit - length of buf to use
 * buf - output buffer
 */
void print_hex_or_string (len, data, limit, buf)
	unsigned len;
	const u_int8_t *data;
	unsigned limit;
	char *buf;
{
	unsigned i;
	if ((buf == NULL) || (limit < 3))
		return;

	for (i = 0; (i < (limit - 3)) && (i < len); i++) {
		if (!isascii(data[i]) || !isprint(data[i])) {
			print_hex_only(len, data, limit, buf);
			return;
		}
	}

	buf[0] = '"';
	i = len;
	if (i > (limit - 3))
		i = limit - 3;
	memcpy(&buf[1], data, i);
	buf[i + 1] = '"';
	buf[i + 2] = 0;
	return;
}

/*
 * print a string as either hex or text
 * using static buffers to hold the output
 *
 * len - length of data
 * data - input data
 * limit - length of buf
 * buf_num - the output buffer to use
 */
#define HBLEN 1024
char *print_hex(len, data, limit, buf_num)
	unsigned len;
	const u_int8_t *data;
	unsigned limit;
	unsigned buf_num;
{
	static char hex_buf_1[HBLEN + 1];
	static char hex_buf_2[HBLEN + 1];
	static char hex_buf_3[HBLEN + 1];
	char *hex_buf;

	switch(buf_num) {
	  case 0:
		hex_buf = hex_buf_1;
		if (limit >= sizeof(hex_buf_1))
			limit = sizeof(hex_buf_1);
		break;
	  case 1:
		hex_buf = hex_buf_2;
		if (limit >= sizeof(hex_buf_2))
			limit = sizeof(hex_buf_2);
		break;
	  case 2:
		hex_buf = hex_buf_3;
		if (limit >= sizeof(hex_buf_3))
			limit = sizeof(hex_buf_3);
		break;
	  default:
		return(NULL);
	}

	print_hex_or_string(len, data, limit, hex_buf);
	return(hex_buf);
}

#define DQLEN	80

char *print_dotted_quads (len, data)
	unsigned len;
	const u_int8_t *data;
{
	static char dq_buf [DQLEN + 1];
	int i;
	char *s;

	s = &dq_buf [0];

	i = 0;

	/* %Audit% Loop bounds checks to 21 bytes. %2004.06.17,Safe%
	 * The sprintf can't exceed 18 bytes, and since the loop enforces
	 * 21 bytes of space per iteration at no time can we exit the
	 * loop without at least 3 bytes spare.
	 */
	do {
		sprintf (s, "%u.%u.%u.%u, ",
			 data [i], data [i + 1], data [i + 2], data [i + 3]);
		s += strlen (s);
		i += 4;
	} while ((s - &dq_buf [0] > DQLEN - 21) &&
		 i + 3 < len);
	if (i == len)
		s [-2] = 0;
	else
		strcpy (s, "...");
	return dq_buf;
}

char *print_dec_1 (val)
	unsigned long val;
{
	static char vbuf [32];
	sprintf (vbuf, "%lu", val);
	return vbuf;
}

char *print_dec_2 (val)
	unsigned long val;
{
	static char vbuf [32];
	sprintf (vbuf, "%lu", val);
	return vbuf;
}

static unsigned print_subexpression (struct expression *, char *, unsigned);

static unsigned print_subexpression (expr, buf, len)
	struct expression *expr;
	char *buf;
	unsigned len;
{
	unsigned rv, left;
	const char *s;

	switch (expr -> op) {
	      case expr_none:
		if (len > 3) {
			strcpy (buf, "nil");
			return 3;
		}
		break;

	      case expr_match:
		if (len > 7) {
			strcpy (buf, "(match)");
			return 7;
		}
		break;

	      case expr_check:
		rv = 10 + strlen (expr -> data.check -> name);
		if (len > rv) {
			sprintf (buf, "(check %s)",
				 expr -> data.check -> name);
			return rv;
		}
		break;

	      case expr_equal:
		if (len > 6) {
			rv = 4;
			strcpy (buf, "(eq ");
			rv += print_subexpression (expr -> data.equal [0],
						   buf + rv, len - rv - 2);
			buf [rv++] = ' ';
			rv += print_subexpression (expr -> data.equal [1],
						   buf + rv, len - rv - 1);
			buf [rv++] = ')';
			buf [rv] = 0;
			return rv;
		}
		break;

	      case expr_not_equal:
		if (len > 7) {
			rv = 5;
			strcpy (buf, "(neq ");
			rv += print_subexpression (expr -> data.equal [0],
						   buf + rv, len - rv - 2);
			buf [rv++] = ' ';
			rv += print_subexpression (expr -> data.equal [1],
						   buf + rv, len - rv - 1);
			buf [rv++] = ')';
			buf [rv] = 0;
			return rv;
		}
		break;

	      case expr_regex_match:
		if (len > 10) {
			rv = 4;
			strcpy(buf, "(regex ");
			rv += print_subexpression(expr->data.equal[0],
						  buf + rv, len - rv - 2);
			buf[rv++] = ' ';
			rv += print_subexpression(expr->data.equal[1],
						  buf + rv, len - rv - 1);
			buf[rv++] = ')';
			buf[rv] = 0;
			return rv;
		}
		break;

	      case expr_substring:
		if (len > 11) {
			rv = 8;
			strcpy (buf, "(substr ");
			rv += print_subexpression (expr -> data.substring.expr,
						   buf + rv, len - rv - 3);
			buf [rv++] = ' ';
			rv += print_subexpression
				(expr -> data.substring.offset,
				 buf + rv, len - rv - 2);
			buf [rv++] = ' ';
			rv += print_subexpression (expr -> data.substring.len,
						   buf + rv, len - rv - 1);
			buf [rv++] = ')';
			buf [rv] = 0;
			return rv;
		}
		break;

	      case expr_suffix:
		if (len > 10) {
			rv = 8;
			strcpy (buf, "(suffix ");
			rv += print_subexpression (expr -> data.suffix.expr,
						   buf + rv, len - rv - 2);
			if (len > rv)
				buf [rv++] = ' ';
			rv += print_subexpression (expr -> data.suffix.len,
						   buf + rv, len - rv - 1);
			if (len > rv)
				buf [rv++] = ')';
			buf [rv] = 0;
			return rv;
		}
		break;

	      case expr_lcase:
		if (len > 9) {
			rv = 7;
			strcpy(buf, "(lcase ");
			rv += print_subexpression(expr->data.lcase,
						  buf + rv, len - rv - 1);
			buf[rv++] = ')';
			buf[rv] = 0;
			return rv;
		}
		break;

	      case expr_ucase:
		if (len > 9) {
			rv = 7;
			strcpy(buf, "(ucase ");
			rv += print_subexpression(expr->data.ucase,
						  buf + rv, len - rv - 1);
			buf[rv++] = ')';
			buf[rv] = 0;
			return rv;
		}
		break;

	      case expr_concat:
		if (len > 10) {
			rv = 8;
			strcpy (buf, "(concat ");
			rv += print_subexpression (expr -> data.concat [0],
						   buf + rv, len - rv - 2);
			buf [rv++] = ' ';
			rv += print_subexpression (expr -> data.concat [1],
						   buf + rv, len - rv - 1);
			buf [rv++] = ')';
			buf [rv] = 0;
			return rv;
		}
		break;

	      case expr_pick_first_value:
		if (len > 8) {
			rv = 6;
			strcpy (buf, "(pick1st ");
			rv += print_subexpression
				(expr -> data.pick_first_value.car,
				 buf + rv, len - rv - 2);
			buf [rv++] = ' ';
			rv += print_subexpression
				(expr -> data.pick_first_value.cdr,
				 buf + rv, len - rv - 1);
			buf [rv++] = ')';
			buf [rv] = 0;
			return rv;
		}
		break;

	      case expr_host_lookup:
		rv = 15 + strlen (expr -> data.host_lookup -> hostname);
		if (len > rv) {
			sprintf (buf, "(dns-lookup %s)",
				 expr -> data.host_lookup -> hostname);
			return rv;
		}
		break;

	      case expr_and:
		s = "and";
	      binop:
		rv = strlen (s);
		if (len > rv + 4) {
			buf [0] = '(';
			strcpy (&buf [1], s);
			rv += 1;
			buf [rv++] = ' ';
			rv += print_subexpression (expr -> data.and [0],
						buf + rv, len - rv - 2);
			buf [rv++] = ' ';
			rv += print_subexpression (expr -> data.and [1],
						   buf + rv, len - rv - 1);
			buf [rv++] = ')';
			buf [rv] = 0;
			return rv;
		}
		break;

	      case expr_or:
		s = "or";
		goto binop;

	      case expr_add:
		s = "+";
		goto binop;

	      case expr_subtract:
		s = "-";
		goto binop;

	      case expr_multiply:
		s = "*";
		goto binop;

	      case expr_divide:
		s = "/";
		goto binop;

	      case expr_remainder:
		s = "%";
		goto binop;

	      case expr_binary_and:
		s = "&";
		goto binop;

	      case expr_binary_or:
		s = "|";
		goto binop;

	      case expr_binary_xor:
		s = "^";
		goto binop;

	      case expr_not:
		if (len > 6) {
			rv = 5;
			strcpy (buf, "(not ");
			rv += print_subexpression (expr -> data.not,
						   buf + rv, len - rv - 1);
			buf [rv++] = ')';
			buf [rv] = 0;
			return rv;
		}
		break;

	      case expr_config_option:
		s = "cfg-option";
		goto dooption;

	      case expr_option:
		s = "option";
	      dooption:
		rv = strlen (s) + 2 + (strlen (expr -> data.option -> name) +
			   strlen (expr -> data.option -> universe -> name));
		if (len > rv) {
			sprintf (buf, "(option %s.%s)",
				 expr -> data.option -> universe -> name,
				 expr -> data.option -> name);
			return rv;
		}
		break;

	      case expr_hardware:
		if (len > 10) {
			strcpy (buf, "(hardware)");
			return 10;
		}
		break;

	      case expr_packet:
		if (len > 10) {
			rv = 8;
			strcpy (buf, "(substr ");
			rv += print_subexpression (expr -> data.packet.offset,
						   buf + rv, len - rv - 2);
			buf [rv++] = ' ';
			rv += print_subexpression (expr -> data.packet.len,
						   buf + rv, len - rv - 1);
			buf [rv++] = ')';
			buf [rv] = 0;
			return rv;
		}
		break;

	      case expr_const_data:
		s = print_hex_1 (expr -> data.const_data.len,
				 expr -> data.const_data.data, len);
		rv = strlen (s);
		if (rv >= len)
			rv = len - 1;
		strncpy (buf, s, rv);
		buf [rv] = 0;
		return rv;

	      case expr_encapsulate:
		rv = 13;
		strcpy (buf, "(encapsulate ");
		rv += expr -> data.encapsulate.len;
		if (rv + 2 > len)
			rv = len - 2;
		strncpy (buf,
			 (const char *)expr -> data.encapsulate.data, rv - 13);
		buf [rv++] = ')';
		buf [rv++] = 0;
		break;

	      case expr_extract_int8:
		if (len > 7) {
			rv = 6;
			strcpy (buf, "(int8 ");
			rv += print_subexpression (expr -> data.extract_int,
						   buf + rv, len - rv - 1);
			buf [rv++] = ')';
			buf [rv] = 0;
			return rv;
		}
		break;

	      case expr_extract_int16:
		if (len > 8) {
			rv = 7;
			strcpy (buf, "(int16 ");
			rv += print_subexpression (expr -> data.extract_int,
						   buf + rv, len - rv - 1);
			buf [rv++] = ')';
			buf [rv] = 0;
			return rv;
		}
		break;

	      case expr_extract_int32:
		if (len > 8) {
			rv = 7;
			strcpy (buf, "(int32 ");
			rv += print_subexpression (expr -> data.extract_int,
						   buf + rv, len - rv - 1);
			buf [rv++] = ')';
			buf [rv] = 0;
			return rv;
		}
		break;

	      case expr_encode_int8:
		if (len > 7) {
			rv = 6;
			strcpy (buf, "(to-int8 ");
			rv += print_subexpression (expr -> data.encode_int,
						   buf + rv, len - rv - 1);
			buf [rv++] = ')';
			buf [rv] = 0;
			return rv;
		}
		break;

	      case expr_encode_int16:
		if (len > 8) {
			rv = 7;
			strcpy (buf, "(to-int16 ");
			rv += print_subexpression (expr -> data.encode_int,
						   buf + rv, len - rv - 1);
			buf [rv++] = ')';
			buf [rv] = 0;
			return rv;
		}
		break;

	      case expr_encode_int32:
		if (len > 8) {
			rv = 7;
			strcpy (buf, "(to-int32 ");
			rv += print_subexpression (expr -> data.encode_int,
						   buf + rv, len - rv - 1);
			buf [rv++] = ')';
			buf [rv] = 0;
			return rv;
		}
		break;

	      case expr_const_int:
		s = print_dec_1 (expr -> data.const_int);
		rv = strlen (s);
		if (len > rv) {
			strcpy (buf, s);
			return rv;
		}
		break;

	      case expr_exists:
		rv = 10 + (strlen (expr -> data.option -> name) +
			   strlen (expr -> data.option -> universe -> name));
		if (len > rv) {
			sprintf (buf, "(exists %s.%s)",
				 expr -> data.option -> universe -> name,
				 expr -> data.option -> name);
			return rv;
		}
		break;

	      case expr_variable_exists:
		rv = 10 + strlen (expr -> data.variable);
		if (len > rv) {
			sprintf (buf, "(defined %s)", expr -> data.variable);
			return rv;
		}
		break;

	      case expr_variable_reference:
		rv = strlen (expr -> data.variable);
		if (len > rv) {
			sprintf (buf, "%s", expr -> data.variable);
			return rv;
		}
		break;

	      case expr_known:
		s = "known";
	      astring:
		rv = strlen (s);
		if (len > rv) {
			strcpy (buf, s);
			return rv;
		}
		break;

	      case expr_leased_address:
		s = "leased-address";
		goto astring;

	      case expr_client_state:
		s = "client-state";
		goto astring;

	      case expr_host_decl_name:
		s = "host-decl-name";
		goto astring;

	      case expr_lease_time:
		s = "lease-time";
		goto astring;

	      case expr_static:
		s = "static";
		goto astring;

	      case expr_filename:
		s = "filename";
		goto astring;

	      case expr_sname:
		s = "server-name";
		goto astring;

	      case expr_reverse:
		if (len > 11) {
			rv = 13;
			strcpy (buf, "(reverse ");
			rv += print_subexpression (expr -> data.reverse.width,
						   buf + rv, len - rv - 2);
			buf [rv++] = ' ';
			rv += print_subexpression (expr -> data.reverse.buffer,
						   buf + rv, len - rv - 1);
			buf [rv++] = ')';
			buf [rv] = 0;
			return rv;
		}
		break;

	      case expr_binary_to_ascii:
		if (len > 5) {
			rv = 9;
			strcpy (buf, "(b2a ");
			rv += print_subexpression (expr -> data.b2a.base,
						   buf + rv, len - rv - 4);
			buf [rv++] = ' ';
			rv += print_subexpression (expr -> data.b2a.width,
						   buf + rv, len - rv - 3);
			buf [rv++] = ' ';
			rv += print_subexpression (expr -> data.b2a.separator,
						   buf + rv, len - rv - 2);
			buf [rv++] = ' ';
			rv += print_subexpression (expr -> data.b2a.buffer,
						   buf + rv, len - rv - 1);
			buf [rv++] = ')';
			buf [rv] = 0;
			return rv;
		}
		break;

	      case expr_dns_transaction:
		rv = 10;
		if (len < rv + 2) {
			buf [0] = '(';
			strcpy (&buf [1], "ns-update ");
			while (len < rv + 2) {
				rv += print_subexpression
					(expr -> data.dns_transaction.car,
					 buf + rv, len - rv - 2);
				buf [rv++] = ' ';
				expr = expr -> data.dns_transaction.cdr;
			}
			buf [rv - 1] = ')';
			buf [rv] = 0;
			return rv;
		}
		return 0;

	      case expr_ns_delete:
		s = "delete";
		left = 4;
		goto dodnsupd;
	      case expr_ns_exists:
		s = "exists";
		left = 4;
		goto dodnsupd;
	      case expr_ns_not_exists:
		s = "not_exists";
		left = 4;
		goto dodnsupd;
	      case expr_ns_add:
		s = "update";
		left = 5;
	      dodnsupd:
		rv = strlen (s);
		if (len > strlen (s) + 1) {
			buf [0] = '(';
			strcpy (buf + 1, s);
			rv++;
			buf [rv++] = ' ';
			s = print_dec_1 (expr -> data.ns_add.rrclass);
			if (len > rv + strlen (s) + left) {
				strcpy (&buf [rv], s);
				rv += strlen (&buf [rv]);
			}
			buf [rv++] = ' ';
			left--;
			s = print_dec_1 (expr -> data.ns_add.rrtype);
			if (len > rv + strlen (s) + left) {
				strcpy (&buf [rv], s);
				rv += strlen (&buf [rv]);
			}
			buf [rv++] = ' ';
			left--;
			rv += print_subexpression
				(expr -> data.ns_add.rrname,
				 buf + rv, len - rv - left);
			buf [rv++] = ' ';
			left--;
			rv += print_subexpression
				(expr -> data.ns_add.rrdata,
				 buf + rv, len - rv - left);
			buf [rv++] = ' ';
			left--;
			rv += print_subexpression
				(expr -> data.ns_add.ttl,
				 buf + rv, len - rv - left);
			buf [rv++] = ')';
			buf [rv] = 0;
			return rv;
		}
		break;

	      case expr_null:
		if (len > 6) {
			strcpy (buf, "(null)");
			return 6;
		}
		break;
	      case expr_funcall:
		rv = 12 + strlen (expr -> data.funcall.name);
		if (len > rv + 1) {
			strcpy (buf, "(funcall  ");
			strcpy (buf + 9, expr -> data.funcall.name);
			buf [rv++] = ' ';
			rv += print_subexpression
				(expr -> data.funcall.arglist, buf + rv,
				 len - rv - 1);
			buf [rv++] = ')';
			buf [rv] = 0;
			return rv;
		}
		break;

	      case expr_arg:
		rv = print_subexpression (expr -> data.arg.val, buf, len);
		if (expr -> data.arg.next && rv + 2 < len) {
			buf [rv++] = ' ';
			rv += print_subexpression (expr -> data.arg.next,
						   buf, len);
			if (rv + 1 < len)
				buf [rv++] = 0;
			return rv;
		}
		break;

	      case expr_function:
		rv = 9;
		if (len > rv + 1) {
			struct string_list *foo;
			strcpy (buf, "(function");
			for (foo = expr -> data.func -> args;
			     foo; foo = foo -> next) {
				if (len > rv + 2 + strlen (foo -> string)) {
					buf [rv - 1] = ' ';
					strcpy (&buf [rv], foo -> string);
					rv += strlen (foo -> string);
				}
			}
			buf [rv++] = ')';
			buf [rv] = 0;
			return rv;
		}
		break;

	      case expr_gethostname:
		if (len > 13) {
			strcpy(buf, "(gethostname)");
			return 13;
		}
		break;

	      default:
		log_fatal("Impossible case at %s:%d (undefined expression "
			  "%d).", MDL, expr->op);
		break;
	}
	return 0;
}

void print_expression (name, expr)
	const char *name;
	struct expression *expr;
{
	char buf [1024];

	print_subexpression (expr, buf, sizeof buf);
	log_info ("%s: %s", name, buf);
}

int token_print_indent_concat (FILE *file, int col,  int indent,
			       const char *prefix,
			       const char *suffix, ...)
{
	va_list list;
	unsigned len;
	char *s, *t, *u;

	va_start (list, suffix);
	s = va_arg (list, char *);
	len = 0;
	while (s) {
		len += strlen (s);
		s = va_arg (list, char *);
	}
	va_end (list);

	t = dmalloc (len + 1, MDL);
	if (!t)
		log_fatal ("token_print_indent: no memory for copy buffer");

	va_start (list, suffix);
	s = va_arg (list, char *);
	u = t;
	while (s) {
		len = strlen (s);
		strcpy (u, s);
		u += len;
		s = va_arg (list, char *);
	}
	va_end (list);

	col = token_print_indent (file, col, indent,
				  prefix, suffix, t);
	dfree (t, MDL);
	return col;
}

int token_indent_data_string (FILE *file, int col, int indent,
			      const char *prefix, const char *suffix,
			      struct data_string *data)
{
	int i;
	char *buf;
	char obuf [3];

	/* See if this is just ASCII. */
	for (i = 0; i < data -> len; i++)
		if (!isascii (data -> data [i]) ||
		    !isprint (data -> data [i]))
			break;

	/* If we have a purely ASCII string, output it as text. */
	if (i == data -> len) {
		buf = dmalloc (data -> len + 3, MDL);
		if (buf) {
			buf [0] = '"';
			memcpy (buf + 1, data -> data, data -> len);
			buf [data -> len + 1] = '"';
			buf [data -> len + 2] = 0;
			i = token_print_indent (file, col, indent,
						prefix, suffix, buf);
			dfree (buf, MDL);
			return i;
		}
	}

	for (i = 0; i < data -> len; i++) {
		sprintf (obuf, "%2.2x", data -> data [i]);
		col = token_print_indent (file, col, indent,
					  i == 0 ? prefix : "",
					  (i + 1 == data -> len
					   ? suffix
					   : ""), obuf);
		if (i + 1 != data -> len)
			col = token_print_indent (file, col, indent,
						  prefix, suffix, ":");
	}
	return col;
}

int token_print_indent (FILE *file, int col, int indent,
			const char *prefix,
			const char *suffix, const char *buf)
{
	int len = 0;
	if (prefix != NULL)
		len += strlen (prefix);
	if (buf != NULL)
		len += strlen (buf);

	if (col + len > 79) {
		if (indent + len < 79) {
			indent_spaces (file, indent);
			col = indent;
		} else {
			indent_spaces (file, col);
			col = len > 79 ? 0 : 79 - len - 1;
		}
	} else if (prefix && *prefix) {
		fputs (prefix, file);
		col += strlen (prefix);
	}
	if ((buf != NULL) && (*buf != 0)) {
		fputs (buf, file);
		col += strlen(buf);
	}
	if (suffix && *suffix) {
		if (col + strlen (suffix) > 79) {
			indent_spaces (file, indent);
			col = indent;
		} else {
			fputs (suffix, file);
			col += strlen (suffix);
		}
	}
	return col;
}

void indent_spaces (FILE *file, int indent)
{
	int i;
	fputc ('\n', file);
	for (i = 0; i < indent; i++)
		fputc (' ', file);
}

/* Format the given time as "A; # B", where A is the format
 * used by the parser, and B is the local time, for humans.
 */
const char *
print_time(TIME t)
{
	static char buf[sizeof("epoch 9223372036854775807; "
			       "# Wed Jun 30 21:49:08 2147483647")];
	static char buf1[sizeof("# Wed Jun 30 21:49:08 2147483647")];
	time_t since_epoch;
	/* The string: 	       "6 2147483647/12/31 23:59:60;"
	 * is smaller than the other, used to declare the buffer size, so
	 * we can use one buffer for both.
	 */

	if (t == MAX_TIME)
		return "never;";

	if (t < 0)
		return NULL;

	/* For those lucky enough to have a 128-bit time_t, ensure that
	 * whatever (corrupt) value we're given doesn't exceed the static
	 * buffer.
	 */
#if (MAX_TIME > 0x7fffffffffffffff)
	if (t > 0x7fffffffffffffff)
		return NULL;
#endif

	if (db_time_format == LOCAL_TIME_FORMAT) {
		since_epoch = mktime(localtime(&t));
		if ((strftime(buf1, sizeof(buf1),
			      "# %a %b %d %H:%M:%S %Y",
			      localtime(&t)) == 0) ||
		    (snprintf(buf, sizeof(buf), "epoch %lu; %s",
			      (unsigned long)since_epoch, buf1) >= sizeof(buf)))
			return NULL;

	} else {
		/* No bounds check for the year is necessary - in this case,
		 * strftime() will run out of space and assert an error.
		 */
		if (strftime(buf, sizeof(buf), "%w %Y/%m/%d %H:%M:%S;",
			     gmtime(&t)) == 0)
			return NULL;
	}

	return buf;
}

/* !brief Return the given data as a string of hex digits "xx:xx:xx ..."
 *
 * Converts the given data into a null-terminated, string of hex digits,
 * stored in an allocated buffer.  It is the caller's responsiblity to free
 * the buffer.
 *
 * \param s - pointer to the data to convert
 * \param len - length of the data to convert
 * \param file - source file of invocation
 * \param line - line number of invocation
 *
 * \return Returns an allocated buffer containing the hex string
*/
char *buf_to_hex (const unsigned char *s, unsigned len,
		   const char *file, int line)
{
	unsigned nulen = 0;
	char *buf;

	/* If somebody hands us length of zero, we'll give them
	 * back an empty string */
	if (!len) {
		buf = dmalloc (1, MDL);
		if (buf) {
			*buf = 0x0;
		}

		return (buf);
	}


	/* Figure out how big it needs to be. print_to_hex uses
	 * "%02x:" per character.  Note since there's no trailing colon
	 * we'll have room for the null */
	nulen = (len * 3);

	/* Allocate our buffer */
	buf = dmalloc (nulen, MDL);

	/* Hex-ify it */
	if (buf) {
		print_hex_only (len, s, nulen, buf);
	}

	return buf;
}

/* !brief Formats data into a string based on a lease id format
 *
 * Takes the given data and returns an allocated string whose contents are
 * the string version of that data, formatted according to the output lease
 * id format.  Note it is the caller's responsiblity to delete the string.
 *
 * Currently two formats are supported:
 *
 *  OCTAL - Default or "legacy" CSL format enclosed in quotes '"'.
 *
 *  HEX - Bytes represented as string colon seperated of hex digit pairs
 *  (xx:xx:xx...)
 *
 * \param s - data to convert
 * \param len - length of the data to convert
 * \param format - desired format of the result
 * \param file -  source file of invocation
 * \param line - line number of invocation
 *
 * \return A pointer to the allocated, null-terminated string
*/
char *format_lease_id(const unsigned char *s, unsigned len,
                      int format, const char *file, int line) {
	char *idstr = NULL;

	switch (format) {
		case TOKEN_HEX:
			idstr = buf_to_hex(s, len, MDL);
			break;
		case TOKEN_OCTAL:
		default:
			idstr = quotify_buf(s, len, '"', MDL);
			break;
	}
	return (idstr);
}

/*
 * Convert a relative path name to an absolute path name
 *
 * Not all versions of realpath() support NULL for
 * the second parameter and PATH_MAX isn't defined
 * on all systems.  For the latter, we'll make what
 * ought to be a big enough buffer and let it fly.
 * If passed an absolute path it should return it
 * an allocated buffer.
 */
char *absolute_path(const char *orgpath) {
	char *abspath = NULL;
	if (orgpath) {
#ifdef PATH_MAX
		char buf[PATH_MAX];
#else
		char buf[2048];
#endif
		errno = 0;
                if (realpath(orgpath, buf) == NULL) {
			const char* errmsg = strerror(errno);
                        log_fatal("Failed to get realpath for %s: %s",
				  orgpath, errmsg);
		}

		/* dup the result into an allocated buffer */
		abspath = dmalloc(strlen(buf) + 1, MDL);
		if (abspath == NULL)  {
			log_fatal("No memory for filename:%s\n",
				  buf);
		}

		memcpy (abspath, buf, strlen(buf));
		abspath[strlen(buf)] = 0x0;
	}

	return (abspath);
}
