/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */
#include <config.h>

#include <stdio.h>

#include <isc/net.h>
#include <isc/print.h>

#include <lwres/netdb.h>

static void
print_he(struct hostent *he, int error, const char *fun, const char *name) {
	char **c;
	int i;

	if (he != NULL) {
		 printf("%s(%s):\n", fun, name);
		 printf("\tname = %s\n", he->h_name);
		 printf("\taddrtype = %d\n", he->h_addrtype);
		 printf("\tlength = %d\n", he->h_length);
		 c = he->h_aliases;
		 i = 1;
		 while (*c != NULL) {
			printf("\talias[%d] = %s\n", i, *c);
			i++;
			c++;
		 }
		 c = he->h_addr_list;
		 i = 1;
		 while (*c != NULL) {
			char buf[128];
			inet_ntop(he->h_addrtype, *c, buf, sizeof(buf));
			printf("\taddress[%d] = %s\n", i, buf);
			c++;
			i++;
		}
	} else {
		printf("%s(%s): error = %d (%s)\n", fun, name, error,
		       hstrerror(error));
	}
}

int
main(int argc, char **argv) {
	struct hostent *he;
	int error;
	struct in_addr in_addr;
	struct in6_addr in6_addr;
	void *addr;
	int af;
	size_t len;

	(void)argc;

	while (argv[1] != NULL) {
		if (inet_pton(AF_INET, argv[1], &in_addr) == 1) {
			af = AF_INET;
			addr = &in_addr;
			len = sizeof(in_addr);
		} else if (inet_pton(AF_INET6, argv[1], &in6_addr) == 1) {
			af = AF_INET6;
			addr = &in6_addr;
			len = sizeof(in6_addr);
		} else {
			printf("unable to convert \"%s\" to an address\n",
			       argv[1]);
			argv++;
			continue;
		}
		he = gethostbyaddr(addr, len, af);
		print_he(he, h_errno, "gethostbyaddr", argv[1]);

		he = getipnodebyaddr(addr, len, af, &error);
		print_he(he, error, "getipnodebyaddr", argv[1]);
		if (he != NULL)
			freehostent(he);
		argv++;
	}
	return (0);
}
