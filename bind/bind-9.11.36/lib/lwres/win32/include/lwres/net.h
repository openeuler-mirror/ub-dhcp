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

#ifndef LWRES_NET_H
#define LWRES_NET_H 1

/*****
 ***** Module Info
 *****/

/*
 * Basic Networking Types
 *
 * This module is responsible for defining the following basic networking
 * types:
 *
 *		struct in_addr
 *		struct in6_addr
 *		struct sockaddr
 *		struct sockaddr_in
 *		struct sockaddr_in6
 *
 * It ensures that the AF_ and PF_ macros are defined.
 *
 * It declares ntoh[sl]() and hton[sl]().
 *
 * It declares lwres_net_aton(), lwres_net_ntop(), and lwres_net_pton().
 *
 * It ensures that INADDR_LOOPBACK, INADDR_ANY and IN6ADDR_ANY_INIT
 * are defined.
 */

/***
 *** Imports.
 ***/

/*
 * Because of some sort of problem in the MS header files, this cannot
 * be simple "#include <winsock2.h>", because winsock2.h tries to include
 * windows.h, which then generates an error out of mswsock.h.  _You_
 * figure it out.
 */
#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_   /* Prevent inclusion of winsock.h in windows.h */
#endif

#include <winsock2.h>
#include <sys/types.h>

#include <lwres/ipv6.h>
#include <lwres/platform.h>	/* Required for LWRES_PLATFORM_*. */

#include <lwres/lang.h>

#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK 0x7f000001UL
#endif
/*
 * Fix the FD_SET and FD_CLR Macros to properly cast
 */
#undef FD_CLR
#define FD_CLR(fd, set) do { \
    u_int __i; \
    for (__i = 0; __i < ((fd_set FAR *)(set))->fd_count; __i++) { \
	if (((fd_set FAR *)(set))->fd_array[__i] == (SOCKET) fd) { \
	    while (__i < ((fd_set FAR *)(set))->fd_count-1) { \
		((fd_set FAR *)(set))->fd_array[__i] = \
		    ((fd_set FAR *)(set))->fd_array[__i+1]; \
		__i++; \
	    } \
	    ((fd_set FAR *)(set))->fd_count--; \
	    break; \
	} \
    } \
} while (0)

#undef FD_SET
#define FD_SET(fd, set) do { \
    u_int __i; \
    for (__i = 0; __i < ((fd_set FAR *)(set))->fd_count; __i++) { \
	if (((fd_set FAR *)(set))->fd_array[__i] == (SOCKET)(fd)) { \
	    break; \
	} \
    } \
    if (__i == ((fd_set FAR *)(set))->fd_count) { \
	if (((fd_set FAR *)(set))->fd_count < FD_SETSIZE) { \
	    ((fd_set FAR *)(set))->fd_array[__i] = (SOCKET)(fd); \
	    ((fd_set FAR *)(set))->fd_count++; \
	} \
    } \
} while (0)

/*
 * Windows Sockets errors redefined as regular Berkeley error constants.
 * These are usually commented out in Windows NT to avoid conflicts with errno.h.
 * Use the WSA constants instead.
 */

#include <errno.h>

#ifndef EWOULDBLOCK
#define EWOULDBLOCK             WSAEWOULDBLOCK
#endif
#ifndef EINPROGRESS
#define EINPROGRESS             WSAEINPROGRESS
#endif
#ifndef EALREADY
#define EALREADY                WSAEALREADY
#endif
#ifndef ENOTSOCK
#define ENOTSOCK                WSAENOTSOCK
#endif
#ifndef EDESTADDRREQ
#define EDESTADDRREQ            WSAEDESTADDRREQ
#endif
#ifndef EMSGSIZE
#define EMSGSIZE                WSAEMSGSIZE
#endif
#ifndef EPROTOTYPE
#define EPROTOTYPE              WSAEPROTOTYPE
#endif
#ifndef ENOPROTOOPT
#define ENOPROTOOPT             WSAENOPROTOOPT
#endif
#ifndef EPROTONOSUPPORT
#define EPROTONOSUPPORT         WSAEPROTONOSUPPORT
#endif
#ifndef ESOCKTNOSUPPORT
#define ESOCKTNOSUPPORT         WSAESOCKTNOSUPPORT
#endif
#ifndef EOPNOTSUPP
#define EOPNOTSUPP              WSAEOPNOTSUPP
#endif
#ifndef EPFNOSUPPORT
#define EPFNOSUPPORT            WSAEPFNOSUPPORT
#endif
#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT            WSAEAFNOSUPPORT
#endif
#ifndef EADDRINUSE
#define EADDRINUSE              WSAEADDRINUSE
#endif
#ifndef EADDRNOTAVAIL
#define EADDRNOTAVAIL           WSAEADDRNOTAVAIL
#endif
#ifndef ENETDOWN
#define ENETDOWN                WSAENETDOWN
#endif
#ifndef ENETUNREACH
#define ENETUNREACH             WSAENETUNREACH
#endif
#ifndef ENETRESET
#define ENETRESET               WSAENETRESET
#endif
#ifndef ECONNABORTED
#define ECONNABORTED            WSAECONNABORTED
#endif
#ifndef ECONNRESET
#define ECONNRESET              WSAECONNRESET
#endif
#ifndef ENOBUFS
#define ENOBUFS                 WSAENOBUFS
#endif
#ifndef EISCONN
#define EISCONN                 WSAEISCONN
#endif
#ifndef ENOTCONN
#define ENOTCONN                WSAENOTCONN
#endif
#ifndef ESHUTDOWN
#define ESHUTDOWN               WSAESHUTDOWN
#endif
#ifndef ETOOMANYREFS
#define ETOOMANYREFS            WSAETOOMANYREFS
#endif
#ifndef ETIMEDOUT
#define ETIMEDOUT               WSAETIMEDOUT
#endif
#ifndef ECONNREFUSED
#define ECONNREFUSED            WSAECONNREFUSED
#endif
#ifndef ELOOP
#define ELOOP                   WSAELOOP
#endif
#ifndef EHOSTDOWN
#define EHOSTDOWN               WSAEHOSTDOWN
#endif
#ifndef EHOSTUNREACH
#define EHOSTUNREACH            WSAEHOSTUNREACH
#endif
#ifndef EPROCLIM
#define EPROCLIM                WSAEPROCLIM
#endif
#ifndef EUSERS
#define EUSERS                  WSAEUSERS
#endif
#ifndef EDQUOT
#define EDQUOT                  WSAEDQUOT
#endif
#ifndef ESTALE
#define ESTALE                  WSAESTALE
#endif
#ifndef EREMOTE
#define EREMOTE                 WSAEREMOTE
#endif

LWRES_LANG_BEGINDECLS

const char *
lwres_net_ntop(int af, const void *src, char *dst, size_t size);

int
lwres_net_pton(int af, const char *src, void *dst);

int
lwres_net_aton(const char *cp, struct in_addr *addr);

LWRES_LANG_ENDDECLS

#endif /* LWRES_NET_H */
