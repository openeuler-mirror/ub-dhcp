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


/*
 * This code was written based on FreeBSD's kernel source whose copyright
 * follows:
 */

/*-
 * Copyright (c) 1998 Doug Rabson.
 * Copyright (c) 2001 Jake Burkholder.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	from: FreeBSD: src/sys/i386/include/atomic.h,v 1.20 2001/02/11
 * $FreeBSD: src/sys/sparc64/include/atomic.h,v 1.8 2004/05/22 00:52:16 marius Exp $
 */

#ifndef ISC_ATOMIC_H
#define ISC_ATOMIC_H 1

#include <inttypes.h>

#include <isc/platform.h>
#include <isc/types.h>

#define	ASI_P	0x80		/* Primary Address Space Identifier */

#ifdef ISC_PLATFORM_USEGCCASM

/*
 * This routine atomically increments the value stored in 'p' by 'val', and
 * returns the previous value.
 */
static inline int32_t
isc_atomic_xadd(int32_t *p, int32_t val) {
	int32_t prev, swapped;

	for (prev = *(volatile int32_t *)p; ; prev = swapped) {
		swapped = prev + val;
		__asm__ volatile(
			"casa [%2] %3, %4, %0"
			: "+r"(swapped), "=m"(*p)
			: "r"(p), "n"(ASI_P), "r"(prev), "m"(*p));
		if (swapped == prev)
			break;
	}

	return (prev);
}

/*
 * This routine atomically stores the value 'val' in 'p'.
 */
static inline void
isc_atomic_store(int32_t *p, int32_t val) {
	int32_t prev, swapped;

	for (prev = *(volatile int32_t *)p; ; prev = swapped) {
		swapped = val;
		__asm__ volatile(
			"casa [%2] %3, %4, %0"
			: "+r"(swapped), "=m"(*p)
			: "r"(p), "n"(ASI_P), "r"(prev), "m"(*p));
		if (swapped == prev)
			break;
	}
}

/*
 * This routine atomically replaces the value in 'p' with 'val', if the
 * original value is equal to 'cmpval'.  The original value is returned in any
 * case.
 */
static inline int32_t
isc_atomic_cmpxchg(int32_t *p, int32_t cmpval, int32_t val) {
	int32_t temp = val;

	__asm__ volatile(
		"casa [%2] %3, %4, %0"
		: "+r"(temp), "=m"(*p)
		: "r"(p), "n"(ASI_P), "r"(cmpval), "m"(*p));

	return (temp);
}

#else  /* ISC_PLATFORM_USEGCCASM */

#error "unsupported compiler.  disable atomic ops by --disable-atomic"

#endif /* ISC_PLATFORM_USEGCCASM */

#endif /* ISC_ATOMIC_H */
