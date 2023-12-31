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
 * Copyright (c) 1998 Doug Rabson
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
 * $FreeBSD: src/sys/alpha/include/atomic.h,v 1.18.6.1 2004/09/13 21:52:04 wilko Exp $
 */

#ifndef ISC_ATOMIC_H
#define ISC_ATOMIC_H 1

#include <inttypes.h>

#include <isc/platform.h>
#include <isc/types.h>

#ifdef ISC_PLATFORM_USEOSFASM
#include <c_asm.h>

#pragma intrinsic(asm)

/*
 * This routine atomically increments the value stored in 'p' by 'val', and
 * returns the previous value.  Memory access ordering around this function
 * can be critical, so we add explicit memory block instructions at the
 * beginning and the end of it (same for other functions).
 */
static inline int32_t
isc_atomic_xadd(int32_t *p, int32_t val) {
	return (asm("mb;"
		    "1:"
		    "ldl_l %t0, 0(%a0);"	/* load old value */
		    "mov %t0, %v0;"		/* copy the old value */
		    "addl %t0, %a1, %t0;"	/* calculate new value */
		    "stl_c %t0, 0(%a0);"	/* attempt to store */
		    "beq %t0, 1b;"		/* spin if failed */
		    "mb;",
		    p, val));
}

/*
 * This routine atomically stores the value 'val' in 'p'.
 */
static inline void
isc_atomic_store(int32_t *p, int32_t val) {
	(void)asm("mb;"
		  "1:"
		  "ldl_l %t0, 0(%a0);"		/* load old value */
		  "mov %a1, %t0;"		/* value to store */
		  "stl_c %t0, 0(%a0);"		/* attempt to store */
		  "beq %t0, 1b;"		/* spin if failed */
		  "mb;",
		  p, val);
}

/*
 * This routine atomically replaces the value in 'p' with 'val', if the
 * original value is equal to 'cmpval'.  The original value is returned in any
 * case.
 */
static inline int32_t
isc_atomic_cmpxchg(int32_t *p, int32_t cmpval, int32_t val) {

	return(asm("mb;"
		   "1:"
		   "ldl_l %t0, 0(%a0);"		/* load old value */
		   "mov %t0, %v0;"		/* copy the old value */
		   "cmpeq %t0, %a1, %t0;"	/* compare */
		   "beq %t0, 2f;"		/* exit if not equal */
		   "mov %a2, %t0;"		/* value to store */
		   "stl_c %t0, 0(%a0);"		/* attempt to store */
		   "beq %t0, 1b;"		/* if it failed, spin */
		   "2:"
		   "mb;",
		   p, cmpval, val));
}
#elif defined (ISC_PLATFORM_USEGCCASM)
static inline int32_t
isc_atomic_xadd(int32_t *p, int32_t val) {
	int32_t temp, prev;

	__asm__ volatile(
		"mb;"
		"1:"
		"ldl_l %0, %1;"			/* load old value */
		"mov %0, %2;"			/* copy the old value */
		"addl %0, %3, %0;"		/* calculate new value */
		"stl_c %0, %1;"			/* attempt to store */
		"beq %0, 1b;"			/* spin if failed */
		"mb;"
		: "=&r"(temp), "+m"(*p), "=&r"(prev)
		: "r"(val)
		: "memory");

	return (prev);
}

static inline void
isc_atomic_store(int32_t *p, int32_t val) {
	int32_t temp;

	__asm__ volatile(
		"mb;"
		"1:"
		"ldl_l %0, %1;"			/* load old value */
		"mov %2, %0;"			/* value to store */
		"stl_c %0, %1;"			/* attempt to store */
		"beq %0, 1b;"			/* if it failed, spin */
		"mb;"
		: "=&r"(temp), "+m"(*p)
		: "r"(val)
		: "memory");
}

static inline int32_t
isc_atomic_cmpxchg(int32_t *p, int32_t cmpval, int32_t val) {
	int32_t temp, prev;

	__asm__ volatile(
		"mb;"
		"1:"
		"ldl_l %0, %1;"			/* load old value */
		"mov %0, %2;"			/* copy the old value */
		"cmpeq %0, %3, %0;"		/* compare */
		"beq %0, 2f;"			/* exit if not equal */
		"mov %4, %0;"			/* value to store */
		"stl_c %0, %1;"			/* attempt to store */
		"beq %0, 1b;"			/* if it failed, spin */
		"2:"
		"mb;"
		: "=&r"(temp), "+m"(*p), "=&r"(prev)
		: "r"(cmpval), "r"(val)
		: "memory");

	return (prev);
}
#else

#error "unsupported compiler.  disable atomic ops by --disable-atomic"

#endif

#endif /* ISC_ATOMIC_H */
