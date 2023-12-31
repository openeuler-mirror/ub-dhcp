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


#ifndef ISC_ATOMIC_H
#define ISC_ATOMIC_H 1

#include <inttypes.h>

#include <isc/platform.h>
#include <isc/types.h>

#ifdef ISC_PLATFORM_USEGCCASM
/*
 * This routine atomically increments the value stored in 'p' by 'val', and
 * returns the previous value.
 */
static __inline__ int32_t
isc_atomic_xadd(int32_t *p, int32_t val) {
	int32_t prev = val;

	__asm__ volatile(
#ifdef ISC_PLATFORM_USETHREADS
		"lock;"
#endif
		"xadd %0, %1"
		:"=q"(prev)
		:"m"(*p), "0"(prev)
		:"memory", "cc");

	return (prev);
}

#ifdef ISC_PLATFORM_HAVEXADDQ
static __inline__ int64_t
isc_atomic_xaddq(int64_t *p, int64_t val) {
	int64_t prev = val;

	__asm__ volatile(
#ifdef ISC_PLATFORM_USETHREADS
	    "lock;"
#endif
	    "xaddq %0, %1"
	    :"=q"(prev)
	    :"m"(*p), "0"(prev)
	    :"memory", "cc");

	return (prev);
}
#endif /* ISC_PLATFORM_HAVEXADDQ */

/*
 * This routine atomically stores the value 'val' in 'p' (32-bit version).
 */
static __inline__ void
isc_atomic_store(int32_t *p, int32_t val) {
	__asm__ volatile(
#ifdef ISC_PLATFORM_USETHREADS
		/*
		 * xchg should automatically lock memory, but we add it
		 * explicitly just in case (it at least doesn't harm)
		 */
		"lock;"
#endif

		"xchgl %1, %0"
		:
		: "r"(val), "m"(*p)
		: "memory");
}

#ifdef ISC_PLATFORM_HAVEATOMICSTOREQ
/*
 * This routine atomically stores the value 'val' in 'p' (64-bit version).
 */
static __inline__ void
isc_atomic_storeq(int64_t *p, int64_t val) {
	__asm__ volatile(
#ifdef ISC_PLATFORM_USETHREADS
		/*
		 * xchg should automatically lock memory, but we add it
		 * explicitly just in case (it at least doesn't harm)
		 */
		"lock;"
#endif

		"xchgq %1, %0"
		:
		: "r"(val), "m"(*p)
		: "memory");
}
#endif /* ISC_PLATFORM_HAVEATOMICSTOREQ */

/*
 * This routine atomically replaces the value in 'p' with 'val', if the
 * original value is equal to 'cmpval'.  The original value is returned in any
 * case.
 */
static __inline__ int32_t
isc_atomic_cmpxchg(int32_t *p, int32_t cmpval, int32_t val) {
	__asm__ volatile(
#ifdef ISC_PLATFORM_USETHREADS
		"lock;"
#endif
		"cmpxchgl %1, %2"
		: "=a"(cmpval)
		: "r"(val), "m"(*p), "a"(cmpval)
		: "memory");

	return (cmpval);
}

#elif defined(ISC_PLATFORM_USESTDASM)
/*
 * The following are "generic" assembly code which implements the same
 * functionality in case the gcc extension cannot be used.  It should be
 * better to avoid inlining below, since we directly refer to specific
 * positions of the stack frame, which would not actually point to the
 * intended address in the embedded mnemonic.
 */
static int32_t
isc_atomic_xadd(int32_t *p, int32_t val) {
	(void)(p);
	(void)(val);

	__asm (
		"movl 8(%ebp), %ecx\n"
		"movl 12(%ebp), %edx\n"
#ifdef ISC_PLATFORM_USETHREADS
		"lock;"
#endif
		"xadd %edx, (%ecx)\n"

		/*
		 * set the return value directly in the register so that we
		 * can avoid guessing the correct position in the stack for a
		 * local variable.
		 */
		"movl %edx, %eax"
		);
}

static void
isc_atomic_store(int32_t *p, int32_t val) {
	(void)(p);
	(void)(val);

	__asm (
		"movl 8(%ebp), %ecx\n"
		"movl 12(%ebp), %edx\n"
#ifdef ISC_PLATFORM_USETHREADS
		"lock;"
#endif
		"xchgl (%ecx), %edx\n"
		);
}

static int32_t
isc_atomic_cmpxchg(int32_t *p, int32_t cmpval, int32_t val) {
	(void)(p);
	(void)(cmpval);
	(void)(val);

	__asm (
		"movl 8(%ebp), %ecx\n"
		"movl 12(%ebp), %eax\n"	/* must be %eax for cmpxchgl */
		"movl 16(%ebp), %edx\n"
#ifdef ISC_PLATFORM_USETHREADS
		"lock;"
#endif

		/*
		 * If (%ecx) == %eax then (%ecx) := %edx.
		 % %eax is set to old (%ecx), which will be the return value.
		 */
		"cmpxchgl %edx, (%ecx)"
		);
}
#else /* !ISC_PLATFORM_USEGCCASM && !ISC_PLATFORM_USESTDASM */

#error "unsupported compiler.  disable atomic ops by --disable-atomic"

#endif
#endif /* ISC_ATOMIC_H */
