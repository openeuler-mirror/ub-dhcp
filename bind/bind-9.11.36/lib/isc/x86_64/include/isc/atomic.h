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

/* We share the gcc-version with x86_32 */
#error "impossible case.  check build configuration"

#elif defined(ISC_PLATFORM_USESTDASM)
/*
 * The following are "generic" assembly code which implements the same
 * functionality in case the gcc extension cannot be used.  It should be
 * better to avoid inlining below, since we directly refer to specific
 * registers for arguments, which would not actually correspond to the
 * intended address or value in the embedded mnemonic.
 */

static int32_t
isc_atomic_xadd(int32_t *p, int32_t val) {
	(void)(p);
	(void)(val);

	__asm (
		"movq %rdi, %rdx\n"
		"movl %esi, %eax\n"
#ifdef ISC_PLATFORM_USETHREADS
		"lock;"
#endif
		"xadd %eax, (%rdx)\n"
		/*
		 * XXX: assume %eax will be used as the return value.
		 */
		);
}

#ifdef ISC_PLATFORM_HAVEXADDQ
static int64_t
isc_atomic_xaddq(int64_t *p, int64_t val) {
	(void)(p);
	(void)(val);

	__asm (
		"movq %rdi, %rdx\n"
		"movq %rsi, %rax\n"
#ifdef ISC_PLATFORM_USETHREADS
		"lock;"
#endif
		"xaddq %rax, (%rdx)\n"
		/*
		 * XXX: assume %rax will be used as the return value.
		 */
		);
}
#endif

static void
isc_atomic_store(int32_t *p, int32_t val) {
	(void)(p);
	(void)(val);

	__asm (
		"movq %rdi, %rax\n"
		"movl %esi, %edx\n"
#ifdef ISC_PLATFORM_USETHREADS
		"lock;"
#endif
		"xchgl (%rax), %edx\n"
		);
}

#ifdef ISC_PLATFORM_HAVEATOMICSTOREQ
static void
isc_atomic_storeq(int64_t *p, int64_t val) {
	(void)(p);
	(void)(val);

	__asm (
		"movq %rdi, %rax\n"
		"movq %rsi, %rdx\n"
#ifdef ISC_PLATFORM_USETHREADS
		"lock;"
#endif
		"xchgq (%rax), %rdx\n"
		);
}
#endif

static int32_t
isc_atomic_cmpxchg(int32_t *p, int32_t cmpval, int32_t val) {
	(void)(p);
	(void)(cmpval);
	(void)(val);

	__asm (
		/*
		 * p is %rdi, cmpval is %esi, val is %edx.
		 */
		"movl %edx, %ecx\n"
		"movl %esi, %eax\n"
		"movq %rdi, %rdx\n"

#ifdef ISC_PLATFORM_USETHREADS
		"lock;"
#endif
		/*
		 * If [%rdi] == %eax then [%rdi] := %ecx (equal to %edx
		 * from above), and %eax is untouched (equal to %esi)
		 * from above.
		 *
		 * Else if [%rdi] != %eax then [%rdi] := [%rdi]
		 * (rewritten in write cycle) and %eax := [%rdi].
		 */
		"cmpxchgl %ecx, (%rdx)"
		);
}

#else /* !ISC_PLATFORM_USEGCCASM && !ISC_PLATFORM_USESTDASM */

#error "unsupported compiler.  disable atomic ops by --disable-atomic"

#endif
#endif /* ISC_ATOMIC_H */
