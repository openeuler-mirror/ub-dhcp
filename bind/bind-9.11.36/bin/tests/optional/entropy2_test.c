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

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <isc/entropy.h>
#include <isc/keyboard.h>
#include <isc/mem.h>
#include <isc/print.h>
#include <isc/string.h>
#include <isc/time.h>
#include <isc/util.h>

static void
hex_dump(const char *msg, void *data, unsigned int length) {
	unsigned int len;
	unsigned char *base;
	bool first = true;

	base = data;

	printf("DUMP of %u bytes:  %s\n\t", length, msg);
	for (len = 0; len < length; len++) {
		if (len % 16 == 0 && !first)
			printf("\n\t");
		printf("%02x ", base[len]);
		first = false;
	}
	printf("\n");
}

static void
CHECK(const char *msg, isc_result_t result) {
	if (result != ISC_R_SUCCESS) {
		printf("FAILURE:  %s:  %s\n", msg, isc_result_totext(result));
		exit(1);
	}
}

static isc_result_t
start(isc_entropysource_t *source, void *arg, bool blocking) {
	isc_keyboard_t *kbd = (isc_keyboard_t *)arg;

	UNUSED(source);

	if (blocking)
		printf("start called, blocking mode.\n");
	else
		printf("start called, non-blocking mode.\n");

	return (isc_keyboard_open(kbd));
}

static void
stop(isc_entropysource_t *source, void *arg) {
	isc_keyboard_t *kbd = (isc_keyboard_t *)arg;

	UNUSED(source);

	printf("ENOUGH!  Stop typing, please.\r\n");

	(void)isc_keyboard_close(kbd, 3);
	printf("stop called\n");
}

static isc_result_t
get(isc_entropysource_t *source, void *arg, bool blocking) {
	isc_keyboard_t *kbd = (isc_keyboard_t *)arg;
	isc_result_t result;
	isc_time_t t;
	uint32_t sample;
	uint32_t extra;
	unsigned char c;

	if (!blocking)
		return (ISC_R_NOENTROPY);

	result = isc_keyboard_getchar(kbd, &c);
	if (result != ISC_R_SUCCESS)
		return (result);

	TIME_NOW(&t);

	sample = isc_time_nanoseconds(&t);
	extra = c;

	result = isc_entropy_addcallbacksample(source, sample, extra);
	if (result != ISC_R_SUCCESS) {
		printf("\r\n");
		return (result);
	}

	printf(".");
	fflush(stdout);

	return (result);
}

int
main(int argc, char **argv) {
	isc_mem_t *mctx;
	unsigned char buffer[512];
	isc_entropy_t *ent;
	isc_entropysource_t *source;
	unsigned int returned;
	unsigned int flags;
	isc_result_t result;
	isc_keyboard_t kbd;

	UNUSED(argc);
	UNUSED(argv);

	mctx = NULL;
	CHECK("isc_mem_create()",
	      isc_mem_create(0, 0, &mctx));

	ent = NULL;
	CHECK("isc_entropy_create()",
	      isc_entropy_create(mctx, &ent));

	isc_entropy_stats(ent, stderr);

	source = NULL;
	result = isc_entropy_createcallbacksource(ent, start, get, stop, &kbd,
						  &source);
	CHECK("isc_entropy_createcallbacksource()", result);

	fprintf(stderr,
		"Reading 32 bytes of GOOD random data only, partial OK\n");

	flags = 0;
	flags |= ISC_ENTROPY_GOODONLY;
	flags |= ISC_ENTROPY_PARTIAL;
	flags |= ISC_ENTROPY_BLOCKING;
	returned = 0;
	result = isc_entropy_getdata(ent, buffer, 32, &returned, flags);
	if (result == ISC_R_NOENTROPY) {
		fprintf(stderr, "No entropy.\r\n");
	}

	isc_entropy_stopcallbacksources(ent);

	hex_dump("good data only:", buffer, returned);

	isc_entropy_stats(ent, stderr);

	isc_entropy_destroysource(&source);
	isc_entropy_detach(&ent);

	isc_mem_stats(mctx, stderr);
	isc_mem_destroy(&mctx);

	return (0);
}
