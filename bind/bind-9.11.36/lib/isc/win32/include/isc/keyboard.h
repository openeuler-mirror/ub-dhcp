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


#ifndef ISC_KEYBOARD_H
#define ISC_KEYBOARD_H 1

#include <stdbool.h>

#include <isc/lang.h>
#include <isc/result.h>

ISC_LANG_BEGINDECLS

typedef struct {
	int fd;
	isc_result_t result;
} isc_keyboard_t;

isc_result_t
isc_keyboard_open(isc_keyboard_t *keyboard);

isc_result_t
isc_keyboard_close(isc_keyboard_t *keyboard, unsigned int sleepseconds);

isc_result_t
isc_keyboard_getchar(isc_keyboard_t *keyboard, unsigned char *cp);

bool
isc_keyboard_canceled(isc_keyboard_t *keyboard);

ISC_LANG_ENDDECLS

#endif /* ISC_KEYBOARD_H */
