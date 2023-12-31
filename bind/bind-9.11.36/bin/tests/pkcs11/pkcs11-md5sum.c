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
 * Portions copyright (c) 2008 Nominet UK.  All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * pkcs11-md5sum
 *
 * Prints the MD5 checksum of the standard input, using the PKCS#11 device.
 *
 * Usage:
 * pkcs11-md5sum [-m module] [-s $slot] [-n] [-p $pin]
 *  -m: PKCS#11 provider module.  This must be the full
 *      path to a shared library object implementing the
 *      PKCS#11 API for a device.
 *  -s: Slot
 *  -p: PIN
 *  -n: don't log in to the PKCS#11 device
 */

/*! \file */

#include <config.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>

#include <isc/commandline.h>
#include <isc/print.h>
#include <isc/result.h>
#include <isc/types.h>

#include <pk11/pk11.h>
#include <pk11/result.h>

#if !(defined(HAVE_GETPASSPHRASE) || (defined (__SVR4) && defined (__sun)))
#define getpassphrase(x)	getpass(x)
#endif

#define BLOCKSIZE	32768

char buffer[BLOCKSIZE + 72];
char digest[16];

int
main(int argc, char *argv[]) {
	isc_result_t result;
	CK_RV rv;
	CK_SLOT_ID slot = 0;
	CK_SESSION_HANDLE hSession;
	CK_MECHANISM mech = { CKM_MD5, NULL, 0 };
	CK_ULONG len;
	pk11_context_t pctx;
	pk11_optype_t op_type = OP_DIGEST;
	char *lib_name = NULL;
	char *pin = NULL;
	int error = 0;
	bool logon = true;
	int c, errflg = 0;
	size_t sum = 0;
	unsigned int i;

	while ((c = isc_commandline_parse(argc, argv, ":m:s:np:")) != -1) {
		switch (c) {
		case 'm':
			lib_name = isc_commandline_argument;
			break;
		case 's':
			slot = atoi(isc_commandline_argument);
			op_type = OP_ANY;
			break;
		case 'n':
			logon = false;
			break;
		case 'p':
			pin = isc_commandline_argument;
			break;
		case ':':
			fprintf(stderr,
				"Option -%c requires an operand\n",
				isc_commandline_option);
			errflg++;
			break;
		case '?':
		default:
			fprintf(stderr, "Unrecognised option: -%c\n",
				isc_commandline_option);
			errflg++;
		}
	}

	if (errflg) {
		fprintf(stderr, "Usage:\n");
		fprintf(stderr,
			"\tpkcs11-md5sum [-m module] [-s slot] [-n|-p pin]\n");
		exit(1);
	}

	pk11_result_register();

	/* Initialize the CRYPTOKI library */
	if (lib_name != NULL)
		pk11_set_lib_name(lib_name);

	if (logon && pin == NULL)
		pin = getpassphrase("Enter Pin: ");

	result = pk11_get_session(&pctx, op_type, false, false, logon,
				  (const char *) pin, slot);
	if ((result != ISC_R_SUCCESS) &&
	    (result != PK11_R_NORANDOMSERVICE) &&
	    (result != PK11_R_NOAESSERVICE)) {
		fprintf(stderr, "Error initializing PKCS#11: %s\n",
			isc_result_totext(result));
		exit(1);
	}

	if (pin != NULL)
		memset(pin, 0, strlen((char *)pin));

	hSession = pctx.session;

	rv = pkcs_C_DigestInit(hSession, &mech);
	if (rv != CKR_OK) {
		fprintf(stderr, "C_DigestInit: Error = 0x%.8lX\n", rv);
		error = 1;
		goto exit_session;
	}

	for (;;) {
		size_t n;

		for (;;) {
			n = fread(buffer + sum, 1, BLOCKSIZE - sum, stdin);
			sum += n;
			if (sum == BLOCKSIZE)
				break;
			if (n == 0) {
				if (ferror(stdin)) {
					fprintf(stderr, "fread failed\n");
					error = 1;
					goto exit_session;
				}
				goto partial_block;
			}
			if (feof(stdin))
				goto partial_block;
		}

		rv = pkcs_C_DigestUpdate(hSession, (CK_BYTE_PTR) buffer,
					 (CK_ULONG) BLOCKSIZE);
		if (rv != CKR_OK) {
			fprintf(stderr,
				"C_DigestUpdate: Error = 0x%.8lX\n",
				rv);
			error = 1;
			goto exit_session;
		}
	}

partial_block:
	if (sum > 0) {
		rv = pkcs_C_DigestUpdate(hSession, (CK_BYTE_PTR) buffer,
					 (CK_ULONG) sum);
		if (rv != CKR_OK) {
			fprintf(stderr,
				"C_DigestUpdate: Error = 0x%.8lX\n",
				rv);
			error = 1;
			goto exit_session;
		}
	}

	len = 16;
	rv = pkcs_C_DigestFinal(hSession, (CK_BYTE_PTR) digest, &len);
	if (rv != CKR_OK) {
		fprintf(stderr, "C_DigestFinal: Error = 0x%.8lX\n", rv);
		error = 1;
		goto exit_session;
	}
	if (len != 16) {
		fprintf(stderr, "C_DigestFinal: bad length = %lu\n", len);
		error = 1;
	}

	for (i = 0; i < 16; i++)
		printf("%02x", digest[i] & 0xff);
	printf("\n");

    exit_session:
	pk11_return_session(&pctx);
	(void) pk11_finalize();

	exit(error);
}
