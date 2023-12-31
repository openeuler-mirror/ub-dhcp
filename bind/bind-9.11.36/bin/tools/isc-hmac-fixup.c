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

#include <config.h>

#include <isc/base64.h>
#include <isc/buffer.h>
#include <isc/md5.h>
#include <isc/print.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/sha1.h>
#include <isc/sha2.h>
#include <isc/stdio.h>
#include <isc/string.h>

#include <pk11/site.h>

#define HMAC_LEN	64

int
main(int argc, char **argv)  {
	isc_buffer_t buf;
	unsigned char key[1024];
	char secret[1024];
	char base64[(1024*4)/3];
	isc_region_t r;
	isc_result_t result;

	if (argc != 3) {
		fprintf(stderr, "Usage:\t%s algorithm secret\n", argv[0]);
#ifndef PK11_MD5_DISABLE
		fprintf(stderr, "\talgorithm: (MD5 | SHA1 | SHA224 | "
				"SHA256 | SHA384 | SHA512)\n");
#else
		fprintf(stderr, "\talgorithm: (SHA1 | SHA224 | "
				"SHA256 | SHA384 | SHA512)\n");
#endif
		return (1);
	}

	isc_buffer_init(&buf, secret, sizeof(secret));
	result = isc_base64_decodestring(argv[2], &buf);
	if (result != ISC_R_SUCCESS) {
		fprintf(stderr, "error: %s\n", isc_result_totext(result));
		return (1);
	}
	isc_buffer_usedregion(&buf, &r);

#ifndef PK11_MD5_DISABLE
	if (!strcasecmp(argv[1], "md5") ||
	    !strcasecmp(argv[1], "hmac-md5")) {
		if (r.length > HMAC_LEN) {
			isc_md5_t md5ctx;
			isc_md5_init(&md5ctx);
			isc_md5_update(&md5ctx, r.base, r.length);
			isc_md5_final(&md5ctx, key);

			r.base = key;
			r.length = ISC_MD5_DIGESTLENGTH;
		}
	} else
#endif
	if (!strcasecmp(argv[1], "sha1") ||
		   !strcasecmp(argv[1], "hmac-sha1")) {
		if (r.length > ISC_SHA1_DIGESTLENGTH) {
			isc_sha1_t sha1ctx;
			isc_sha1_init(&sha1ctx);
			isc_sha1_update(&sha1ctx, r.base, r.length);
			isc_sha1_final(&sha1ctx, key);

			r.base = key;
			r.length = ISC_SHA1_DIGESTLENGTH;
		}
	} else if (!strcasecmp(argv[1], "sha224") ||
		   !strcasecmp(argv[1], "hmac-sha224")) {
		if (r.length > ISC_SHA224_DIGESTLENGTH) {
			isc_sha224_t sha224ctx;
			isc_sha224_init(&sha224ctx);
			isc_sha224_update(&sha224ctx, r.base, r.length);
			isc_sha224_final(key, &sha224ctx);

			r.base = key;
			r.length = ISC_SHA224_DIGESTLENGTH;
		}
	} else if (!strcasecmp(argv[1], "sha256") ||
		   !strcasecmp(argv[1], "hmac-sha256")) {
		if (r.length > ISC_SHA256_DIGESTLENGTH) {
			isc_sha256_t sha256ctx;
			isc_sha256_init(&sha256ctx);
			isc_sha256_update(&sha256ctx, r.base, r.length);
			isc_sha256_final(key, &sha256ctx);

			r.base = key;
			r.length = ISC_SHA256_DIGESTLENGTH;
		}
	} else if (!strcasecmp(argv[1], "sha384") ||
		   !strcasecmp(argv[1], "hmac-sha384")) {
		if (r.length > ISC_SHA384_DIGESTLENGTH) {
			isc_sha384_t sha384ctx;
			isc_sha384_init(&sha384ctx);
			isc_sha384_update(&sha384ctx, r.base, r.length);
			isc_sha384_final(key, &sha384ctx);

			r.base = key;
			r.length = ISC_SHA384_DIGESTLENGTH;
		}
	} else if (!strcasecmp(argv[1], "sha512") ||
		   !strcasecmp(argv[1], "hmac-sha512")) {
		if (r.length > ISC_SHA512_DIGESTLENGTH) {
			isc_sha512_t sha512ctx;
			isc_sha512_init(&sha512ctx);
			isc_sha512_update(&sha512ctx, r.base, r.length);
			isc_sha512_final(key, &sha512ctx);

			r.base = key;
			r.length = ISC_SHA512_DIGESTLENGTH;
		}
	} else {
		fprintf(stderr, "unknown hmac/digest algorithm: %s\n", argv[1]);
		return (1);
	}

	isc_buffer_init(&buf, base64, sizeof(base64));
	result = isc_base64_totext(&r, 0, "", &buf);
	if (result != ISC_R_SUCCESS) {
		fprintf(stderr, "error: %s\n", isc_result_totext(result));
		return (1);
	}
	fprintf(stdout, "%.*s\n", (int)isc_buffer_usedlength(&buf), base64);
	return (0);
}
