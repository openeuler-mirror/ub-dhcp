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

#include <string.h>

#include <isc/buffer.h>
#include <isc/region.h>
#include <isc/sha1.h>
#include <isc/sha2.h>
#include <isc/util.h>

#include <dns/ds.h>
#include <dns/fixedname.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdatastruct.h>
#include <dns/result.h>

#include <dst/dst.h>

#if defined(HAVE_OPENSSL_GOST) || defined(HAVE_PKCS11_GOST)
#include "dst_gost.h"
#endif

isc_result_t
dns_ds_buildrdata(dns_name_t *owner, dns_rdata_t *key,
		  dns_dsdigest_t digest_type, unsigned char *buffer,
		  dns_rdata_t *rdata)
{
	dns_fixedname_t fname;
	dns_name_t *name;
	unsigned char digest[ISC_SHA384_DIGESTLENGTH];
	isc_region_t r;
	isc_buffer_t b;
	dns_rdata_ds_t ds;
	isc_sha1_t sha1;
	isc_sha256_t sha256;
	isc_sha384_t sha384;
#if defined(HAVE_OPENSSL_GOST) || defined(HAVE_PKCS11_GOST)
	isc_gost_t gost;
#endif

	REQUIRE(key != NULL);
	REQUIRE(key->type == dns_rdatatype_dnskey);

	if (!dst_ds_digest_supported(digest_type))
		return (ISC_R_NOTIMPLEMENTED);

	name = dns_fixedname_initname(&fname);
	(void)dns_name_downcase(owner, name, NULL);

	memset(buffer, 0, DNS_DS_BUFFERSIZE);
	isc_buffer_init(&b, buffer, DNS_DS_BUFFERSIZE);

	switch (digest_type) {
	case DNS_DSDIGEST_SHA1:
		isc_sha1_init(&sha1);
		dns_name_toregion(name, &r);
		isc_sha1_update(&sha1, r.base, r.length);
		dns_rdata_toregion(key, &r);
		INSIST(r.length >= 4);
		isc_sha1_update(&sha1, r.base, r.length);
		isc_sha1_final(&sha1, digest);
		break;

#if defined(HAVE_OPENSSL_GOST) || defined(HAVE_PKCS11_GOST)
#define RETERR(x) do {					\
	isc_result_t ret = (x);				\
	if (ret != ISC_R_SUCCESS) {			\
		isc_gost_invalidate(&gost);		\
		return (ret);				\
	}						\
} while (0)

	case DNS_DSDIGEST_GOST:
		RETERR(isc_gost_init(&gost));
		dns_name_toregion(name, &r);
		RETERR(isc_gost_update(&gost, r.base, r.length));
		dns_rdata_toregion(key, &r);
		INSIST(r.length >= 4);
		RETERR(isc_gost_update(&gost, r.base, r.length));
		RETERR(isc_gost_final(&gost, digest));
		break;
#endif

	case DNS_DSDIGEST_SHA384:
		isc_sha384_init(&sha384);
		dns_name_toregion(name, &r);
		isc_sha384_update(&sha384, r.base, r.length);
		dns_rdata_toregion(key, &r);
		INSIST(r.length >= 4);
		isc_sha384_update(&sha384, r.base, r.length);
		isc_sha384_final(digest, &sha384);
		break;

	case DNS_DSDIGEST_SHA256:
		isc_sha256_init(&sha256);
		dns_name_toregion(name, &r);
		isc_sha256_update(&sha256, r.base, r.length);
		dns_rdata_toregion(key, &r);
		INSIST(r.length >= 4);
		isc_sha256_update(&sha256, r.base, r.length);
		isc_sha256_final(digest, &sha256);
		break;

	default:
		INSIST(0);
		ISC_UNREACHABLE();
	}

	ds.mctx = NULL;
	ds.common.rdclass = key->rdclass;
	ds.common.rdtype = dns_rdatatype_ds;
	ds.algorithm = r.base[3];
	ds.key_tag = dst_region_computeid(&r, ds.algorithm);
	ds.digest_type = digest_type;
	switch (digest_type) {
	case DNS_DSDIGEST_SHA1:
		ds.length = ISC_SHA1_DIGESTLENGTH;
		break;

#if defined(HAVE_OPENSSL_GOST) || defined(HAVE_PKCS11_GOST)
	case DNS_DSDIGEST_GOST:
		ds.length = ISC_GOST_DIGESTLENGTH;
		break;
#endif

	case DNS_DSDIGEST_SHA384:
		ds.length = ISC_SHA384_DIGESTLENGTH;
		break;

	case DNS_DSDIGEST_SHA256:
	default:
		ds.length = ISC_SHA256_DIGESTLENGTH;
		break;
	}
	ds.digest = digest;

	return (dns_rdata_fromstruct(rdata, key->rdclass, dns_rdatatype_ds,
				     &ds, &b));
}
