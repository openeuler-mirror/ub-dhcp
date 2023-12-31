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

#ifndef RDATA_GENERIC_NULL_10_C
#define RDATA_GENERIC_NULL_10_C

#define RRTYPE_NULL_ATTRIBUTES (0)

static inline isc_result_t
fromtext_null(ARGS_FROMTEXT) {
	REQUIRE(type == dns_rdatatype_null);

	UNUSED(rdclass);
	UNUSED(type);
	UNUSED(lexer);
	UNUSED(origin);
	UNUSED(options);
	UNUSED(target);
	UNUSED(callbacks);

	return (DNS_R_SYNTAX);
}

static inline isc_result_t
totext_null(ARGS_TOTEXT) {
	REQUIRE(rdata->type == dns_rdatatype_null);

	return (unknown_totext(rdata, tctx, target));
}

static inline isc_result_t
fromwire_null(ARGS_FROMWIRE) {
	isc_region_t sr;

	REQUIRE(type == dns_rdatatype_null);

	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(dctx);
	UNUSED(options);

	isc_buffer_activeregion(source, &sr);
	isc_buffer_forward(source, sr.length);
	return (mem_tobuffer(target, sr.base, sr.length));
}

static inline isc_result_t
towire_null(ARGS_TOWIRE) {
	REQUIRE(rdata->type == dns_rdatatype_null);

	UNUSED(cctx);

	return (mem_tobuffer(target, rdata->data, rdata->length));
}

static inline int
compare_null(ARGS_COMPARE) {
	isc_region_t r1;
	isc_region_t r2;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == dns_rdatatype_null);

	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);
	return (isc_region_compare(&r1, &r2));
}

static inline isc_result_t
fromstruct_null(ARGS_FROMSTRUCT) {
	dns_rdata_null_t *null;

	REQUIRE(type == dns_rdatatype_null);
	REQUIRE(((dns_rdata_null_t *)source) != NULL);
	REQUIRE(((dns_rdata_null_t *)source)->common.rdtype == type);
	REQUIRE(((dns_rdata_null_t *)source)->common.rdclass == rdclass);
	REQUIRE(((dns_rdata_null_t *)source)->data != NULL ||
		((dns_rdata_null_t *)source)->length == 0);

	null = source;

	UNUSED(type);
	UNUSED(rdclass);

	return (mem_tobuffer(target, null->data, null->length));
}

static inline isc_result_t
tostruct_null(ARGS_TOSTRUCT) {
	dns_rdata_null_t *null;
	isc_region_t r;

	REQUIRE(rdata->type == dns_rdatatype_null);
	REQUIRE(((dns_rdata_null_t *)target) != NULL);

	null = target;

	null->common.rdclass = rdata->rdclass;
	null->common.rdtype = rdata->type;
	ISC_LINK_INIT(&null->common, link);

	dns_rdata_toregion(rdata, &r);
	null->length = r.length;
	null->data = mem_maybedup(mctx, r.base, r.length);
	if (null->data == NULL)
		return (ISC_R_NOMEMORY);

	null->mctx = mctx;
	return (ISC_R_SUCCESS);
}

static inline void
freestruct_null(ARGS_FREESTRUCT) {
	dns_rdata_null_t *null;

	REQUIRE(((dns_rdata_null_t *)source) != NULL);
	REQUIRE(((dns_rdata_null_t *)source)->common.rdtype ==
		dns_rdatatype_null);

	null = source;

	if (null->mctx == NULL)
		return;

	if (null->data != NULL)
		isc_mem_free(null->mctx, null->data);
	null->mctx = NULL;
}

static inline isc_result_t
additionaldata_null(ARGS_ADDLDATA) {
	UNUSED(rdata);
	UNUSED(add);
	UNUSED(arg);

	REQUIRE(rdata->type == dns_rdatatype_null);

	return (ISC_R_SUCCESS);
}

static inline isc_result_t
digest_null(ARGS_DIGEST) {
	isc_region_t r;

	REQUIRE(rdata->type == dns_rdatatype_null);

	dns_rdata_toregion(rdata, &r);

	return ((digest)(arg, &r));
}

static inline bool
checkowner_null(ARGS_CHECKOWNER) {

	REQUIRE(type == dns_rdatatype_null);

	UNUSED(name);
	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(wildcard);

	return (true);
}

static inline bool
checknames_null(ARGS_CHECKNAMES) {

	REQUIRE(rdata->type == dns_rdatatype_null);

	UNUSED(rdata);
	UNUSED(owner);
	UNUSED(bad);

	return (true);
}

static inline int
casecompare_null(ARGS_COMPARE) {
	return (compare_null(rdata1, rdata2));
}

#endif	/* RDATA_GENERIC_NULL_10_C */
