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
 * A simple database driver that calls a Tcl procedure to define
 * the contents of the DNS namespace.  The procedure is loaded
 * from the file lookup.tcl; look at the comments there for
 * more information.
 */

#include <config.h>

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#include <isc/mem.h>
#include <isc/print.h>
#include <isc/result.h>
#include <isc/util.h>

#include <dns/log.h>
#include <dns/sdb.h>

#include <named/globals.h>

#include <tcl.h>

#include <tcldb.h>

#define CHECK(op)						\
	do { result = (op);					\
		if (result != ISC_R_SUCCESS) return (result);	\
	} while (0)

typedef struct tcldb_driver {
	isc_mem_t *mctx;
	Tcl_Interp *interp;
} tcldb_driver_t;

static tcldb_driver_t *the_driver = NULL;

static dns_sdbimplementation_t *tcldb = NULL;

static isc_result_t
tcldb_driver_create(isc_mem_t *mctx, tcldb_driver_t **driverp) {
	int tclres;
	isc_result_t result = ISC_R_SUCCESS;
	tcldb_driver_t *driver = isc_mem_get(mctx, sizeof(tcldb_driver_t));
	if (driver == NULL)
		return (ISC_R_NOMEMORY);
	driver->mctx = mctx;
	driver->interp = Tcl_CreateInterp();

	tclres = Tcl_EvalFile(driver->interp, (char *) "lookup.tcl");
	if (tclres != TCL_OK) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL,
			      DNS_LOGMODULE_SDB, ISC_LOG_ERROR,
			      "initializing tcldb: "
			      "loading 'lookup.tcl' failed: %s",
			      driver->interp->result);
		result = ISC_R_FAILURE;
		goto cleanup;
	}
	*driverp = driver;
	return (ISC_R_SUCCESS);

 cleanup:
	isc_mem_put(mctx, driver, sizeof(tcldb_driver_t));
	return (result);

}

static void
tcldb_driver_destroy(tcldb_driver_t **driverp) {
	tcldb_driver_t *driver = *driverp;
	Tcl_DeleteInterp(driver->interp);
	isc_mem_put(driver->mctx, driver, sizeof(tcldb_driver_t));
}

/*
 * Perform a lookup, by invoking the Tcl procedure "lookup".
 */
#ifdef DNS_CLIENTINFO_VERSION
static isc_result_t
tcldb_lookup(const char *zone, const char *name, void *dbdata,
	      dns_sdblookup_t *lookup, dns_clientinfomethods_t *methods,
	      dns_clientinfo_t *clientinfo)
#else
static isc_result_t
tcldb_lookup(const char *zone, const char *name, void *dbdata,
	      dns_sdblookup_t *lookup)
#endif /* DNS_CLIENTINFO_VERSION */
{
	isc_result_t result = ISC_R_SUCCESS;
	int tclres;
	int rrc;	/* RR count */
	char **rrv;	/* RR vector */
	int i;
	char *cmdv[3];
	char *cmd;

#ifdef DNS_CLIENTINFO_VERSION
	UNUSED(methods);
	UNUSED(clientinfo);
#endif /* DNS_CLIENTINFO_VERSION */

	tcldb_driver_t *driver = (tcldb_driver_t *) dbdata;

	cmdv[0] = "lookup";
	cmdv[1] = zone;
	cmdv[2] = name;
	cmd = Tcl_Merge(3, cmdv);
	tclres = Tcl_Eval(driver->interp, cmd);
	Tcl_Free(cmd);

	if (tclres != TCL_OK) {
		isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL,
			      DNS_LOGMODULE_SDB, ISC_LOG_ERROR,
			      "zone '%s': tcl lookup function failed: %s",
			      zone, driver->interp->result);
		return (ISC_R_FAILURE);
	}

	if (strcmp(driver->interp->result, "NXDOMAIN") == 0) {
		result = ISC_R_NOTFOUND;
		goto fail;
	}

	tclres = Tcl_SplitList(driver->interp, driver->interp->result,
			       &rrc, &rrv);
	if (tclres != TCL_OK)
		goto malformed;

	for (i = 0; i < rrc; i++) {
		isc_result_t tmpres;
		int fieldc;	/* Field count */
		char **fieldv;	/* Field vector */
		tclres = Tcl_SplitList(driver->interp, rrv[i],
				       &fieldc, &fieldv);
		if (tclres != TCL_OK) {
			tmpres = ISC_R_FAILURE;
			goto failrr;
		}
		if (fieldc != 3)
			goto malformed;
		tmpres = dns_sdb_putrr(lookup, fieldv[0], atoi(fieldv[1]),
				       fieldv[2]);
		Tcl_Free((char *) fieldv);
	failrr:
		if (tmpres != ISC_R_SUCCESS)
			result = tmpres;
	}
	Tcl_Free((char *) rrv);
	if (result == ISC_R_SUCCESS)
		return (result);

 malformed:
	isc_log_write(dns_lctx, DNS_LOGCATEGORY_GENERAL,
		      DNS_LOGMODULE_SDB, ISC_LOG_ERROR,
		      "zone '%s': "
		      "malformed return value from tcl lookup function: %s",
		      zone, driver->interp->result);
	result = ISC_R_FAILURE;
 fail:
	return (result);
}

/*
 * Set up per-zone state.  In our case, the database arguments of the
 * zone are collected into a Tcl list and assigned to an element of
 * the global array "dbargs".
 */
static isc_result_t
tcldb_create(const char *zone, int argc, char **argv,
	     void *driverdata, void **dbdata)
{
	tcldb_driver_t *driver = (tcldb_driver_t *) driverdata;

	char *list = Tcl_Merge(argc, argv);

	Tcl_SetVar2(driver->interp, (char *) "dbargs", (char *) zone, list, 0);

	Tcl_Free(list);

	*dbdata = driverdata;

	return (ISC_R_SUCCESS);
}

/*
 * This driver does not support zone transfer, so allnodes() is NULL.
 */
static dns_sdbmethods_t tcldb_methods = {
	tcldb_lookup,
	NULL, /* authority */
	NULL, /* allnodes */
	tcldb_create,
	NULL, /* destroy */
	NULL /* lookup2 */
};

/*
 * Initialize the tcldb driver.
 */
isc_result_t
tcldb_init(void) {
	isc_result_t result;
	int flags = DNS_SDBFLAG_RELATIVEOWNER | DNS_SDBFLAG_RELATIVERDATA;

	result = tcldb_driver_create(ns_g_mctx, &the_driver);
	if (result != ISC_R_SUCCESS)
		return (result);

	return (dns_sdb_register("tcl", &tcldb_methods, the_driver, flags,
				 ns_g_mctx, &tcldb));
}

/*
 * Wrapper around dns_sdb_unregister().
 */
void
tcldb_clear(void) {
	if (tcldb != NULL)
		dns_sdb_unregister(&tcldb);
	if (the_driver != NULL)
		tcldb_driver_destroy(&the_driver);
}
