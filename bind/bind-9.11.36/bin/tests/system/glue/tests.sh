#!/bin/sh
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

#
# Do glue tests.
#

DIGOPTS="+norec -p ${PORT}"

status=0

echo_i "testing that a ccTLD referral gets a full glue set from the root zone"
$DIG $DIGOPTS @10.53.0.1 foo.bar.fi. A >dig.out || status=1
digcomp --lc fi.good dig.out || status=1

echo_i "testing that we find glue A RRs we are authoritative for"
$DIG +norec @10.53.0.1 -p ${PORT} foo.bar.xx. a >dig.out || status=1
$PERL ../digcomp.pl xx.good dig.out || status=1

echo_i "testing that we find glue A/AAAA RRs in the cache"
$DIG +norec @10.53.0.1 -p ${PORT} foo.bar.yy. a >dig.out || status=1
$PERL ../digcomp.pl yy.good dig.out || status=1

echo_i "testing that we don't find out-of-zone glue"
$DIG $DIGOPTS @10.53.0.1 example.net. a > dig.out || status=1
digcomp noglue.good dig.out || status=1

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
