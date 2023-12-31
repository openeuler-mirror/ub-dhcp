#!/bin/sh -e
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

SYSTEMTESTTOP=../..
. $SYSTEMTESTTOP/conf.sh

for zone in example01.com example02.com example03.com example04.com \
	    example05.com example06.com example07.com example08.com \
	    example09.com example10.com example11.com example12.com \
	    example13.com example14.com example15.com example16.com
do
  rm -f K${zone}.+*+*.key
  rm -f K${zone}.+*+*.private
  keyname=`$KEYGEN -q -r $RANDFILE -a $DEFAULT_ALGORITHM -b $DEFAULT_BITS -n zone $zone`
  keyname=`$KEYGEN -q -r $RANDFILE -a $DEFAULT_ALGORITHM -b $DEFAULT_BITS -n zone -f KSK $zone`
  cp example.com.db.in ${zone}.db
  $SIGNER -r $RANDFILE -S -T 3600 -O raw -o ${zone} ${zone}.db > /dev/null 2>&1
done
