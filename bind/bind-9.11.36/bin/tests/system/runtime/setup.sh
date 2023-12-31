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

SYSTEMTESTTOP=..
. $SYSTEMTESTTOP/conf.sh

copy_setports ns2/named1.conf.in ns2/named.conf

copy_setports ns2/named-alt1.conf.in ns2/named-alt1.conf
copy_setports ns2/named-alt2.conf.in ns2/named-alt2.conf
copy_setports ns2/named-alt3.conf.in ns2/named-alt3.conf
copy_setports ns2/named-alt4.conf.in ns2/named-alt4.conf
copy_setports ns2/named-alt5.conf.in ns2/named-alt5.conf
copy_setports ns2/named-alt6.conf.in ns2/named-alt6.conf

mkdir ns2/nope

if [ 1 = "${CYGWIN:-0}" ]
then
    setfacl -s user::r-x,group::r-x,other::r-x ns2/nope
    cwd=`cygpath -aw .`
else
    chmod 555 ns2/nope
    cwd=`pwd`
fi

echo "directory \"$cwd/ns2\";" > ns2/dir
echo "directory \"$cwd/ns2/nope\";" > ns2/nopedir
echo "managed-keys-directory \"$cwd/ns2\";" > ns2/mkd
echo "managed-keys-directory \"$cwd/ns2/nope\";" > ns2/nopemkd
