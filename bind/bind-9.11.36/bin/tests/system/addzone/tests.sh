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

DIGOPTS="+tcp +nosea +nostat +nocmd +norec +noques +noauth +noadd +nostats +dnssec -p ${PORT}"
RNDCCMD="$RNDC -c $SYSTEMTESTTOP/common/rndc.conf -p ${CONTROLPORT} -s"

status=0
n=0

echo_i "checking normally loaded zone ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.2 a.normal.example a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.normal.example' dig.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

# When LMDB support is compiled in, this tests that migration from
# NZF to NZD occurs during named startup
echo_i "checking previously added zone ($n)"
ret=0
$DIG $DIGOPTS @10.53.0.2 a.previous.example a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.previous.example' dig.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

if [ -n "$NZD" ]; then
    echo_i "checking that existing NZF file was renamed after migration ($n)"
    [ -e ns2/3bf305731dd26307.nzf~ ] || ret=1
    n=`expr $n + 1`
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=`expr $status + $ret`
fi

echo_i "adding new zone ($n)"
ret=0
$RNDCCMD 10.53.0.2 addzone 'added.example { type master; file "added.db"; };' 2>&1 | sed 's/^/ns2 /' | cat_i
$DIG $DIGOPTS @10.53.0.2 a.added.example a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.added.example' dig.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "checking addzone errors are logged correctly"
ret=0
$RNDCCMD 10.53.0.2 addzone bad.example '{ type mister; };' 2>&1 | grep 'unexpected token' > /dev/null 2>&1 || ret=1
grep "addzone: 'mister' unexpected" ns2/named.run >/dev/null 2>&1 || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "checking modzone errors are logged correctly"
ret=0
$RNDCCMD 10.53.0.2 modzone added.example '{ type mister; };' 2>&1 | grep 'unexpected token' > /dev/null 2>&1 || ret=1
grep "modzone: 'mister' unexpected" ns2/named.run >/dev/null 2>&1 || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "adding a zone that requires quotes ($n)"
ret=0
$RNDCCMD 10.53.0.2 addzone '"32/1.0.0.127-in-addr.added.example" { check-names ignore; type master; file "added.db"; };' 2>&1 | sed 's/^/ns2 /' | cat_i
$DIG $DIGOPTS @10.53.0.2 "a.32/1.0.0.127-in-addr.added.example" a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.32/1.0.0.127-in-addr.added.example' dig.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "adding a zone with a quote in the name ($n)"
ret=0
$RNDCCMD 10.53.0.2 addzone '"foo\"bar.example" { check-names ignore; type master; file "added.db"; };' 2>&1 | sed 's/^/ns2 /' | cat_i
$DIG $DIGOPTS @10.53.0.2 "a.foo\"bar.example" a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.foo\\"bar.example' dig.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "adding new zone with missing master file ($n)"
ret=0
$DIG $DIGOPTS +all @10.53.0.2 a.missing.example a > dig.out.ns2.pre.$n || ret=1
grep "status: REFUSED" dig.out.ns2.pre.$n > /dev/null || ret=1
$RNDCCMD 10.53.0.2 addzone 'missing.example { type master; file "missing.db"; };' 2> rndc.out.ns2.$n
grep "file not found" rndc.out.ns2.$n > /dev/null || ret=1
$DIG $DIGOPTS +all @10.53.0.2 a.missing.example a > dig.out.ns2.post.$n || ret=1
grep "status: REFUSED" dig.out.ns2.post.$n > /dev/null || ret=1
digcomp dig.out.ns2.pre.$n dig.out.ns2.post.$n || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

if [ -z "$NZD" ]; then
    echo_i "verifying no comments in NZF file ($n)"
    ret=0
    hcount=`grep "^# New zone file for view: _default" ns2/3bf305731dd26307.nzf | wc -l`
    [ $hcount -eq 0 ] || ret=1
    n=`expr $n + 1`
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=`expr $status + $ret`
fi

echo_i "checking rndc showzone with previously added zone ($n)"
ret=0
$RNDCCMD 10.53.0.2 showzone previous.example > rndc.out.ns2.$n
expected='zone "previous.example" { type master; file "previous.db"; };'
[ "`cat rndc.out.ns2.$n`" = "$expected" ] || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

if [ -n "$NZD" ]; then
    echo_i "checking zone is present in NZD ($n)"
    ret=0
    $NZD2NZF ns2/_default.nzd | grep previous.example > /dev/null || ret=1
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=`expr $status + $ret`
fi

echo_i "deleting previously added zone ($n)"
ret=0
$RNDCCMD 10.53.0.2 delzone previous.example 2>&1 | sed 's/^/ns2 /' | cat_i
$DIG $DIGOPTS @10.53.0.2 a.previous.example a > dig.out.ns2.$n
grep 'status: REFUSED' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.previous.example' dig.out.ns2.$n > /dev/null && ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

if [ -n "$NZD" ]; then
    echo_i "checking zone was deleted from NZD ($n)"
    for i in 0 1 2 3 4 5 6 7 8 9; do
        ret=0
        $NZD2NZF ns2/_default.nzd | grep previous.example > /dev/null && ret=1
        [ $ret = 0 ] && break
        sleep 1
    done
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=`expr $status + $ret`
fi

if [ -z "$NZD" ]; then
    echo_i "checking NZF file now has comment ($n)"
    ret=0
    hcount=`grep "^# New zone file for view: _default" ns2/3bf305731dd26307.nzf | wc -l`
    [ $hcount -eq 1 ] || ret=1
    n=`expr $n + 1`
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=`expr $status + $ret`
fi

echo_i "deleting newly added zone added.example ($n)"
ret=0
$RNDCCMD 10.53.0.2 delzone added.example 2>&1 | sed 's/^/ns2 /' | cat_i
$DIG $DIGOPTS @10.53.0.2 a.added.example a > dig.out.ns2.$n
grep 'status: REFUSED' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.added.example' dig.out.ns2.$n > /dev/null && ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "deleting newly added zone with escaped quote ($n)"
ret=0
$RNDCCMD 10.53.0.2 delzone "foo\\\"bar.example" 2>&1 | sed 's/^/ns2 /' | cat_i
$DIG $DIGOPTS @10.53.0.2 "a.foo\"bar.example" a > dig.out.ns2.$n
grep 'status: REFUSED' dig.out.ns2.$n > /dev/null || ret=1
grep "^a.foo\"bar.example" dig.out.ns2.$n > /dev/null && ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "checking rndc showzone with a normally-loaded zone ($n)"
ret=0
$RNDCCMD 10.53.0.2 showzone normal.example > rndc.out.ns2.$n
expected='zone "normal.example" { type master; file "normal.db"; };'
[ "`cat rndc.out.ns2.$n`" = "$expected" ] || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "checking rndc showzone with a normally-loaded zone with trailing dot ($n)"
ret=0
$RNDCCMD 10.53.0.2 showzone finaldot.example > rndc.out.ns2.$n
expected='zone "finaldot.example." { type master; file "normal.db"; };'
[ "`cat rndc.out.ns2.$n`" = "$expected" ] || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "delete a normally-loaded zone ($n)"
ret=0
$RNDCCMD 10.53.0.2 delzone normal.example > rndc.out.ns2.$n 2>&1
$DIG $DIGOPTS @10.53.0.2 a.normal.example a > dig.out.ns2.$n
grep "is no longer active and will be deleted" rndc.out.ns2.$n > /dev/null || ret=1
grep "To keep it from returning when the server is restarted" rndc.out.ns2.$n > /dev/null || ret=1
grep "must also be removed from named.conf." rndc.out.ns2.$n > /dev/null || ret=1

grep 'status: REFUSED' dig.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "attempting to add master zone with inline signing ($n)"
$RNDCCMD 10.53.0.2 addzone 'inline.example { type master; file "inline.db"; inline-signing yes; };' 2>&1 | sed 's/^/ns2 /' | cat_i
for i in 1 2 3 4 5
do
ret=0
$DIG $DIGOPTS @10.53.0.2 a.inline.example a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.inline.example' dig.out.ns2.$n > /dev/null || ret=1
[ $ret = 0 ] && break
sleep 1
done
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "attempting to add master zone with inline signing and missing master ($n)"
ret=0
$RNDCCMD 10.53.0.2 addzone 'inlinemissing.example { type master; file "missing.db"; inline-signing yes; };' 2> rndc.out.ns2.$n
grep "file not found" rndc.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "attempting to add slave zone with inline signing ($n)"
$RNDCCMD 10.53.0.2 addzone 'inlineslave.example { type slave; masters { 10.53.0.1; }; file "inlineslave.bk"; inline-signing yes; };' 2>&1 | sed 's/^/ns2 /' | cat_i
for i in 1 2 3 4 5
do
ret=0
$DIG $DIGOPTS @10.53.0.2 a.inlineslave.example a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.inlineslave.example' dig.out.ns2.$n > /dev/null || ret=1
[ $ret = 0 ] && break
sleep 1
done
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "attempting to delete slave zone with inline signing ($n)"
ret=0
for i in 0 1 2 3 4 5 6 7 8 9
do
	test -f ns2/inlineslave.bk.signed -a -f ns2/inlineslave.bk && break
	sleep 1
done
$RNDCCMD 10.53.0.2 delzone inlineslave.example 2>&1 > rndc.out2.test$n
test -f inlineslave.bk ||
grep '^inlineslave.bk$' rndc.out2.test$n > /dev/null || {
	echo_i "failed to report inlineslave.bk"; ret=1;
}
test ! -f inlineslave.bk.signed ||
grep '^inlineslave.bk.signed$' rndc.out2.test$n > /dev/null || {
	echo_i "failed to report inlineslave.bk.signed"; ret=1;
}
n=`expr $n + 1`
status=`expr $status + $ret`

echo_i "restoring slave zone with inline signing ($n)"
$RNDCCMD 10.53.0.2 addzone 'inlineslave.example { type slave; masters { 10.53.0.1; }; file "inlineslave.bk"; inline-signing yes; };' 2>&1 | sed 's/^/ns2 /' | cat_i
for i in 1 2 3 4 5
do
ret=0
$DIG $DIGOPTS @10.53.0.2 a.inlineslave.example a > dig.out.ns2.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.inlineslave.example' dig.out.ns2.$n > /dev/null || ret=1
[ $ret = 0 ] && break
sleep 1
done
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "deleting slave zone with automatic zone file removal ($n)"
ret=0
for i in 0 1 2 3 4 5 6 7 8 9
do
	test -f ns2/inlineslave.bk.signed -a -f ns2/inlineslave.bk && break
	sleep 1
done
$RNDCCMD 10.53.0.2 delzone -clean inlineslave.example 2>&1 > /dev/null
for i in 0 1 2 3 4 5 6 7 8 9
do
        ret=0
	test -f ns2/inlineslave.bk.signed -a -f ns2/inlineslave.bk && ret=1
        [ $ret = 0 ] && break
	sleep 1
done
n=`expr $n + 1`
status=`expr $status + $ret`

echo_i "modifying zone configuration ($n)"
ret=0
$RNDCCMD 10.53.0.2 addzone 'mod.example { type master; file "added.db"; };' 2>&1 | sed 's/^/ns2 /' | cat_i
$DIG +norec $DIGOPTS @10.53.0.2 mod.example ns > dig.out.ns2.1.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.1.$n > /dev/null || ret=1
$RNDCCMD 10.53.0.2 modzone 'mod.example { type master; file "added.db"; allow-query { none; }; };' 2>&1 | sed 's/^/ns2 /' | cat_i
$DIG +norec $DIGOPTS @10.53.0.2 mod.example ns > dig.out.ns2.2.$n || ret=1
$RNDCCMD 10.53.0.2 showzone mod.example | grep 'allow-query { "none"; };' > /dev/null 2>&1 || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "check that adding a 'stub' zone works ($n)"
ret=0
$RNDCCMD 10.53.0.2 addzone 'stub.example { type stub; masters { 1.2.3.4; }; file "stub.example.bk"; };' > rndc.out.ns2.$n 2>&1 || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "check that adding a 'static-stub' zone works ($n)"
ret=0
$RNDCCMD 10.53.0.2 addzone 'static-stub.example { type static-stub; server-addresses { 1.2.3.4; }; };' > rndc.out.ns2.$n 2>&1 || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "check that zone type 'redirect' (master) is properly rejected ($n)"
ret=0
$RNDCCMD 10.53.0.2 addzone '"." { type redirect; file "redirect.db"; };' > rndc.out.ns2.$n 2>&1 && ret=1
grep "zones not supported by addzone" rndc.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "check that zone type 'redirect' (slave) is properly rejected ($n)"
ret=0
$RNDCCMD 10.53.0.2 addzone '"." { type redirect; masters { 1.2.3.4; }; file "redirect.bk"; };' > rndc.out.ns2.$n 2>&1 && ret=1
grep "zones not supported by addzone" rndc.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "check that zone type 'hint' is properly rejected ($n)"
ret=0
$RNDCCMD 10.53.0.2 addzone '"." { type hint; file "hints.db"; };' > rndc.out.ns2.$n 2>&1 && ret=1
grep "zones not supported by addzone" rndc.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "check that zone type 'forward' is properly rejected ($n)"
ret=0
$RNDCCMD 10.53.0.2 addzone 'forward.example { type forward; forwarders { 1.2.3.4; }; forward only; };' > rndc.out.ns2.$n 2>&1 && ret=1
grep "zones not supported by addzone" rndc.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "check that zone type 'delegation-only' is properly rejected ($n)"
ret=0
$RNDCCMD 10.53.0.2 addzone 'delegation-only.example { type delegation-only; };' > rndc.out.ns2.$n 2>&1 && ret=1
grep "zones not supported by addzone" rndc.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "check that 'in-view' zones are properly rejected ($n)"
ret=0
$RNDCCMD 10.53.0.2 addzone 'in-view.example { in-view "_default"; };' > rndc.out.ns2.$n 2>&1 && ret=1
grep "zones not supported by addzone" rndc.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "reconfiguring server with multiple views"
rm -f ns2/named.conf
copy_setports ns2/named2.conf.in ns2/named.conf
$RNDCCMD 10.53.0.2 reconfig 2>&1 | sed 's/^/ns2 /' | cat_i
sleep 5

echo_i "adding new zone to external view ($n)"
# NOTE: The internal view has "recursion yes" set, and so queries for
# nonexistent zones should return NOERROR.  The external view is
# "recursion no", so queries for nonexistent zones should return
# REFUSED.  This behavior should be the same regardless of whether
# the zone does not exist because a) it has not yet been loaded, b)
# it failed to load, or c) it has been deleted.
ret=0
$DIG +norec $DIGOPTS @10.53.0.2 -b 10.53.0.2 a.added.example a > dig.out.ns2.intpre.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.intpre.$n > /dev/null || ret=1
$DIG +norec $DIGOPTS @10.53.0.4 -b 10.53.0.4 a.added.example a > dig.out.ns2.extpre.$n || ret=1
grep 'status: REFUSED' dig.out.ns2.extpre.$n > /dev/null || ret=1
$RNDCCMD 10.53.0.2 addzone 'added.example in external { type master; file "added.db"; };' 2>&1 | sed 's/^/ns2 /' | cat_i
$DIG +norec $DIGOPTS @10.53.0.2 -b 10.53.0.2 a.added.example a > dig.out.ns2.int.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.int.$n > /dev/null || ret=1
$DIG +norec $DIGOPTS @10.53.0.4 -b 10.53.0.4 a.added.example a > dig.out.ns2.ext.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.ext.$n > /dev/null || ret=1
grep '^a.added.example' dig.out.ns2.ext.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

if [ -z "$NZD" ]; then
    echo_i "checking new NZF file has comment ($n)"
    ret=0
    hcount=`grep "^# New zone file for view: external" ns2/external.nzf | wc -l`
    [ $hcount -eq 1 ] || ret=1
    n=`expr $n + 1`
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=`expr $status + $ret`
fi

if [ -n "$NZD" ]; then
    echo_i "verifying added.example in external view created an external.nzd DB ($n)"
    ret=0
    [ -e ns2/external.nzd ] || ret=1
    n=`expr $n + 1`
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=`expr $status + $ret`
fi

echo_i "checking rndc reload causes named to reload the external view's new zone config ($n)"
ret=0
$RNDCCMD 10.53.0.2 reload 2>&1 | sed 's/^/ns2 /' | cat_i
$DIG +norec $DIGOPTS @10.53.0.2 -b 10.53.0.2 a.added.example a > dig.out.ns2.int.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.int.$n > /dev/null || ret=1
$DIG +norec $DIGOPTS @10.53.0.4 -b 10.53.0.4 a.added.example a > dig.out.ns2.ext.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.ext.$n > /dev/null || ret=1
grep '^a.added.example' dig.out.ns2.ext.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "checking rndc showzone with newly added zone ($n)"
# loop because showzone may complain if zones are still being
# loaded from the NZDB at this point.
for try in 0 1 2 3 4 5; do
    ret=0
$RNDCCMD 10.53.0.2 showzone added.example in external > rndc.out.ns2.$n 2>/dev/null
    if [ -z "$NZD" ]; then
      expected='zone "added.example" in external { type master; file "added.db"; };'
    else
      expected='zone "added.example" { type master; file "added.db"; };'
    fi
    [ "`cat rndc.out.ns2.$n`" = "$expected" ] || ret=1
    [ $ret -eq 0 ] && break
    sleep 1
done
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "deleting newly added zone ($n)"
ret=0
$RNDCCMD 10.53.0.2 delzone 'added.example in external' 2>&1 | sed 's/^/ns2 /' | cat_i
$DIG $DIGOPTS @10.53.0.4 -b 10.53.0.4 a.added.example a > dig.out.ns2.$n || ret=1
grep 'status: REFUSED' dig.out.ns2.$n > /dev/null || ret=1
grep '^a.added.example' dig.out.ns2.$n > /dev/null && ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "attempting to add zone to internal view ($n)"
ret=0
$DIG +norec $DIGOPTS @10.53.0.2 -b 10.53.0.2 a.added.example a > dig.out.ns2.pre.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.pre.$n > /dev/null || ret=1
$RNDCCMD 10.53.0.2 addzone 'added.example in internal { type master; file "added.db"; };' 2> rndc.out.ns2.$n
grep "permission denied" rndc.out.ns2.$n > /dev/null || ret=1
$DIG $DIGOPTS @10.53.0.2 -b 10.53.0.2 a.added.example a > dig.out.ns2.int.$n || ret=1
grep 'status: NOERROR' dig.out.ns2.int.$n > /dev/null || ret=1
$DIG $DIGOPTS @10.53.0.4 -b 10.53.0.4 a.added.example a > dig.out.ns2.ext.$n || ret=1
grep 'status: REFUSED' dig.out.ns2.ext.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "attempting to delete a policy zone ($n)"
ret=0
$RNDCCMD 10.53.0.2 delzone 'policy in internal' 2> rndc.out.ns2.$n >&1
grep 'cannot be deleted' rndc.out.ns2.$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "ensure the configuration context is cleaned up correctly ($n)"
ret=0
$RNDCCMD 10.53.0.2 reconfig > /dev/null 2>&1 || ret=1
sleep 5
$RNDCCMD 10.53.0.2 status > /dev/null 2>&1 || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "check delzone after reconfig failure ($n)"
ret=0
$RNDCCMD 10.53.0.3 addzone 'inlineslave.example. IN { type slave; file "inlineslave.db"; masterfile-format text; masters { testmaster; }; };' > /dev/null 2>&1 || ret=1
copy_setports ns3/named2.conf.in ns3/named.conf
$RNDCCMD 10.53.0.3 reconfig > /dev/null 2>&1 && ret=1
sleep 5
$RNDCCMD 10.53.0.3 delzone inlineslave.example > /dev/null 2>&1 || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

if ! $FEATURETEST --with-lmdb
then
    echo_i "check that addzone is fully reversed on failure (--with-lmdb=no) ($n)"
    ret=0
    $RNDCCMD 10.53.0.3 addzone "test1.baz" '{ type master; file "e.db"; };' > /dev/null 2>&1 || ret=1
    $RNDCCMD 10.53.0.3 addzone "test2.baz" '{ type master; file "dne.db"; };' > /dev/null 2>&1 && ret=1
    $RNDCCMD 10.53.0.3 addzone "test3.baz" '{ type master; file "e.db"; };' > /dev/null 2>&1 || ret=1
    $RNDCCMD 10.53.0.3 delzone "test3.baz" > /dev/null 2>&1 || ret=1
    grep test2.baz ns3/_default.nzf > /dev/null && ret=1
    n=`expr $n + 1`
    if [ $ret != 0 ]; then echo_i "failed"; fi
    status=`expr $status + $ret`
fi

echo_i "check that named restarts with multiple added zones ($n)"
ret=0
$RNDCCMD 10.53.0.3 addzone "test4.baz" '{ type master; file "e.db"; };' > /dev/null 2>&1 || ret=1
$RNDCCMD 10.53.0.3 addzone "test5.baz" '{ type master; file "e.db"; };' > /dev/null 2>&1 || ret=1
$RNDCCMD 10.53.0.3 addzone '"test/.baz"' '{ type master; check-names ignore; file "e.db"; };' > /dev/null 2>&1 || ret=1
$RNDCCMD 10.53.0.3 addzone '"test\".baz"' '{ type master; check-names ignore; file "e.db"; };' > /dev/null 2>&1 || ret=1
$RNDCCMD 10.53.0.3 addzone '"test\\.baz"' '{ type master; check-names ignore; file "e.db"; };' > /dev/null 2>&1 || ret=1
$RNDCCMD 10.53.0.3 addzone '"test\032.baz"' '{ type master; check-names ignore; file "e.db"; };' > /dev/null 2>&1 || ret=1
$RNDCCMD 10.53.0.3 addzone '"test\010.baz"' '{ type master; check-names ignore; file "e.db"; };' > /dev/null 2>&1 || ret=1
$PERL $SYSTEMTESTTOP/stop.pl addzone ns3
$PERL $SYSTEMTESTTOP/start.pl --noclean --restart --port ${PORT} addzone ns3 || ret=1
$DIG $DIGOPTS @10.53.0.3 version.bind txt ch > dig.out.test$n || ret=1
grep "status: NOERROR" dig.out.test$n > /dev/null || ret=1
$DIG $DIGOPTS @10.53.0.3 SOA  "test4.baz" > dig.out.1.test$n || ret=1
grep "status: NOERROR" dig.out.1.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.1.test$n > /dev/null || ret=1
$DIG $DIGOPTS @10.53.0.3 SOA  "test5.baz" > dig.out.2.test$n || ret=1
grep "status: NOERROR" dig.out.2.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.2.test$n > /dev/null || ret=1
$DIG $DIGOPTS @10.53.0.3 SOA  'test/.baz' > dig.out.3.test$n || ret=1
grep "status: NOERROR" dig.out.3.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.3.test$n > /dev/null || ret=1
$DIG $DIGOPTS @10.53.0.3 SOA  'test\\.baz' > dig.out.4.test$n || ret=1
grep "status: NOERROR" dig.out.4.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.4.test$n > /dev/null || ret=1
$DIG $DIGOPTS @10.53.0.3 SOA  'test\032.baz' > dig.out.5.test$n || ret=1
grep "status: NOERROR" dig.out.5.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.5.test$n > /dev/null || ret=1
$DIG $DIGOPTS @10.53.0.3 SOA  'test\010.baz' > dig.out.6.test$n || ret=1
grep "status: NOERROR" dig.out.6.test$n > /dev/null || ret=1
grep "ANSWER: 1," dig.out.6.test$n > /dev/null || ret=1
n=`expr $n + 1`
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
