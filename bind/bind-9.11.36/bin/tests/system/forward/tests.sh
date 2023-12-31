# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

#shellcheck source=conf.sh
SYSTEMTESTTOP=..
. "$SYSTEMTESTTOP/conf.sh"

dig_with_opts() (
	"$DIG" -p "$PORT" "$@"
)

sendcmd() (
	"$PERL" ../send.pl 10.53.0.6 "$EXTRAPORT1"
)

root=10.53.0.1
hidden=10.53.0.2
f1=10.53.0.3
f2=10.53.0.4

status=0
n=0

n=`expr $n + 1`
echo_i "checking that a forward zone overrides global forwarders ($n)"
ret=0
dig_with_opts +noadd +noauth txt.example1. txt @$hidden > dig.out.$n.hidden || ret=1
dig_with_opts +noadd +noauth txt.example1. txt @$f1 > dig.out.$n.f1 || ret=1
digcomp dig.out.$n.hidden dig.out.$n.f1 || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking that a forward first zone no forwarders recurses ($n)"
ret=0
dig_with_opts +noadd +noauth txt.example2. txt @$root > dig.out.$n.root || ret=1
dig_with_opts +noadd +noauth txt.example2. txt @$f1 > dig.out.$n.f1 || ret=1
digcomp dig.out.$n.root dig.out.$n.f1 || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking that a forward only zone no forwarders fails ($n)"
ret=0
dig_with_opts +noadd +noauth txt.example2. txt @$root > dig.out.$n.root || ret=1
dig_with_opts +noadd +noauth txt.example2. txt @$f1 > dig.out.$n.f1 || ret=1
digcomp dig.out.$n.root dig.out.$n.f1 || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking that global forwarders work ($n)"
ret=0
dig_with_opts +noadd +noauth txt.example4. txt @$hidden > dig.out.$n.hidden || ret=1
dig_with_opts +noadd +noauth txt.example4. txt @$f1 > dig.out.$n.f1 || ret=1
digcomp dig.out.$n.hidden dig.out.$n.f1 || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking that a forward zone works ($n)"
ret=0
dig_with_opts +noadd +noauth txt.example1. txt @$hidden > dig.out.$n.hidden || ret=1
dig_with_opts +noadd +noauth txt.example1. txt @$f2 > dig.out.$n.f2 || ret=1
digcomp dig.out.$n.hidden dig.out.$n.f2 || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking that forwarding doesn't spontaneously happen ($n)"
ret=0
dig_with_opts +noadd +noauth txt.example2. txt @$root > dig.out.$n.root || ret=1
dig_with_opts +noadd +noauth txt.example2. txt @$f2 > dig.out.$n.f2 || ret=1
digcomp dig.out.$n.root dig.out.$n.f2 || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking that a forward zone with no specified policy works ($n)"
ret=0
dig_with_opts +noadd +noauth txt.example3. txt @$hidden > dig.out.$n.hidden || ret=1
dig_with_opts +noadd +noauth txt.example3. txt @$f2 > dig.out.$n.f2 || ret=1
digcomp dig.out.$n.hidden dig.out.$n.f2 || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking that a forward only doesn't recurse ($n)"
ret=0
dig_with_opts txt.example5. txt @$f2 > dig.out.$n.f2 || ret=1
grep "SERVFAIL" dig.out.$n.f2 > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking for negative caching of forwarder response ($n)"
# prime the cache, shutdown the forwarder then check that we can
# get the answer from the cache.  restart forwarder.
ret=0
dig_with_opts nonexist. txt @10.53.0.5 > dig.out.$n.f2 || ret=1
grep "status: NXDOMAIN" dig.out.$n.f2 > /dev/null || ret=1
$PERL ../stop.pl forward ns4 || ret=1
dig_with_opts nonexist. txt @10.53.0.5 > dig.out.$n.f2 || ret=1
grep "status: NXDOMAIN" dig.out.$n.f2 > /dev/null || ret=1
$PERL ../start.pl --restart --noclean --port "${PORT}" forward ns4 || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

check_override() (
    dig_with_opts 1.0.10.in-addr.arpa TXT @10.53.0.4 > dig.out.$n.f2 &&
    grep "status: NOERROR" dig.out.$n.f2 > /dev/null &&
    dig_with_opts 2.0.10.in-addr.arpa TXT @10.53.0.4 > dig.out.$n.f2 &&
    grep "status: NXDOMAIN" dig.out.$n.f2 > /dev/null
)

n=`expr $n + 1`
echo_i "checking that forward only zone overrides empty zone ($n)"
ret=0
# retry loop in case the server restart above causes transient failure
retry_quiet 10 check_override || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking that DS lookups for grafting forward zones are isolated ($n)"
ret=0
dig_with_opts grafted A @10.53.0.4 > dig.out.$n.q1 || ret=1
dig_with_opts grafted DS @10.53.0.4 > dig.out.$n.q2 || ret=1
dig_with_opts grafted A @10.53.0.4 > dig.out.$n.q3 || ret=1
dig_with_opts grafted AAAA @10.53.0.4 > dig.out.$n.q4 || ret=1
grep "status: NOERROR" dig.out.$n.q1 > /dev/null || ret=1
grep "status: NXDOMAIN" dig.out.$n.q2 > /dev/null || ret=1
grep "status: NOERROR" dig.out.$n.q3 > /dev/null || ret=1
grep "status: NOERROR" dig.out.$n.q4 > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking that rfc1918 inherited 'forward first;' zones are warned about ($n)"
ret=0
$CHECKCONF rfc1918-inherited.conf | grep "forward first;" >/dev/null || ret=1
$CHECKCONF rfc1918-notinherited.conf | grep "forward first;" >/dev/null && ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking that ULA inherited 'forward first;' zones are warned about ($n)"
ret=0
$CHECKCONF ula-inherited.conf | grep "forward first;" >/dev/null || ret=1
$CHECKCONF ula-notinherited.conf | grep "forward first;" >/dev/null && ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

count_sent() (
	logfile="$1"
	start_pattern="$2"
	pattern="$3"
	nextpartpeek "$logfile" | tr -d '\r' | sed -n "/$start_pattern/,/^\$/p" | grep -c "$pattern"
)

check_sent() (
	expected="$1"
	shift
	count=`count_sent "$@"`
	[ "$expected" = "$count" ]
)

wait_for_log() (
	nextpartpeek "$1" | grep "$2" >/dev/null

)

n=`expr $n + 1`
echo_i "checking that a forwarder timeout prevents it from being reused in the same fetch context ($n)"
ret=0
# Make ans6 receive queries without responding to them.
echo "//" | sendcmd
# Query for a record in a zone which is forwarded to a non-responding forwarder
# and is delegated from the root to check whether the forwarder will be retried
# when a delegation is encountered after falling back to full recursive
# resolution.
nextpart ns3/named.run >/dev/null
dig_with_opts txt.example7. txt @$f1 > dig.out.$n.f1 || ret=1
# The forwarder for the "example7" zone should only be queried once.
start_pattern="sending packet to 10\.53\.0\.6"
retry_quiet 5 wait_for_log ns3/named.run "$start_pattern"
check_sent 1 ns3/named.run "$start_pattern" ";txt\.example7\.[[:space:]]*IN[[:space:]]*TXT$" || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=`expr $n + 1`
echo_i "checking that priming queries are not forwarded ($n)"
ret=0
nextpart ns7/named.run >/dev/null
dig_with_opts +noadd +noauth txt.example1. txt @10.53.0.7 > dig.out.$n.f7 || ret=1
received_pattern="received packet from 10\.53\.0\.1"
start_pattern="sending packet to 10\.53\.0\.1"
retry_quiet 5 wait_for_log ns7/named.run "$received_pattern" || ret=1
check_sent 1 ns7/named.run "$start_pattern" ";\.[[:space:]]*IN[[:space:]]*NS$" || ret=1
sent=`grep -c "10.53.0.7#.* (.): query '\./NS/IN' approved" ns4/named.run`
[ "$sent" -eq 0 ] || ret=1
sent=`grep -c "10.53.0.7#.* (.): query '\./NS/IN' approved" ns1/named.run`
[ "$sent" -eq 1 ] || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=`expr $status + $ret`

n=$((n+1))
echo_i "checking that rebinding protection works in forward only mode ($n)"
ret=0
# 10.53.0.5 will forward target.malicious. query to 10.53.0.4
# which in turn will return a CNAME for subdomain.rebind.
# to honor the option deny-answer-aliases { "rebind"; };
# ns5 should return a SERVFAIL to avoid potential rebinding attacks
dig_with_opts +noadd +noauth @10.53.0.5 target.malicious. > dig.out.$n || ret=1
grep "status: SERVFAIL" dig.out.$n > /dev/null || ret=1
if [ $ret != 0 ]; then echo_i "failed"; fi
status=$((status+ret))


echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
