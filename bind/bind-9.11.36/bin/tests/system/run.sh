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

#
# Run a system test.
#

SYSTEMTESTTOP="$(cd -P -- "$(dirname -- "$0")" && pwd -P)"
. $SYSTEMTESTTOP/conf.sh

if [ "`id -u`" -eq "0" ] && ! ${NAMED} -V | grep -q -F -- "enable-developer"; then
    echofail "Refusing to run test as root. Build with --enable-developer to override." >&2
    exit 1
fi

export SYSTEMTESTTOP

stopservers=true
baseport=5300

if [ ${SYSTEMTEST_NO_CLEAN:-0} -eq 1 ]; then
    clean=false
else
    clean=true
fi

while getopts "knp:r-:" flag; do
    case "$flag" in
    -) case "${OPTARG}" in
               keep) stopservers=false ;;
               noclean) clean=false ;;
           esac
           ;;
    k) stopservers=false ;;
    n) clean=false ;;
    p) baseport=$OPTARG ;;
    esac
done
shift `expr $OPTIND - 1`

if [ $# -eq 0 ]; then
    echofail "Usage: $0 [-k] [-n] [-p <PORT>] test-directory [test-options]" >&2;
    exit 1
fi

systest=${1%%/}
shift

if [ ! -d $systest ]; then
    echofail "$0: $systest: no such test" >&2
    exit 1
fi

# Define the number of ports allocated for each test, and the lowest and
# highest valid values for the "-p" option.
#
# The lowest valid value is one more than the highest privileged port number
# (1024).
#
# The highest valid value is calculated by noting that the value passed on the
# command line is the lowest port number in a block of "numports" consecutive
# ports and that the highest valid port number is 65,535.
numport=100
minvalid=`expr 1024 + 1`
maxvalid=`expr 65535 - $numport + 1`

test "$baseport" -eq "$baseport" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echofail "$0: $systest: must specify a numeric value for the port" >&2
    exit 1
elif [ $baseport -lt $minvalid -o $baseport -gt $maxvalid  ]; then
    echofail "$0: $systest: the specified port must be in the range $minvalid to $maxvalid" >&2
    exit 1
fi

# Name the first 10 ports in the set (it is assumed that each test has access
# to ten or more ports): the query port, the control port and eight extra
# ports.  Since the lowest numbered port (specified in the command line)
# will usually be a multiple of 10, the names are chosen so that if this is
# true, the last digit of EXTRAPORTn is "n".
PORT=$baseport
EXTRAPORT1=`expr $baseport + 1`
EXTRAPORT2=`expr $baseport + 2`
EXTRAPORT3=`expr $baseport + 3`
EXTRAPORT4=`expr $baseport + 4`
EXTRAPORT5=`expr $baseport + 5`
EXTRAPORT6=`expr $baseport + 6`
EXTRAPORT7=`expr $baseport + 7`
EXTRAPORT8=`expr $baseport + 8`
CONTROLPORT=`expr $baseport + 9`

LOWPORT=$baseport
HIGHPORT=`expr $baseport + $numport - 1`

export PORT
export EXTRAPORT1
export EXTRAPORT2
export EXTRAPORT3
export EXTRAPORT4
export EXTRAPORT5
export EXTRAPORT6
export EXTRAPORT7
export EXTRAPORT8
export CONTROLPORT

export LOWPORT
export HIGHPORT

echostart "S:$systest:`date`"
echoinfo  "T:$systest:1:A"
echoinfo  "A:$systest:System test $systest"
echoinfo  "I:$systest:PORTRANGE:${LOWPORT} - ${HIGHPORT}"

if [ x${PERL:+set} = x ]
then
    echowarn "I:$systest:Perl not available.  Skipping test."
    echowarn "R:$systest:UNTESTED"
    echoend  "E:$systest:`date $dateargs`"
    exit 0;
fi

$PERL testsock.pl -p $PORT  || {
    echowarn "I:$systest:Network interface aliases not set up.  Skipping test."
    echowarn "R:$systest:UNTESTED"
    echoend  "E:$systest:`date $dateargs`"
    exit 0;
}

# Check for test-specific prerequisites.
test ! -f $systest/prereq.sh || ( cd $systest && $SHELL prereq.sh "$@" )
result=$?

if [ $result -eq 0 ]; then
    : prereqs ok
else
    echowarn "I:$systest:Prerequisites missing, skipping test."
    [ $result -eq 255 ] && echowarn "R:$systest:SKIPPED" || echowarn "R:$systest:UNTESTED"
    echoend "E:$systest:`date $dateargs`"
    exit 0
fi

# Check for PKCS#11 support
if
    test ! -f $systest/usepkcs11 || $SHELL cleanpkcs11.sh
then
    : pkcs11 ok
else
    echowarn "I:$systest:Need PKCS#11, skipping test."
    echowarn "R:$systest:PKCS11ONLY"
    echoend  "E:$systest:`date $dateargs`"
    exit 0
fi

# Clean up files left from any potential previous runs
if test -f $systest/clean.sh
then
   ( cd $systest && $SHELL clean.sh "$@" )
fi

# Set up any dynamically generated test data
if test -f $systest/setup.sh
then
   ( cd $systest && $SHELL setup.sh "$@" )
fi

# Start name servers running
$PERL start.pl --port $PORT $systest
if [ $? -ne 0 ]; then
    echofail "R:$systest:FAIL"
    echoend  "E:$systest:`date $dateargs`"
    exit 1
fi

# Run the tests
( cd $systest ; $SHELL tests.sh "$@" )
status=$?

if $stopservers
then
    :
else
    exit $status
fi

# Shutdown
$PERL stop.pl $systest

status=`expr $status + $?`

get_core_dumps() {
    find "$systest/" \( -name 'core' -or -name 'core.*' -or -name '*.core' \) ! -name '*.gz' ! -name '*.txt' | sort
}

core_dumps=$(get_core_dumps | tr '\n' ' ')
assertion_failures=$(find "$systest/" -name named.run -print0 | xargs -0 grep "assertion failure" | wc -l)
sanitizer_summaries=$(find "$systest/" -name 'tsan.*' | wc -l)
if [ -n "$core_dumps" ]; then
    echoinfo "I:$systest:Core dump(s) found: $core_dumps"
    echofail "R:$systest:FAIL"
    get_core_dumps | while read -r coredump; do
        SYSTESTDIR="$systest"
        echoinfo "D:$systest:backtrace from $coredump:"
        echoinfo "D:$systest:--------------------------------------------------------------------------------"
        binary=$(gdb --batch --core="$coredump" 2>/dev/null | sed -ne "s|Core was generated by \`\([^' ]*\)[' ].*|\1|p")
        if [ ! -f "${binary}" ]; then
            binary=$(find "${TOP}" -path "*/.libs/${binary}" -type f)
        fi
        "${TOP}/libtool" --mode=execute gdb \
                                  -batch \
                                  -ex bt \
                                  -core="$coredump" \
                                  -- \
                                  "$binary" 2>/dev/null | sed -n '/^Core was generated by/,$p' | cat_d
        echoinfo "D:$systest:--------------------------------------------------------------------------------"
        coredump_backtrace="${coredump}-backtrace.txt"
        echoinfo "D:$systest:full backtrace from $coredump saved in $coredump_backtrace"
        "${TOP}/libtool" --mode=execute gdb \
                      -batch \
                      -command=run.gdb \
                      -core="$coredump" \
                      -- \
                      "$binary" > "$coredump_backtrace" 2>&1
        echoinfo "D:$systest:core dump $coredump archived as $coredump.gz"
        gzip -1 "${coredump}"
    done
elif [ "$assertion_failures" -ne 0 ]; then
    echoinfo "I:$systest:$assertion_failures assertion failure(s) found"
    find "$systest/" -name 'tsan.*' -print0 | xargs -0 grep "SUMMARY: " | sort -u | cat_d
    echofail "R:$systest:FAIL"
elif [ "$sanitizer_summaries" -ne 0 ]; then
    echoinfo "I:$systest:$sanitizer_summaries sanitizer report(s) found"
    echofail "R:$systest:FAIL"
elif [ "$status" != 0 ]; then
    echofail "R:$systest:FAIL"
else
    echopass "R:$systest:PASS"
    if $clean; then
        ( cd $systest && $SHELL clean.sh "$@" )
        if test -d ../../../.git; then
            git status -su --ignored "${systest}/" 2>/dev/null | \
            sed -n -e 's|^?? \(.*\)|I:'${systest}':file \1 not removed|p' \
            -e 's|^!! \(.*/named.run\)$|I:'${systest}':file \1 not removed|p' \
            -e 's|^!! \(.*/named.memstats\)$|I:'${systest}':file \1 not removed|p'
        fi
    fi
fi

echoend "E:$systest:`date $dateargs`"

exit $status
