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

SYSTESTDIR=autosign

dumpit () {
	echo_d "${debug}: dumping ${1}"
	cat "${1}" | cat_d
}

setup () {
	echo_i "setting up zone: $1"
	debug="$1"
	zone="$1"
	zonefile="${zone}.db"
	infile="${zonefile}.in"
	n=`expr ${n:-0} + 1`
}

setup secure.example
cp $infile $zonefile
ksk=`$KEYGEN -3 -q -r $RANDFILE -fk $zone 2> kg.out` || dumpit kg.out
$KEYGEN -3 -q -r $RANDFILE $zone > kg.out 2>&1 || dumpit kg.out
$DSFROMKEY $ksk.key > dsset-${zone}$TP

#
#  NSEC3/NSEC test zone
#
setup secure.nsec3.example
cp $infile $zonefile
ksk=`$KEYGEN -q -3 -r $RANDFILE -fk $zone 2> kg.out` || dumpit kg.out
$KEYGEN -q -3 -r $RANDFILE $zone > kg.out 2>&1 || dumpit kg.out
$DSFROMKEY $ksk.key > dsset-${zone}$TP

#
#  NSEC3/NSEC3 test zone
#
setup nsec3.nsec3.example
cp $infile $zonefile
ksk=`$KEYGEN -q -3 -r $RANDFILE -fk $zone 2> kg.out` || dumpit kg.out
$KEYGEN -q -3 -r $RANDFILE $zone > kg.out 2>&1 || dumpit kg.out
$DSFROMKEY $ksk.key > dsset-${zone}$TP

#
#  Jitter/NSEC3 test zone
#
setup jitter.nsec3.example
cp $infile $zonefile
count=1
while [ $count -le 1000 ]
do
    echo "label${count} IN TXT label${count}" >> $zonefile
    count=`expr $count + 1`
done
# Don't create keys just yet, because the scenario we want to test
# is an unsigned zone that has a NSEC3PARAM record added with
# dynamic update before the keys are generated.

#
#  OPTOUT/NSEC3 test zone
#
setup optout.nsec3.example
cp $infile $zonefile
ksk=`$KEYGEN -q -3 -r $RANDFILE -fk $zone 2> kg.out` || dumpit kg.out
$KEYGEN -q -3 -r $RANDFILE $zone > kg.out 2>&1 || dumpit kg.out
$DSFROMKEY $ksk.key > dsset-${zone}$TP

#
# A nsec3 zone (non-optout).
#
setup nsec3.example
cat $infile dsset-*.${zone}$TP > $zonefile
ksk=`$KEYGEN -q -3 -r $RANDFILE -fk $zone 2> kg.out` || dumpit kg.out
$KEYGEN -q -3 -r $RANDFILE $zone > kg.out 2>&1 || dumpit kg.out
$DSFROMKEY $ksk.key > dsset-${zone}$TP

#
# An NSEC3 zone, with NSEC3 parameters set prior to signing
#
setup autonsec3.example
cat $infile > $zonefile
ksk=`$KEYGEN -G -q -3 -r $RANDFILE -fk $zone 2> kg.out` || dumpit kg.out
echo $ksk > ../autoksk.key
zsk=`$KEYGEN -G -q -3 -r $RANDFILE $zone 2> kg.out` || dumpit kg.out
echo $zsk > ../autozsk.key
$DSFROMKEY $ksk.key > dsset-${zone}$TP

#
#  OPTOUT/NSEC test zone
#
setup secure.optout.example
cp $infile $zonefile
ksk=`$KEYGEN -q -3 -r $RANDFILE -fk $zone 2> kg.out` || dumpit kg.out
$KEYGEN -q -3 -r $RANDFILE $zone > kg.out 2>&1 || dumpit kg.out
$DSFROMKEY $ksk.key > dsset-${zone}$TP

#
#  OPTOUT/NSEC3 test zone
#
setup nsec3.optout.example
cp $infile $zonefile
ksk=`$KEYGEN -q -3 -r $RANDFILE -fk $zone 2> kg.out` || dumpit kg.out
$KEYGEN -q -3 -r $RANDFILE $zone > kg.out 2>&1 || dumpit kg.out
$DSFROMKEY $ksk.key > dsset-${zone}$TP

#
#  OPTOUT/OPTOUT test zone
#
setup optout.optout.example
cp $infile $zonefile
ksk=`$KEYGEN -q -3 -r $RANDFILE -fk $zone 2> kg.out` || dumpit kg.out
$KEYGEN -q -3 -r $RANDFILE $zone > kg.out 2>&1 || dumpit kg.out
$DSFROMKEY $ksk.key > dsset-${zone}$TP

#
# A optout nsec3 zone.
#
setup optout.example
cat $infile dsset-*.${zone}$TP > $zonefile
ksk=`$KEYGEN -q -3 -r $RANDFILE -fk $zone 2> kg.out` || dumpit kg.out
$KEYGEN -q -3 -r $RANDFILE $zone > kg.out 2>&1 || dumpit kg.out
$DSFROMKEY $ksk.key > dsset-${zone}$TP

#
# A RSASHA256 zone.
#
setup rsasha256.example
cp $infile $zonefile
ksk=`$KEYGEN -q -a RSASHA256 -b 2048 -r $RANDFILE -fk $zone 2> kg.out` || dumpit kg.out
$KEYGEN -q -a RSASHA256 -b 1024 -r $RANDFILE $zone > kg.out 2>&1 || dumpit kg.out
$DSFROMKEY $ksk.key > dsset-${zone}$TP

#
# A RSASHA512 zone.
#
setup rsasha512.example
cp $infile $zonefile
ksk=`$KEYGEN -q -a RSASHA512 -b 2048 -r $RANDFILE -fk $zone 2> kg.out` || dumpit kg.out
$KEYGEN -q -a RSASHA512 -b 1024 -r $RANDFILE $zone > kg.out 2>&1 || dumpit kg.out
$DSFROMKEY $ksk.key > dsset-${zone}$TP

#
# NSEC-only zone.
#
setup nsec.example
cp $infile $zonefile
ksk=`$KEYGEN -q -r $RANDFILE -fk $zone 2> kg.out` || dumpit kg.out
$KEYGEN -q -r $RANDFILE $zone > kg.out 2>&1 || dumpit kg.out
$DSFROMKEY $ksk.key > dsset-${zone}$TP

#
# Signature refresh test zone.  Signatures are set to expire long
# in the past; they should be updated by autosign.
#
setup oldsigs.example
cp $infile $zonefile
count=1
while [ $count -le 1000 ]
do
    echo "label${count} IN TXT label${count}" >> $zonefile
    count=`expr $count + 1`
done
$KEYGEN -q -r $RANDFILE -fk $zone > kg.out 2>&1 || dumpit kg.out
$KEYGEN -q -r $RANDFILE $zone > kg.out 2>&1 || dumpit kg.out
$SIGNER -PS -s now-1y -e now-6mo -o $zone -f $zonefile.signed $zonefile > s.out 2>&1 || dumpit s.out
mv $zonefile.signed $zonefile

#
# NSEC3->NSEC transition test zone.
#
setup nsec3-to-nsec.example
$KEYGEN -q -a RSASHA512 -b 2048 -r $RANDFILE -fk $zone > kg.out 2>&1 || dumpit kg.out
$KEYGEN -q -a RSASHA512 -b 1024 -r $RANDFILE $zone > kg.out 2>&1 || dumpit kg.out
$SIGNER -S -3 beef -A -o $zone -f $zonefile $infile > s.out 2>&1 || dumpit s.out

#
# secure-to-insecure transition test zone; used to test removal of
# keys via nsupdate
#
setup secure-to-insecure.example
$KEYGEN -q -r $RANDFILE -fk $zone > kg.out 2>&1 || dumpit kg.out
$KEYGEN -q -r $RANDFILE $zone > kg.out 2>&1 || dumpit kg.out
$SIGNER -S -o $zone -f $zonefile $infile > s.out 2>&1 || dumpit s.out

#
# another secure-to-insecure transition test zone; used to test
# removal of keys on schedule.
#
setup secure-to-insecure2.example
ksk=`$KEYGEN -q -3 -r $RANDFILE -fk $zone 2> kg.out` || dumpit kg.out
echo $ksk > ../del1.key
zsk=`$KEYGEN -q -3 -r $RANDFILE $zone 2> kg.out` || dumpit kg.out
echo $zsk > ../del2.key
$SIGNER -S -3 beef -o $zone -f $zonefile $infile > s.out 2>&1 || dumpit s.out

#
# Introducing a pre-published key test.
#
setup prepub.example
infile="secure-to-insecure2.example.db.in"
$KEYGEN -3 -q -r $RANDFILE -fk $zone > kg.out 2>&1 || dumpit kg.out
$KEYGEN -3 -q -r $RANDFILE $zone > kg.out 2>&1 || dumpit kg.out
$SIGNER -S -3 beef -o $zone -f $zonefile $infile > s.out 2>&1 || dumpit s.out

#
# Key TTL tests.
#

# no default key TTL; DNSKEY should get SOA TTL
setup ttl1.example
$KEYGEN -3 -q -r $RANDFILE -fk $zone > kg.out 2>&1 || dumpit kg.out
$KEYGEN -3 -q -r $RANDFILE $zone > kg.out 2>&1 || dumpit kg.out
cp $infile $zonefile

# default key TTL should be used
setup ttl2.example 
$KEYGEN -3 -q -r $RANDFILE -fk -L 60 $zone > kg.out 2>&1 || dumpit kg.out
$KEYGEN -3 -q -r $RANDFILE -L 60 $zone > kg.out 2>&1 || dumpit kg.out
cp $infile $zonefile

# mismatched key TTLs, should use shortest
setup ttl3.example
$KEYGEN -3 -q -r $RANDFILE -fk -L 30 $zone > kg.out 2>&1 || dumpit kg.out
$KEYGEN -3 -q -r $RANDFILE -L 60 $zone > kg.out 2>&1 || dumpit kg.out
cp $infile $zonefile

# existing DNSKEY RRset, should retain TTL
setup ttl4.example
$KEYGEN -3 -q -r $RANDFILE -L 30 -fk $zone > kg.out 2>&1 || dumpit kg.out
cat ${infile} K${zone}.+*.key > $zonefile
$KEYGEN -3 -q -r $RANDFILE -L 180 $zone > kg.out 2>&1 || dumpit kg.out

#
# A zone with a DNSKEY RRset that is published before it's activated
#
setup delay.example
ksk=`$KEYGEN -G -q -3 -r $RANDFILE -fk $zone 2> kg.out` || dumpit kg.out
echo $ksk > ../delayksk.key
zsk=`$KEYGEN -G -q -3 -r $RANDFILE $zone 2> kg.out` || dumpit kg.out
echo $zsk > ../delayzsk.key

#
# A zone with signatures that are already expired, and the private ZSK
# is missing.
#
setup nozsk.example
$KEYGEN -q -3 -r $RANDFILE -fk $zone > kg.out 2>&1 || dumpit kg.out
zsk=`$KEYGEN -q -3 -r $RANDFILE $zone`
$SIGNER -S -P -s now-1mo -e now-1mi -o $zone -f $zonefile ${zonefile}.in > s.out 2>&1 || dumpit s.out
echo $zsk > ../missingzsk.key
rm -f ${zsk}.private

#
# A zone with signatures that are already expired, and the private ZSK
# is inactive.
#
setup inaczsk.example
$KEYGEN -q -3 -r $RANDFILE -fk $zone > kg.out 2>&1 || dumpit kg.out
zsk=`$KEYGEN -q -3 -r $RANDFILE $zone`
$SIGNER -S -P -s now-1mo -e now-1mi -o $zone -f $zonefile ${zonefile}.in > s.out 2>&1 || dumpit s.out
echo $zsk > ../inactivezsk.key
$SETTIME -I now $zsk > st.out 2>&1 || dumpit st.out

#
# A zone that is set to 'auto-dnssec maintain' during a recofnig
#
setup reconf.example
cp secure.example.db.in $zonefile
$KEYGEN -q -3 -r $RANDFILE -fk $zone > kg.out 2>&1 || dumpit kg.out
$KEYGEN -q -3 -r $RANDFILE $zone > kg.out 2>&1 || dumpit kg.out

#
# A zone which generates a CDS and CDNSEY RRsets automatically
#
setup sync.example
cp $infile $zonefile
ksk=`$KEYGEN -3 -q -r $RANDFILE -fk -P sync now $zone 2> kg.out` || dumpit kg.out
$KEYGEN -3 -q -r $RANDFILE $zone > kg.out 2>&1 || dumpit kg.out
$DSFROMKEY $ksk.key > dsset-${zone}$TP
echo ns3/$ksk > ../sync.key

#
# A zone that has a published inactive key that is autosigned.
#
setup inacksk2.example
cp $infile $zonefile
ksk=`$KEYGEN -a NSEC3RSASHA1 -b 1024 -3 -q -r $RANDFILE -Pnow -A now+3600 -fk $zone 2> kg.out` || dumpit kg.out
$KEYGEN -a NSEC3RSASHA1 -b 1024 -3 -q -r $RANDFILE $zone > kg.out 2>&1 || dumpit kg.out
$DSFROMKEY $ksk.key > dsset-${zone}$TP

#
# A zone that has a published inactive key that is autosigned.
#
setup inaczsk2.example
cp $infile $zonefile
ksk=`$KEYGEN -a NSEC3RSASHA1 -b 1024 -3 -q -r $RANDFILE -fk $zone 2> kg.out` || dumpit kg.out
$KEYGEN -a NSEC3RSASHA1 -b 1024 -3 -q -r $RANDFILE -P now -A now+3600 $zone > kg.out 2>&1 || dumpit kg.out
$DSFROMKEY $ksk.key > dsset-${zone}$TP

#
#  A zone that starts with a active KSK + ZSK and a inactive ZSK.
#
setup inacksk3.example
cp $infile $zonefile
$KEYGEN -a NSEC3RSASHA1 -b 1024 -3 -q -r $RANDFILE -P now -A now+3600 -fk $zone > kg.out 2>&1 || dumpit kg.out
ksk=`$KEYGEN -a NSEC3RSASHA1 -b 1024 -3 -q -r $RANDFILE -fk $zone 2> kg.out` || dumpit kg.out
$KEYGEN -a NSEC3RSASHA1 -b 1024 -3 -q -r $RANDFILE $zone > kg.out 2>&1 || dumpit kg.out
$DSFROMKEY $ksk.key > dsset-${zone}$TP

#
#  A zone that starts with a active KSK + ZSK and a inactive ZSK.
#
setup inaczsk3.example
cp $infile $zonefile
ksk=`$KEYGEN -a NSEC3RSASHA1 -b 1024 -3 -q -r $RANDFILE -fk $zone 2> kg.out` || dumpit kg.out
$KEYGEN -a NSEC3RSASHA1 -b 1024 -3 -q -r $RANDFILE $zone > kg.out 2>&1 || dumpit kg.out
$KEYGEN -a NSEC3RSASHA1 -b 1024 -3 -q -r $RANDFILE -P now -A now+3600 $zone > kg.out 2>&1 || dumpit kg.out
$DSFROMKEY $ksk.key > dsset-${zone}$TP

#
# A zone that starts with an active KSK + ZSK and an inactive ZSK, with the
# latter getting deleted during the test.
#
setup delzsk.example
cp $infile $zonefile
ksk=`$KEYGEN -a NSEC3RSASHA1 -b 1024 -3 -q -r $RANDFILE -fk $zone 2> kg.out` || dumpit kg.out
$KEYGEN -a NSEC3RSASHA1 -b 1024 -3 -q -r $RANDFILE $zone > kg.out 2>&1 || dumpit kg.out
zsk=`$KEYGEN -a NSEC3RSASHA1 -b 1024 -3 -q -r $RANDFILE -I now-1w $zone 2>kg.out` || dumpit kg.out
echo $zsk > ../delzsk.key

#
#  Check that NSEC3 are correctly signed and returned from below a DNAME
#
setup dname-at-apex-nsec3.example
cp $infile $zonefile
ksk=`$KEYGEN -q -r $RANDFILE -a NSEC3RSASHA1 -b 1024 -3 -fk $zone 2> kg.out` || dumpit kg.out
$KEYGEN -q -r $RANDFILE -a NSEC3RSASHA1 -b 1024 -3 $zone > kg.out 2>&1 || dumpit kg.out
$DSFROMKEY $ksk.key > dsset-${zone}$TP
