#!/usr/bin/perl
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

use warnings;
use strict;
use Time::Piece;

if (@ARGV < 2) {
	print STDERR <<'END';
usage:
    perl docbook-options.pl options_file section > section.grammar.xml
END
	exit 1;
}

my $FILE = shift;
my $SECTION = shift;

open (FH, "<", $FILE) or die "Can't open $FILE";

my $t = Time::Piece->new();
my $year = $t->year;

print <<END;
<!--
 - Copyright (C) 2004-$year  Internet Systems Consortium, Inc. ("ISC")
 -
 - This Source Code Form is subject to the terms of the Mozilla Public
 - License, v. 2.0. If a copy of the MPL was not distributed with this
 - file, You can obtain one at http://mozilla.org/MPL/2.0/.
-->

<!-- Generated by doc/misc/docbook-options.pl -->

<programlisting>
END

# skip preamble
my $preamble = 0;
while (<FH>) {
	if (m{^\s*$}) {
		last if $preamble > 0;
	} else {
		$preamble++;
	}
}

my $display = 0;
while (<FH>) {
	if (m{^$SECTION\b}) {
		$display = 1
	}

	if (m{// not.*implemented} || m{// obsolete} || m{// test.*only}) {
		next;
	}

	s{ // not configured}{};
	s{ // non-operational}{};
	s{ // may occur multiple times}{};
	s{<([a-z0-9_-]+)>}{<replaceable>$1</replaceable>}g;
	s{^(\s*)([a-z0-9_-]+)\b}{$1<command>$2</command>};
	s{[[]}{[}g;
	s{[]]}{]}g;
	s{        }{\t}g;

	if (m{^\s*$} && $display) {
		last;
	}
	if ($display) {
		print;
	}
}

print <<END;
</programlisting>
END