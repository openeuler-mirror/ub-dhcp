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

# makedefs.pl
# This script goes through all of the lib header files and creates a .def file
# for each DLL for Win32. It recurses as necessary through the subdirectories
#
# This program should only be run if it is necessary to regenerate
# the .def files.  Normally these files should be updated by  hand, adding
# new functions to the end and removing obsolete ones.
# If you do regenerate them you will also need to modify them by hand to
# to pick up those routines not detected by this program (like openlog).
#
# Search String: ^(([_a-z0-9])*( ))*prefix_[_a-z0-9]+_[a-z0-9]+( )*\(
# List of directories

@prefixlist = ("isc", "isccfg", "dns", "isccc", "bind9", "lwres", "irs");
@iscdirlist = ("isc/include/isc","isc/win32/include/isc","isc/include/pk11",
	       "isc/include/pkcs11","isc/win32/include/pkcs11");
@iscprefixlist = ("isc", "pk11", "pkcs");

@isccfgdirlist = ("isccfg/include/isccfg");
@isccfgprefixlist = ("cfg");

@iscccdirlist = ("isccc/include/isccc");
@iscccprefixlist = ("isccc");

@dnsdirlist = ("dns/include/dns","dns/include/dst");
@dnsprefixlist = ("dns", "dst");

@lwresdirlist = ("lwres/include/lwres","lwres/win32/include/lwres");
@lwresprefixlist = ("lwres");

@bind9dirlist = ("bind9/include/bind9");
@bind9prefixlist = ("bind9");

@irsdirlist = ("irs/include/irs","irs/win32/include/irs");
@irsprefixlist = ("irs");

# Run the changes for each directory in the directory list 

$ind = 0;
createoutfile($iscprefixlist[0]);
foreach $dir (@iscdirlist) {
	createdeffile($dir, $iscprefixlist[$ind]);
	$ind++;
}
close OUTDEFFILE;

$ind = 0;
createoutfile($isccfgprefixlist[0]);
foreach $dir (@isccfgdirlist) {
	createdeffile($dir, $isccfgprefixlist[$ind]);
	$ind++;
}
close OUTDEFFILE;

$ind = 0;
createoutfile($dnsprefixlist[0]);
foreach $dir (@dnsdirlist) {
	createdeffile($dir, $dnsprefixlist[$ind]);
	$ind++;
}
close OUTDEFFILE;

$ind = 0;
createoutfile($iscccprefixlist[0]);
foreach $dir (@iscccdirlist) {
	createdeffile($dir, $iscccprefixlist[$ind]);
	$ind++;
}
close OUTDEFFILE;

$ind = 0;
createoutfile($lwresprefixlist[0]);
foreach $dir (@lwresdirlist) {
	createdeffile($dir, $lwresprefixlist[$ind]);
	$ind++;
}
close OUTDEFFILE;

$ind = 0;
createoutfile($bind9prefixlist[0]);
foreach $dir (@bind9dirlist) {
	createdeffile($dir, $bind9prefixlist[$ind]);
	$ind++;
}
close OUTDEFFILE;

$ind = 0;
createoutfile($irsprefixlist[0]);
foreach $dir (@irsdirlist) {
	createdeffile($dir, $irsprefixlist[$ind]);
	$ind++;
}
close OUTDEFFILE;

exit;

#
# Subroutines
#
sub createdeffile {
	$xdir = $_[0];

	#
	# Get the List of files in the directory to be processed.
	#
	#^(([_a-z0-9])*( ))*prefix_[_a-z]+_[a-z]+( )*\(
	$prefix = $_[1];
	$pattern = "\^\(\(\[\_a\-z0\-9\]\)\*\( \)\)\*\(\\*\( \)\+\)\*$prefix";
	$pattern = "$pattern\_\[\_a\-z0\-9\]\+_\[a\-z0\-9\]\+\( \)\*\\\(";

	opendir(DIR,$xdir) || die "No Directory: $!";
	@files = grep(/\.h$/i, readdir(DIR));
	closedir(DIR);

	foreach $filename (sort @files) {
		#
		# Open the file and locate the pattern.
		#
		open (HFILE, "$xdir/$filename") ||
		      die "Can't open file $filename : $!";

		while (<HFILE>) {
			if(/$pattern/) {
				$func = $&;
				chop($func);
				$space = rindex($func, " ") + 1;
				if($space >= 0) {
					# strip out return values
					$func = substr($func, $space, 100);
				}
				print OUTDEFFILE "$func\n";
			}
		}
		# Set up the Patterns
		close(HFILE);
	}
}

# This is the routine that applies the changes

# output the result to the platform specific directory.
sub createoutfile {
	$outfile = "lib$_[0].def";

	open (OUTDEFFILE, ">$outfile")
	    || die "Can't open output file $outfile: $!";
	print OUTDEFFILE "LIBRARY lib$_[0]\n";
	print OUTDEFFILE "\n";
	print OUTDEFFILE "; Exported Functions\n";
	print OUTDEFFILE "EXPORTS\n";
	print OUTDEFFILE "\n";
}
