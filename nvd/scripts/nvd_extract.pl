#! /usr/bin/perl -w
#
#  Extract vulnerability records detailed in NIST NVD XML files. Save the
#  records into a database.

use strict;
use warnings;

use FindBin;
use lib qq($FindBin::Bin/../lib);

use NVD;
use Dumpvalue;

if (@ARGV == 0) {
    die "Extract NVD vulnerability records into a SQLite database file\n",
        "Usage:\n    $0 <NVD_XML_files>\n\n";
}
#my $size = @ARGV;
#print "$size\n"
foreach my $file  (@ARGV){
 print "$file\n"
 #die "No file $file " if not -e $file;
 #my %vuln = NVD::extract($file);
 #Dumpvalue->new->dumpValue(\%vuln);
}



#my %vuln = NVD::extract(@ARGV);

#Dumpvalue->new->dumpValue(\%vuln);
