use strict;
use warnings;
use DBI;
use Data::Dumper;
use FindBin;
use lib qq($FindBin::Bin/../lib);
use NVD;


if (@ARGV == 0) {
    die "Extract NVD vulnerability records into a SQLite database file\n",
        "Usage:\n    $0 <NVD_XML_files>\n\n";
}

#db_credentials
my $driver = "mysql";
my $database = "mysql";
my $dsn = "DBI:$driver:database=$database";

my %vuln;
foreach my $file  (@ARGV){

 die "No file $file " if not -e $file;
 %vuln = NVD::extract($file);
 #Dumpvalue->new->dumpValue(\%vuln);
 #Dumper(\%vuln);
}

NVD::save2db(\%vuln,$dsn)

