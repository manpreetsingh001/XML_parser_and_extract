#! /usr/bin/perl -w
#
#  Extract vulnerability records detailed in NIST NVD XML files. Save the
#  records into a database.

use strict;
use warnings;
use Data::Dumper;
use FindBin;
use lib qq($FindBin::Bin/../lib);
use DBI;
use NVD;


if (@ARGV == 0) {
    die "Extract NVD vulnerability records into a SQLite database file\n",
        "Usage:\n    $0 <NVD_XML_files>\n\n";
}

#db_credentials
my $driver = "mysql";
my $database = "mysql";
my $dsn = "DBI:$driver:database=$database";

 
sub savedb{
   #saving data in a mysql database
   my $data = $_[0];
   my $db_cred = $_[1];

   #db connection
   my $dbh = DBI->connect($db_cred, "root", "root" ) or die $DBI::errstr;
   my $ddl = (
   #create extract table
            "CREATE TABLE IF NOT EXISTS extract (cve_id varchar(255) NOT NULL PRIMARY KEY, severity VARCHAR(255) ,published VARCHAR(255),modified varchar(255))");  
   $dbh->do($ddl);

   #insert values into table
   my $sql ='INSERT INTO extract
                       (cve_id,severity,published,modified)
                        values
                      (?,?,?,?)';
   my $sth = $dbh->prepare($sql);
  
   #extracting required values from hash
   my @cve_list;
   for my $cve (keys %$data){
     #print "$_->[0] $_->[1] $_->[2] $_->[3]";
     push @cve_list, [$cve, $data->{$cve}{severity},$data->{$cve}{published},$data->{$cve}{modified}];
}
   print "Saving data into a db.......\n";
   for (@cve_list) {
     $sth->execute($_->[0], $_->[1], $_->[2] ,$_->[3]);
     #print "$_->[0] $_->[1] $_->[2] $_->[3]\n"
   }
   
}

my %vuln;
foreach my $file  (@ARGV){

 die "No file $file " if not -e $file;
 %vuln = NVD::extract($file);
 #Dumpvalue->new->dumpValue(\%vuln);
 #Dumper(\%vuln);
}

savedb(\%vuln,$dsn)

