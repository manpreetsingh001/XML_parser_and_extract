package NVD;

#  Extract vulnerability records from the XML files provided by NIST in their
#  public data feed at: https://nvd.nist.gov/download.cfm
#
#  This module supports only the NVD XML version 1.2.1 schema. The version 2.0
#  schema is not supported.

use strict;
use warnings;
use DBI; 
use XML::LibXML;

sub extract {
    my $fname = shift
        or warn("please provide the XML file to load\n"),
        return;

    my $xml = XML::LibXML->load_xml(location => $fname);
    my( $nvd ) = $xml->nonBlankChildNodes;

    my %vuln;
    for my $entry ($nvd->nonBlankChildNodes) {
        my %value;
       # %value = parse_nvd_entry($entry);

        for my $attr ($entry->attributes) {
            $value{$attr->nodeName} = $attr->nodeValue;
        }

        # rename 'name' to 'cve_id'
        my $cve_id = $value{cve_id} = delete $value{name};

        $vuln{$cve_id} = \%value;
    }

    return %vuln;
}

sub save2db{
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
     push @cve_list, [$cve, $data->{$cve}{severity},$data->{$cve}{published},$data->{$cve}{modified}];
  }
   print "Saving data into a db.......\n";
   for (@cve_list) {
     $sth->execute($_->[0], $_->[1], $_->[2] ,$_->[3]);
     #print "$_->[0] $_->[1] $_->[2] $_->[3]\n"
   }
}

sub parse_nvd_entry {
    my $entry = shift;

    my %entry;
    for my $node ($entry->nonBlankChildNodes) {
        my $name = $node->nodeName;
        my $value = $node->textContent;
        $value =~ s/^\s+|\s+$//g;

        if ($node->nodeName eq '#text') {
            # The node content is held in an element called: '#text'. This is 
            # returned by the call to the method: textContent. As we recurse 
            # through the document, we rename it to "body".

            $name = "body";
        }

        if ($node->hasChildNodes) {
            my %value = parse_nvd_entry($node);
            $value = \%value;
        }

        if (defined $entry{$name}) {
            # This node name is reused within the same parent node
            my $existing_entry = $entry{$name};

            $value = {$name, $value};
            if (ref $existing_entry eq "ARRAY") {
                push @$existing_entry, $value;
            } else {
                $entry{$name} = [$existing_entry, $value];
            }

        } else {
            $entry{$name} = $value;
        }

        if ($node->hasAttributes) {
            my %attr ;
            for my $attr ($node->attributes) {
                $attr{$attr->nodeName} = $attr->nodeValue;
            }

            if (ref $value eq "HASH") {
                @$value{keys %attr} = values %attr;
            } else {
                $entry{$name} = {$name => $value, %attr};
            }
        }
    }

    return %entry;
}

1;
