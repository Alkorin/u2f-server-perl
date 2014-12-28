#!/usr/bin/perl

use strict;
use warnings;

use Getopt::Long;
use JSON;
use MIME::Base64 qw{ encode_base64url };

# Parse options
my $appId;
GetOptions("appId|a=s" => \$appId);
if(!$appId)
{
    print STDERR "--appId ('-a') option required\n";
    exit -1;
}

# Create challenge
open(FH, '/dev/urandom');
read(FH, my $challenge, 32);
close FH;

# Output result
print encode_json({
    challenge => encode_base64url($challenge),
    version   => "U2F_V2",
    appId     => $appId
});
