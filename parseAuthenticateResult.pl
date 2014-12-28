#!/usr/bin/perl

use strict;
use warnings;

use Data::Dumper;
use Digest::SHA qw{ sha256 };
use File::Temp;
use Getopt::Long;
use IPC::Open2;
use JSON;
use MIME::Base64 qw{ decode_base64url };

# Parse options
my $appId;
my $pubKey;
GetOptions(
    "pubKey|k=s" => \$pubKey,
    "appId|a=s" => \$appId,
);
if(!$appId)
{
    print STDERR "$0 : --appId ('-a') option required\n";
    exit -1;
}
if(!$pubKey)
{
    print STDERR "$0 : --pubKey ('-k') option required\n";
    exit -1;
}
if(!-e $pubKey)
{
    print STDERR "$0 : pubKey file '$pubKey' doesn't exists\n";
    exit -1;
}

# Read input
my $data = eval{ decode_json(<STDIN>) };

if(!$data)
{
    print STDERR "Invalid JSON input\n";
    exit -1;
}

my $authenticateResult = eval{ parseAuthenticateResult({ pubKey => $pubKey, appId => $appId, data => $data }) };

if($authenticateResult)
{
    print "Authentication success:\n";
    print " - Counter: " . $authenticateResult->{'signature'}->{'counter'} . "\n";
    print " - User presence: " . ($authenticateResult->{'signature'}->{'userPresenceByte'} eq "\x01" ? "true" : "false") . "\n";
    print " - Validated challenge: " . $authenticateResult->{'clientData'}->{'challenge'} . "\n";
}
else
{
    print STDERR "FAILED\n";
    print STDERR $@;
    exit -1;
}

sub parseAuthenticateResult
{
    my $params = shift;
    
    my $data   = $params->{'data'};
    my $pubKey = $params->{'pubKey'};
    my $appId  = $params->{'appId'};

    if(!$data->{'signatureData'} or !$data->{'clientData'})
    {
        die("Missing fields in data");
    }

    my $clientDataJSON = decode_base64url($data->{'clientData'});
    my $clientData     = decode_json($clientDataJSON);

    my $signatureData  = decode_base64url($data->{'signatureData'});

    # Extract signature infos
    my $signature = parseSignature({ signature => $signatureData });

    # Verify signature
    my $dataSignature = sha256($appId) . $signature->{'userPresenceByte'} . pack('N', $signature->{'counter'}) . sha256($clientDataJSON);
    my $ret = verifySignature({ 
        keyFile => $pubKey,
        data => $dataSignature,
        signature => $signature->{'signature'} 
    });
    if(!$ret)
    {
        die('Invalid signature');
    }

    # Return infos
    return {
        clientData => $clientData,
        signature  => $signature,
    };
}

# http://fidoalliance.org/specs/fido-u2f-v1.0-ps-20141009/fido-u2f-raw-message-formats-ps-20141009.html#authentication-response-message-success
sub parseSignature
{
    my $params = shift;

    my $signature = $params->{'signature'};

    # A user presence byte [1 byte]. Bit 0 is set to 1, which means that user presence was verified. 
    my $userPresenceByte = substr($signature, 0, 1, "");
    if($userPresenceByte ne "\x01")
    {
        die('Invalid presence byte');
    }    

    # A counter [4 bytes]. This is the big-endian representation of a counter value that the U2F token increments every time it performs an authentication operation.
    my $counter = unpack('N', substr($signature, 0, 4, ""));

    return {
        userPresenceByte    => $userPresenceByte,
        counter             => $counter,
        signature           => $signature,
    };
}

# Verify ECDSA-SHA256 signature
sub verifySignature
{
    # Use openssl for now
    my $params = shift;
    my $key  = $params->{'keyFile'};
    my $data = $params->{'data'};
    my $sign = $params->{'signature'};

    # Create temp files to store signature
    my $signatureFile = File::Temp->new();
    print $signatureFile $sign;

    # Build args
    my @args = (qw{ openssl dgst -sha256 -verify }, $key, qw{ -signature }, $signatureFile->filename);

    # Launch openssl
    my $pid = open2(undef, \*OPENSSL_IN, @args);
    print OPENSSL_IN $data;
    close OPENSSL_IN;
    waitpid($pid, 0);

    # Check return, exit code == 0 means Verification OK
    my $returnCode = ($? >> 8);
    return ($returnCode == 0);
}

