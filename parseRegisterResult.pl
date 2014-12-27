#!/usr/bin/perl

use strict;
use warnings;

use Crypt::OpenSSL::X509;
use Data::Dumper;
use Digest::SHA qw{ sha256 };
use File::Temp;
use Getopt::Long;
use IPC::Open2;
use JSON;
use MIME::Base64 qw{ encode_base64url decode_base64url };

# Parse options
my $appId;
GetOptions("appId|a=s" => \$appId);
if(!$appId)
{
        print STDERR "$0 : --appId ('-a') option required\n";
        exit -1;
}

# Read Input
my $data = eval{ decode_json(<STDIN>) };

if(!$data or !$data->{'registrationData'} or !$data->{'clientData'})
{
	print STDERR "Invalid JSON input\n";
	exit -1;
}

my $registrationData = decode_base64url($data->{'registrationData'});
my $clientDataJSON   = decode_base64url($data->{'clientData'});
my $clientData       = decode_json($clientDataJSON);

# Parse registrationData
my $registrationResult = eval{ parseRegistrationData({ registrationData => $registrationData, clientData => $clientDataJSON, appId => $appId }) };

if($registrationResult)
{
	# Parse done, print reults
	print "Registration sucess:\n";
	print "PubKey: " . encode_base64url($registrationResult->{'userPublicKey'}, '') . "\n";
	print "KeyHandle: " . encode_base64url($registrationResult->{'keyHandle'}, '') . "\n";
}
else
{
	print STDERR "Error while parsing registrationData\n";
	print STDERR $@;
	exit -1;
}

# http://fidoalliance.org/specs/fido-u2f-v1.0-ps-20141009/fido-u2f-raw-message-formats-ps-20141009.html#registration-response-message-success
sub parseRegistrationData
{
	my $params = shift;
	my $registrationString = $params->{'registrationData'};
	my $clientData = $params->{'clientData'};
	my $appId = $params->{'appId'};

	# A reserved byte [1 byte], which for legacy reasons has the value 0x05.
	my $reservedByte = substr($registrationString, 0, 1, "");
	if ($reservedByte ne "\x05")
	{
		die('Invalid reservedByte');
	}

	# A user public key [65 bytes]. This is the (uncompressed) x,y-representation of a curve point on the P-256 NIST elliptic curve.
	my $userPublicKey = substr($registrationString, 0, 65, "");
	
	# A key handle length byte [1 byte], which specifies the length of the key handle (see below).
	my $keyHandleLength = unpack("C", substr($registrationString, 0, 1, ""));
	
	# A key handle [length specified in previous field].
	my $keyHandle = substr($registrationString, 0, $keyHandleLength, "");

	# An attestation certificate [variable length]. This is a certificate in X.509 DER format.
	my $DERLength = getDERLength($registrationString);
	my $DERCertificate = substr($registrationString, 0, $DERLength, "");
	my $Certificate = Crypt::OpenSSL::X509->new_from_string($DERCertificate, Crypt::OpenSSL::X509::FORMAT_ASN1);

	# The remaining bytes in the message are a signature. This is a ECDSA (see [ECDSA-ANSI] in bibliography) signature (on P-256)
	my $signature = $registrationString;

	# Verify signature upon DER Certificate
	my $dataSignature = "\x00" . sha256($appId) . sha256($clientData) . $keyHandle . $userPublicKey;
	my $ret = verifySignature({ key => $Certificate->pubkey, data => $dataSignature, signature => $signature });
	if (not $ret)
	{
		die('Invalid signature');
	}

	# Return decoded values
	return {
		userPublicKey => $userPublicKey,
		keyHandle     => $keyHandle,
		certificate   => $Certificate,
		signature     => $signature
	};
}

# Verify ECDSA-SHA256 signature
sub verifySignature
{
	# Use openssl for now
	my $params = shift;
	my $key  = $params->{'key'};
	my $data = $params->{'data'};
	my $sign = $params->{'signature'};

	# Create temp files to store public key and signature
	my $pubKeyFile = File::Temp->new();
	print $pubKeyFile $key;

	my $signatureFile = File::Temp->new();
	print $signatureFile $sign;

	# Build args
	my @args = (qw{ openssl dgst -sha256 -verify }, $pubKeyFile->filename, qw{ -signature }, $signatureFile->filename);

	# Launch openssl
	my $pid = open2(undef, \*OPENSSL_IN, @args);
	print OPENSSL_IN $data;
	close OPENSSL_IN;
	waitpid($pid, 0);

	# Check return, exit code == 0 means Verification OK
	my $returnCode = ($? >> 8);
	return ($returnCode == 0);
}

# Fetch certificate length from DER header
sub getDERLength
{
	my $DERString = shift;	

	my $firstDerByte = substr($DERString, 0, 1);
	if($firstDerByte ne "\x30")
	{
		die('Invalid DER certificate');
	}

	my $firstLengthByte = unpack("C", substr($DERString, 1, 1));
	if($firstLengthByte < 0x81)
	{
		return $firstLengthByte + 2;
	}
	elsif($firstLengthByte == 0x81)
	{
		return unpack("C", substr($DERString, 2, 1)) + 3;
	}
	elsif($firstLengthByte == 0x82)
	{

		return unpack("n", substr($DERString, 2, 2)) + 4;
	}
	else
	{
		die('Invalid DER length');
	}
}
