#!/usr/bin/perl    
use strict;
use warnings;
use feature qw( say );

use Getopt::Long qw(GetOptions);
use Crypt::CBC   qw( );
use MIME::Base64 qw( encode_base64 decode_base64 );

my ($password, $otpSecret);
GetOptions(
	'password|p=s' 	=> \$password,
	'secret|s=s' 		=> \$otpSecret) 
	or die "Usage: $0 --password [password_to_use] --secret [OTP secret]\n";

if (!$password || !$otpSecret) {
	die "Password and OTP secret are mandatory! Usage: $0 --password [password_to_use] --secret [OTP secret]\n";
}
if (length($password) < 4) {
	die "Password MUST be at least 4 characters long";
}
if (length($otpSecret)  < 32) {
	die "Secret MUST be at least 32 characters long";
}

my $cipher = Crypt::CBC->new({
	cipher => 'Rijndael',
    key    => $password,
});

my $encryptedotpSecret = encode_base64($cipher->encrypt($otpSecret), '');
say $encryptedotpSecret;