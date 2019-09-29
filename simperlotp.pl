#!/usr/bin/perl
#=============================================================================
#    Title		:  	Simperl OTP
#    Author		:  	Baptiste VANDENBORGHT
#    Version	:  	0.1.2 (September 2019)
#
#   Description	:  	Perl module for Radius (using rlm_perl) integrating in a 
#   				very simple way TOTP (Time-based One-Time Password). It 
#   				uses User-Password (in cleartext) and User-Name to 
#					retrieve the OTP secret in the database (encrypted), then 
#					it checks if the OTP the user has provided matches.
#===========================================================================
use strict;
use warnings;

#===========================================================================
#  Importing all required Perl Modules (see installation)
#===========================================================================
use Authen::OATH;
use Authen::SASL;
use Convert::Base32 qw( decode_base32 );
use Crypt::CBC   qw( );
use DBI;
use MIME::Base64;
use MIME::Base64 qw( decode_base64 );
use MIME::Lite;
use Switch;
use Try::Tiny;


#===========================================================================
#  Declare the global hashes from Radius (see FreeRadius documentation)
#===========================================================================
our (%RAD_REQUEST, %RAD_REPLY, %RAD_CHECK, %RAD_STATE, %RAD_PERLCONF);

#===========================================================================
#  Declare the constants that will be handled by FreeRadius for processing
#  (we use only 3 of them, OK, REJECT and UPDATED, but there are many more)
#  (see FreeRadius documentation for more information)
#===========================================================================
use constant {
	RLM_MODULE_REJECT   => 0, 
	RLM_MODULE_OK       => 2,
	RLM_MODULE_UPDATED  => 8,
};

#==========================================================================
#  Declare the level of logs available, that will be used for logging
#
#	This is used by the subroutine "log_request_attribute", which comes
#	by default with Perl script from rlm_perl module. Check FreeRadius
#   documentation for more info.
#===========================================================================
use constant {
	L_AUTH         => 2,  # Authentication message
	L_INFO         => 3,  # Informational message
	L_ERR          => 4,  # Error message
	L_WARN         => 5,  # Warning
	L_PROXY        => 6,  # Proxy messages
	L_ACCT         => 7,  # Accounting messages
	L_DBG          => 16, # Only displayed when debugging is enabled
	L_DBG_WARN     => 17, # Warning only displayed when debugging is enabled
	L_DBG_ERR      => 18, # Error only displayed when debugging is enabled
	L_DBG_WARN_REQ => 19, # Less severe warning only displayed when debugging is enabled
	L_DBG_ERR_REQ  => 20, # Less severe error only displayed when debugging is enabled
};

#===========================================================================
#  Declare a custom global hash specific to this perl script
#
#  As per the FreeRadius documentation states, all the values stored 
#  in that hash will be persistent and can be retrieved at different
#  stages of the Radius process (authentication, authorization, etc.)
#===========================================================================
my %SimperlOTP = (
	'secret' 	=> undef,
	'status' 	=> undef,
	'log'		=> undef,
);

#===========================================================================
#  Main Program
#===========================================================================
# +------------------------------------------------------------
# |	This subroutine is called during FreeRadius  autorize{} section 
# +------------------------------------------------------------
sub authorize {
	my $radiusUserName = $RAD_REQUEST{'User-Name'};
	my $encryptedOTPSecret;
	
	$encryptedOTPSecret = get_user_from_database($radiusUserName);
	
	$RAD_CHECK{'Auth-Type'} = "OTP"					if ($SimperlOTP{'status'} == 0);	# <--- Specify here the Auth-Type that will be used during authenticate{} section of FreeRadius
	$SimperlOTP{'secret'} = $encryptedOTPSecret 	if ($encryptedOTPSecret);
	
	end_perl_module();
}

# +------------------------------------------------------------
# |	This subroutine is called during FreeRadius authenticate{} section
# +------------------------------------------------------------
sub authenticate {
	my $radiusUserPassword = $RAD_REQUEST{'User-Password'};
	my ($decryptedOTPSecret, $genOTP);
	
	my $OTP = substr($radiusUserPassword, -6);						# <--- Extract the last 6 characters from the User-Password, which should be the 6 digits OTP (change if needed)
	my $password = substr($radiusUserPassword, 0, -6);				# <--- Extract the rest of it (all minus 6 last chars) from the User-Password, which will be used for decrypt the OTP secret (change if needed)
	
	$decryptedOTPSecret = decrypt_otp_secret($password);
	$genOTP = generate_otp($decryptedOTPSecret);
	
	if ($genOTP) {
		$SimperlOTP{'status'} = 5;
		$SimperlOTP{'status'} = 1 if ($OTP == $genOTP);				# <--- If the OTP is correct, we change the status from 5 (RLM_MODULE_REJECT) to 1 (RLM_MODULE_OK)
	}

	end_perl_module();
}

#===========================================================================
#  Subroutines
#===========================================================================
# +------------------------------------------------------------
# |		Name: 		get_user_from_database
# |		Added on:	0.1
# |		Purpose:	This will retrieve the database from the 
# |					Perlconf settings (check below and rlm_perl
# |					configuration file) and it will serve two
# |					purposes:
# |						1) It checks if the user exists in the DB
# |						2) It stores the encrypted OTP secret
# |						   in the global hash $SimperlOTP
# +------------------------------------------------------------
# | PARAMETERS
# +------------------------------------------------------------
# |		$username				:		Radius attribute User-Name	
# +------------------------------------------------------------
# | RADIUS PERLCONF PARAMETERS 
# +------------------------------------------------------------
# |		{'db'}->{'name'}		:		rlm_perl configuration
# |										used for the DB name
# |		{'db'}->{'user'}		:		rlm_perl configuration
# |										used for the DB user
# |		{'db'}->{'password'}	:		rlm_perl configuration
# |										used for the DB password
# +------------------------------------------------------------
# | RETURN 
# +------------------------------------------------------------
# |		$encryptedOTPSecret		:		Rijndael encrypted OTP 
# |										secret (if the user 
# |										was found)
# |		undef					:		The user was not found
# +------------------------------------------------------------
sub get_user_from_database {
	my $username = shift;
	my $encryptedOTPSecret;
	
	my $dbName 		= $RAD_PERLCONF{'db'}->{'name'};
	my $dbUsername	= $RAD_PERLCONF{'db'}->{'user'};
	my $dbPassword 	= $RAD_PERLCONF{'db'}->{'password'};

	try {
		my $dbInstance = DBI->connect(          
			"dbi:mysql:dbname=$dbName", 							# <--- For now, it supports only MySQL. You can change it if necessary.
			$dbUsername,                          
			$dbPassword,                          
			{ RaiseError => 1 },         
		);
		
		my $query = $dbInstance->prepare("SELECT * FROM otpusers WHERE username=? LIMIT 1");
		$query->execute($username);									# <--- Passing $username as execute argument is useful for escaping special characters

		my $result = $query->fetchrow_arrayref();
		$encryptedOTPSecret = @$result[2];							# <--- This will get the 3rd column of the database. Change [2] if you have a different schema than default

		$query->finish();
		$dbInstance->disconnect();
		
		$SimperlOTP{'status'} = 0;
		$SimperlOTP{'status'} = 2 	if (!$encryptedOTPSecret);		# <--- If $encryptedOTPSecret is undef (because there was no results in the DB), then the user does not exist
	} catch {
		$SimperlOTP{'status'} = 3;									# <--- If try{} fails, this is probably because there is an error with the database (connectivity or permissions issue, usually)		
	};
	
	return $encryptedOTPSecret if ($SimperlOTP{'status'} == 0);		# <--- Return $encryptedOTPSecret only if the status has been initialized to 0
	return undef;
}

# +------------------------------------------------------------
# |		Name: 		decrypt_otp_secret
# |		Added on: 	0.1
# |		Purpose:	This will get the OTP secret from global hash 
# |					$SimperlOTP{'secret'}, which is encrypted. 
# |					Then, this will try to decrypt it using 
# |					Rijndael cipher and the password that the 
# |					user has provided
# +------------------------------------------------------------
# | PARAMETERS
# +------------------------------------------------------------
# |		$key						:	Password that the user
# |										has provided (this 
# |										should be a part of the 
# |										Radius User-Password 
# |										attribute)
# +------------------------------------------------------------
# | RETURN 
# +------------------------------------------------------------
# |		$cipher->decrypt(secret)	:	If the password ($key) 
# |										was incorrect, it will
# |										still return something
# |										but as non-ASCII chars 
# +------------------------------------------------------------
sub decrypt_otp_secret {
	my $key = shift;

	my $cipher = Crypt::CBC->new({
		cipher => 'Rijndael',										# <--- Change the cipher here if necessary
		key    => $key,
	});
	
	return $cipher->decrypt(decode_base64($SimperlOTP{'secret'}));
}

# +------------------------------------------------------------
# |		Name: 		generate_otp
# |		Added on: 	0.1
# |		Purpose:	This will generate an OTP based on the 
# |					OTP secret that has been decrypted from
# |					the database
# +------------------------------------------------------------
# | PARAMETERS
# +------------------------------------------------------------
# |		$decryptedOTPSecret		:		String containing the
# |										cleartext OTP secret 
# |										in base32
# +------------------------------------------------------------
# | RETURN 
# +------------------------------------------------------------
# |		$value 					:		A 6-digits passcode 
# +------------------------------------------------------------
sub generate_otp {
	my ($otp, $value);
	my $decryptedOTPSecret = shift;

	$otp = Authen::OATH->new(
		digest => 'Digest::SHA1',									# <--- Change the digest here if necessary. Nevertheless, you should have the dependent Perl Module installed on your system if you do so.
	);
	
	try {
		$value = $otp->totp(  decode_base32( $decryptedOTPSecret ) ) ;
	} catch {
		$SimperlOTP{'status'} = 4;									# <--- If try{} fails, this is probably because $decryptedOTPSecret was not a correct Base32 string, and this is probably due to an incorrect password used for decrypting the secret.
	};
	
	return $value;
}

# +------------------------------------------------------------
# |		Name: 		send_success_email
# |		Added on: 	0.1.2
# |		Purpose:	This sends an email message with sucess
# |					to a specified administrator
# +------------------------------------------------------------
# | PARAMETERS
# +------------------------------------------------------------
# |		none
# +------------------------------------------------------------
# | RETURN 
# +------------------------------------------------------------
# |		none
# +------------------------------------------------------------
sub send_success_email {
	my $raduser = $RAD_REQUEST{'User-Name'};

	my $msg = MIME::Lite->new(
		From     => 'youchoose@test.com',
		To       => 'youchoose@test.com',
		Subject  => 'Successful Login From RADIUS',
		Type     => 'TEXT',
		Data     => "The client $raduser has successfully been authed by RADIUS to this system"
	);
	
	$msg->send('smtp',$RAD_PERLCONF{'smtp'}->{'server'}, Port=>$RAD_PERLCONF{'smtp'}->{'port'}, AuthUser=>$RAD_PERLCONF{'smtp'}->{'user'}, AuthPass=>$RAD_PERLCONF{'smtp'}->{'pwd'});
}

# +------------------------------------------------------------
# |		Name: 		end_perl_module
# |		Added on: 	0.1
# |		Purpose:	This ends this Perl script with a return code
# |					that will be handled by FreeRadius.
# |					Depending on the $SimperlOTP{'status'} value,
# |					it will affect different messages to the reply
# |					and will return OK or REJECT
# +------------------------------------------------------------
# | PARAMETERS
# +------------------------------------------------------------
# |		none
# +------------------------------------------------------------
# | RETURN 
# +------------------------------------------------------------
# |		$radiusReturnCode	:		Value of the return code 
# |									that will be handled by 
# |									FreeRadius
# +------------------------------------------------------------
sub end_perl_module {
	my ($message, $radiusReturnCode);
	
	if ($SimperlOTP{'status'} > 2) {			
		$radiusReturnCode = RLM_MODULE_REJECT;				# <--- For all statuses greater than 2, this Perl script shall always reject the client
	}
	elsif ($SimperlOTP{'status'} == 1) {				
		$radiusReturnCode = RLM_MODULE_OK;					# <--- If status is still equals to 0, then it means the update has only been updated
	}
	else {
		$radiusReturnCode = RLM_MODULE_UPDATED;
	}
	
	switch ($SimperlOTP{'status'}) {
		case 1		{ $message = "Welcome!"; send_success_email(); }
		case 2		{ $message = "OTP User was not found!" }
		case 3		{ $message = "Something went wrong with the database" }
		case 4		{ $message = "Password is incorrect" }
		case 5		{ $message = "OTP is incorrect" }
		else		{ $message = "An unknown error has occured" } 	# <--- This should never happen!
	}
	
	$RAD_REPLY{'Reply-Message'} = $message;
	return $radiusReturnCode;
}

# +------------------------------------------------------------
# |		Name: 		log_request_attributes
# |		Added on: 	Comes as default with example.pl from 
# |					rlm_perl module
# |		Purpose:	This will print the Radius attributes each  
# |					time this function is called on the 
# |					FreeRadius logs (when you do "radiusd -X")
# +------------------------------------------------------------
# | PARAMETERS
# +------------------------------------------------------------
# |		none	
# +------------------------------------------------------------
# | RETURN 
# +------------------------------------------------------------
# |		none
# +------------------------------------------------------------
sub log_request_attributes {
	for (keys %RAD_REQUEST) {
		&radiusd::radlog(L_DBG, "RAD_REQUEST: $_ = $RAD_REQUEST{$_}");
	}
	for (keys %RAD_CHECK) {
		&radiusd::radlog(L_DBG, "RAD_CHECK: $_ = $RAD_CHECK{$_}");
	}
	for (keys %RAD_PERLCONF) {
		&radiusd::radlog(L_DBG, "RAD_PERLCONF: $_ = $RAD_PERLCONF{$_}");
	}
	for (keys %SimperlOTP) {
		&radiusd::radlog(L_DBG, "SimperlOTP: $_ = $SimperlOTP{$_}");
	}
}