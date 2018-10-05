# SimperlOTP 

A simple PERL script for using OTP with **rlm_perl** FreeRadius 3.x module

## Description

This script uses **Time-based OTP (TOTP)** for generating a 6-digits passcode. It is important to have a clear knowledge of how RADIUS works as we won't cover its operating in this document. This script takes action during two steps of an AAA authentication: 

- During **authorization**: it checks if the user exists in the database
- During **authentication**: it generates an OTP and checks if the one provided by the user matches the one generated

The OTP is created using a secret that is already stored in a database. Each user has his own secret. In this document, we will provide the default database schema in order to make this script work as soon as deployed, and we will describe how to add a user with a secret using command-line. 

In addition to this document, **the code itself is well-documented**. As a result, we won't describe its subroutines and methods. 

## Security Concerns

For security purposes, the secret is stored in the database using *Rijndael* cipher. The key used for decrypting it should be provided by the user himself in the ***User-Password*** RADIUS attribute. By default, the ***User-Password*** shall respect this formatting:<br>
> **encryption-passwordDIGIT**

- **encryption-password:** the key used for decrypting 
- **DIGIT:** a 6-digit code which will be checked by the script

For instance, in the following ***User-Password***: 
> **PerlsTheBest389122**

- **PerlsTheBest** will be used as the key to decrypt the OTP secret
- **389122** will be the OTP that will be checked with the one generated by the script

Needless to say that you are free to change this formatting in the code according to your will. 

**Please note that the *User-Name* and *User-Password* RADIUS attributes are sent in cleartext!**<br> 
This should not be a problem when attempting to authenticate to the RADIUS within the same network/subnet, but if you plan to use this configuration in a more complex setup, you should keep in mind that the security risk is greater! We plan to harden security by encapsulating this script with EAP.

## Getting Started 

These instructions will help you to deploy and run this script.

### Environment 

This script has been solely tested on the following environment:

- CentOS **7.5**
- Perl **5.16.3**
- FreeRadius **3.0.13**
- MariaDB Server **10.1.36**

Nevertheless, it should work in *most* of environments.

### Prerequisites 

We assume that you have an up and running *FreeRadius* server installed, with a *MariaDB/MySQL* instance on the same server listening to tcp/3306 (default port). A database named **radius** should already exist. 

###### *1 - Install rlm_perl module* 
    yum install freeradius-perl

###### *2 - Install required Perl Modules using Yum* 
	yum install perl-Crypt-CBC perl-DBI perl-Switch perl-Try-Tiny perl-Digest-HMAC perl-Module-Build perl-Crypt-Rijndael 

###### *3 - Install CPAN* 
Some Perl Modules can only be installed via *CPAN*:

	yum install perl-CPAN perl-CPAN-Meta perl-CPAN-Meta-YAML

Run *CPAN* and configure it (using *autoconfig*):

	cpan

At the end, you should get the following prompt:

	cpan[1]>

###### *4 - Install remaining Perl Modules using CPAN*


Run *CPAN*:

	cpan

Install the modules:

	cpan[1]> install MIME::Base64
	cpan[1]> install Convert::Base32
	cpan[1]> install Authen::OATH

###### *5 - Install the Perl Module digest used to generate the OTP* 
By default, this script uses **SHA1** as digest for generating the OTP. If you wish to use another digest (SHA256, for instance), you have to install the Perl Module and change the code accordingly.

	yum install perl-Digest-SHA1

### Encrypt an OTP secret
As stated previously, the database contains all the users with their encrypted OTP secrets. As the Perl script does not provide itself an algorithm to encrypt a secret, you can find another Perl script serving this purpose. It can be used very easily: 

	perl encrypt.pl -h
	Usage: encrypt.pl --password [password_to_use] --secret [OTP_secret]

For instance, to encrypt the OTP secret **hello** with **myPassword** as the encryption key: 

	perl encrypt.pl -p myPassword -s hello

It will print a string similar to this one (that you can store directly into the database):

	U2FsdGVkX19DsIevHbPU1LlnW/9AtYA89jE07nMLsRpgKqmEb0FRtXmBhkcmECvTKcsuq9pFBSVm+JcppvzALQ==

Please note that for the sake of the example, we used **hello** as OTP secret. In fact, **the OTP secret MUST be a *Base32* string** that you can easily get using [a website like this one.](https://freeotp.github.io/qrcode.html) You will find more information about creating a QR Code for a client in a future chapter. 

### Prepare the database
If you wish to use a different schema or integrate this script with an existing table, you have to make changes accordingly in the code itself (it is documented so it should not be complicated).

###### *1 - Connect to the database using the account who has permissions to use "radius" database*
	mysql -u raduser -p
	MariaDB [(none)]> use radius;
	Database changed

###### *2 - Create the following table*
	CREATE TABLE otpusers ( 
		id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY, 
		username VARCHAR(256) NOT NULL, 
		secret VARCHAR(256) NOT NULL 
	);

###### *3 - Insert a user with an Rijndael-cipher encrypted secret*
	INSERT INTO otpusers (
		username, 
		secret
	)  
	VALUES (
		'johndoe', 
		'U2FsdGVkX19DsIevHbPU1LlnW/9AtYA89jE07nMLsRpgKqmEb0FRtXmBhkcmECvTKcsuq9pFBSVm+JcppvzALQ=='
	);

### Configure FreeRadius

###### *1 - Place the script in the FreeRadius folder with the correct permissions*
	mv simperlotp.pl /etc/raddb/mods-config/perl/simperlotp.pl
	chown root:radiusd /etc/raddb/mods-config/perl/simperlotp.pl

###### *2 - Run the script and make sure it does not return any errors*
	perl /etc/raddb/mods-config/perl/simperlotp.pl

###### *3 - Edit the file /etc/raddb/mods-available/perl to the following:*
	perl {
		#  Specify here the SimperlOTP script that will be used.
		#  It should be located in /etc/raddb/mods-config/perl/
		#  and be owned by root:radiusd (CentOS configuration)
		filename = ${modconfdir}/${.:instance}/simperlotp.pl
	
		#  Specify here all the information needed for the 
		#  database connection. For now, it supports only MySQL
		#  backend. It will retrieve otpusers table (you can change
		#  it in the script)
		config {
			db {
				name = "radius"
				user = "raduser"
				password = "radpassword"
			}
		}
	}

Change the **filename** directive and **config{db{}}** section according to your settings.

###### *4 - Add the "perl" directive to section "authorize" in the file /etc/raddb/sites-available/default*
	authorize {
		[...you should have a bunch of directives here, such as eap, files, ldap, etc.]
		# Add this
		perl 
		
		# This should always be the last (you should place "perl" before pap, if you have it)
		pap
	}

If you are using a different site than the **default**, then you should edit the correct file.

###### *5 - Add the Auth-Type handling for OTP to the "authenticate" section in /etc/raddb/sites-available/default*
	authenticate {
		# This can comes first
		Auth-Type otp {
			perl
		}
		
		[...you should have other Auth-Type methods such as PAP, CHAP, etc.]
	}

If you are using a different site than the **default**, then you should edit the correct file.

###### *6 - Enable Perl module (rlm_perl) by creating a symlink*
	ln -s /etc/raddb/mods-available/perl /etc/raddb/mods-enabled/perl

###### *7 - Restart (or start) FreeRadius Daemon*
	systemctl restart radiusd.service

Now you should have your *FreeRadius* server ready to handle OTP authentication. 

## Proof-of-Concept
We will attempt to authenticate **John Doe** (username: **johndoe**) which was inserted into the database with the OTP secret encrypted by the password **myPassword**. To do so, we will be using a free *iOS* application named **FreeOTP** in order to authenticate. You can get it from the *App Store* and you can find similar applications for *Android*.

### Generate a QR Code
We will use [this website](https://freeotp.github.io/qrcode.html) to generate a QR code that will be imported in our app. 

<img align="center" src="https://raw.githubusercontent.com/aleaforny/simperlotp/master/img/freeotp_generator.png">

By default, we choose the following settings:

- **SHA1** (you can choose SHA256 but you will have to change the code as well)
- **Timeout** (TOTP)
- **Account** (it can be **johndoe** in our example)
- **Secret** (*base32*). In our example, we used **hello**, which was NOT a valid *Base32* string

You are free to change the number of digits as well, but you will have to change a large part  of the code accordingly. 

### Import the settings into the app
From the app, you can directly scan the generated QR code in order to import directly the settings. After doing so, you should see:

![](https://raw.githubusercontent.com/aleaforny/simperlotp/master/img/freeotp_added_otp.png)

If you touch this entry, you will see a **6 digits OTP** that you can use for the authentication.

### Test authentication with radtest

On the server, start *FreeRadius* in debug mode:

	radiusd -X

If no errors occured, you should see the message:

	Ready to process requests

Get a **6-digits OTP** from the *FreeOTP* app. Within 30 seconds, type the following command (assuming your OTP was **056733**):

	radtest johndoe "myPassword056733" localhost:1812 0 testing123

You should get an ***Access-Accept***: 

![](https://raw.githubusercontent.com/aleaforny/simperlotp/master/img/radtest_ok.png)

If you try the same command 30 seconds later, you should get an ***Access-Reject*** (with **OTP incorrect** as ***Reply-Message***). We will not explain the parameters of **radtest**. For more information, please check *man* or *FreeRadius* documentation. 

You can try different scenario, like attempting the authentication with a wrong username or wrong password, and you should always get an *Access-Reject*. 

## Release History

 - **0.1** (10/05/2018)
	 - *First version*

## Contribute
Please feel free to add comments and/or contribution to this script. I was not able to find a proper and simple script to implement this very useful OTP feature. **I have the strong belief that OTP should be easy and free to implement**, coupling with a *FreeRadius*, as security has become a major issue nowadays. 

I will be glad to have all of your recommendations/best practices.  

## References

- [FreeRadius Documentation](https://networkradius.com/doc/3.0.10/index.html)
- [rlm_perl Documentation](https://networkradius.com/doc/3.0.10/raddb/mods-available/perl.html)
- [How TOTP works and why it should be used](https://medium.freecodecamp.org/how-time-based-one-time-passwords-work-and-why-you-should-use-them-in-your-app-fdd2b9ed43c3)
- [FreeOTP References](https://freeotp.github.io/)
- [FreeOTP App Store Page](https://itunes.apple.com/fr/app/freeotp-authenticator/id872559395?mt=8)
- [Authen::OATH Perl Module for TOTP generation](https://metacpan.org/pod/Authen::OATH)
- [Crypt::CBC Perl Module for encrypting and decrypting the secret](https://metacpan.org/pod/Crypt::CBC)
- [DBI Perl Module for storing and retrieving the database information](https://metacpan.org/pod/DBI)
- [Try::Tiny Perl Module for the try{} catch{} operations ](https://metacpan.org/pod/Try::Tiny)
- [radtest Manual page](https://freeradius.org/radiusd/man/radtest.html)
