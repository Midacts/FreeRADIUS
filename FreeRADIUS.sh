#!/bin/bash
# FreeRADIUS Server Setup Script
# Date: 2nd of April, 2014
# Version 1.0
#
# Author: John McCarthy
# Email: midactsmystery@gmail.com
# <http://www.midactstech.blogspot.com> <https://www.github.com/Midacts>
#
# To God only wise, be glory through Jesus Christ forever. Amen.
# Romans 16:27, I Corinthians 15:1-4
#---------------------------------------------------------------
######## VARIABLES ########
# FreeRADIUS Version
rad_ver=3.0.2
######## FUNCTIONS ########
function check_joinDomain()
{
	# Checks if you want to join the Active Directory domain
		echo
		echo -e "\e[33m=== Join this machine to your Active Directory domain ? (y/n)\e[0m"
		read yesno
		if [ "$yesno" = "y" ]; then
			installKerberos
		elif [ "$yesno" != "y" ] && [ "$yesno" != "n" ]; then
			clear
			check_joinDomain
			return 0
		fi
}
function installKerberos()
{
	# Calls Function 'installKerberos'
		echo -e "\e[33m=== Install Kerberos ? (y/n)\e[0m"
		read yesno
		if [ "$yesno" = "y" ]; then
			echo
		elif [ "$yesno" != "y" ] && [ "$yesno" != "n" ]; then
			clear
			installKerberos
			return 0
		elif [ "$yesno" = "n" ]; then
			configureKerberos
			return 0
		fi

	# Installs the required packages for Kerberos
		echo -e '\e[01;34m+++ Installing the Kerberos packages...\e[0m'
		echo
		apt-get update
		apt-get install -y krb5-user libpam-krb5
		echo
		echo -e '\e[01;37;42mThe Kerberos packages were successfully installed!\e[0m'
		echo

	# Calls Function 'configureKerberos'
		configureKerberos
}
function configureKerberos()
{
	# Calls Function 'configureKerberos'
		echo -e "\e[33m=== Configure the Kerberos configuration file ? (y/n)\e[0m"
		read yesno
		if [ "$yesno" = "y" ]; then
			echo
		elif [ "$yesno" != "y" ] && [ "$yesno" != "n" ]; then
			clear
			configureKerberos
			return 0
		elif [ "$yesno" = "n" ]; then
			installSamba
			return 0
		fi

	# Gets the domain and domain controller's names
		echo -e '\e[33mPlease type in the name of your domain:\e[0m'
		echo -e '\e[33;01mFor Example:  example.com\e[0m'
		read domain
		echo
		echo -e '\e[33mPlease type in the name of your domain controller:\e[0m'
		echo -e '\e[33;01mFor Example:  dc.example.com\e[0m'
		read dc
	# Sets the variables to upper and lower case
		dom_low=$( echo "$domain" | tr -s  '[:upper:]'  '[:lower:]' )
		dom_up=$( echo "$domain" | tr -s  '[:lower:]' '[:upper:]' )
		dc_up=$( echo "$dc" | tr -s  '[:lower:]' '[:upper:]' )

		echo
		echo -e '\e[01;34m+++ Editing the Kerberos configuration file...\e[0m'
		cat <<EOA> /etc/krb5.conf
[libdefaults]
        clock-skew              = 300
        default_realm           = $dom_up
        dns_lookup_realm        = true
        dns_lookup_kdc          = true
        forwardable             = true
        proxiable               = true
        ticket_lifetime         = 24000
        default_tgs_enctypes    = rc4-hmac aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
        default_tkt_enctypes    = rc4-hmac aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
        permitted_enctypes      = rc4-hmac aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96

[realms]
        $dom_up = {
                kdc             = $dc_up
                admin_server    = $dc_up
                default_domain  = $dom_up
        }

[domain_realm]
        .$dom_low	        = $dom_up
       $dom_low	        = $dom_up

[login]
        krb4_convert            = true
        krb4_get_tickets        = false

[logging]
        default                 = /var/log/krb5libs.log
        kdc                     = /var/log/kdc.log
        admin_server            = /var/log/kadmind.log
EOA
		echo
		echo -e '\e[01;37;42mThe Kerberos configuration file has been successfully edited!\e[0m'
		echo

	# Calls Function 'installSamba'
		installSamba
}
function installSamba()
{
	# Calls Function 'installSamba'
		echo -e "\e[33m=== Install Samba ? (y/n)\e[0m"
		read yesno
		if [ "$yesno" = "y" ]; then
			echo
		elif [ "$yesno" != "y" ] && [ "$yesno" != "n" ]; then
			clear
			installSamba
			return 0
		elif [ "$yesno" = "n" ]; then
			configureSamba
			return 0
		fi

	# Installs the samba package
		echo -e '\e[01;34m+++ Installing the Samba package...\e[0m'
		echo
		apt-get install -y samba
		echo
		echo -e '\e[01;37;42mThe Samba package was successfully installed!\e[0m'
		echo

	# Calls Function 'configureSamba'
		configureSamba
}
function configureSamba()
{
	# Calls Function 'configureSamba'
		echo -e "\e[33m=== Configure the Samba configuration file ? (y/n)\e[0m"
		read yesno
		if [ "$yesno" = "y" ]; then
			echo
		elif [ "$yesno" != "y" ] && [ "$yesno" != "n" ]; then
			clear
			configureSamba
			return 0
		elif [ "$yesno" = "n" ]; then
			installWinbind
			return 0
		fi

	# Verifies that the dom variable is set
		if [[ -z "$domain" ]]; then
		# Gets the domain and domain controller's names
			echo -e '\e[33mPlease type in the name of your domain:\e[0m'
			echo -e '\e[33;01mFor Example:  example.com\e[0m'
			read domain
			echo
			echo -e '\e[33mPlease type in the name of your domain controller:\e[0m'
			echo -e '\e[33;01mFor Example:  dc.example.com\e[0m'
			read dc
		# Sets the variables to upper and lower case
			dom_low=$( echo "$domain" | tr -s  '[:upper:]'  '[:lower:]' )
			dom_up=$( echo "$domain" | tr -s  '[:lower:]' '[:upper:]' )
			dc_up=$( echo "$dc" | tr -s  '[:lower:]' '[:upper:]' )
		fi
			dom_short=$(echo $dom_up | awk 'match($0,"\."){print substr($0,RSTART-99,99)}')
	# Edits the smb.conf file
		echo -e '\e[01;34m+++ Editing the Samba configuration file...\e[0m'
		cat <<EOB> /etc/samba/smb.conf
[global]

  security                              = ads
  workgroup                             = $dom_short
  realm                                 = $dom_up
  password server                       = $dc_up
  kerberos method                       = secrets and keytab
  log file                              = /var/log/samba/%m.log
  template homedir                      = /home/%D/%U
  template shell                        = /bin/bash
  encrypt passwords                     = Yes
  client signing                        = Yes
  client use spnego                     = Yes
  winbind separator                     = +
  winbind enum users                    = Yes
  winbind enum groups                   = Yes
  winbind use default domain            = Yes
  winbind refresh tickets               = Yes
  idmap config ORTHOBANC : schema_mode  = rfc2307
  idmap config ORTHOBANC : range        = 10000000-29999999
  idmap config ORTHOBANC : default      = Yes
  idmap config ORTHOBANC : backend      = rid
  idmap config * : range                = 20000-29999
  idmap config * : backend              = tdb

[sysvol]

  path                                  = /var/lib/samba/sysvol
  read only                             = no

[netlogon]

  path                                  = /var/lib/samba/sysvol/$dom_up/scripts
  read only                             = no
EOB
		echo
		echo -e '\e[01;37;42mThe Samba configuration file has been successfully edited!\e[0m'

	# Restarts the samba service
		echo
		echo -e '\e[01;34m+++ Restarting the Samba service...\e[0m'
		echo
		service samba restart
		echo
		echo -e '\e[01;37;42mThe Samba service has been successfully restarted!\e[0m'
		echo

	# Calls Function 'installWinbind'
		installWinbind
}
function installWinbind()
{
	# Calls Function 'installWinbind'
		echo -e "\e[33m=== Install Winbind ? (y/n)\e[0m"
		read yesno
		if [ "$yesno" = "y" ]; then
			echo
		elif [ "$yesno" != "y" ] && [ "$yesno" != "n" ]; then
			clear
			installWinbind
			return 0
		elif [ "$yesno" = "n" ]; then
			configureWinbind
			return 0
		fi

	# Installs winbind
		echo -e '\e[01;34m+++ Installing the Winbind package...\e[0m'
		echo
		apt-get install -y winbind
		echo
		echo -e '\e[01;37;42mThe Winbind package was successfully installed!\e[0m'
		echo

	# Calls Function 'configureWinbind'
		configureWinbind
}
function configureWinbind()
{
	# Calls Function 'configureWinbind'
		echo -e "\e[33m=== Configure the nsswitch configuration file ? (y/n)\e[0m"
		read yesno
		if [ "$yesno" = "y" ]; then
			echo
		elif [ "$yesno" != "y" ] && [ "$yesno" != "n" ]; then
			clear
			configureWinbind
			return 0
		elif [ "$yesno" = "n" ]; then
			joinDomain
			return 0
		fi

	# Configures the use of winbind by editing /etc/nsswitch.conf
		echo -e '\e[01;34m+++ Editing the nsswitch configuration file...\e[0m'
		cat <<EOC> /etc/nsswitch.conf
passwd:         compat winbind
group:          compat winbind
shadow:         compat winbind

hosts:          files dns
networks:       files

protocols:      db files
services:       db files
ethers:         db files
rpc:            db files

netgroup:       nis
EOC
		echo
		echo -e '\e[01;37;42mThe nsswitch configuration file has been successfully edited!\e[0m'
		echo

	# Calls Function 'joinDomain'
		joinDomain
}
function joinDomain()
{
	# Calls Function 'joinDomain'
		echo -e "\e[33m=== Join the Active Directory domain ? (y/n)\e[0m"
		read yesno
		if [ "$yesno" = "y" ]; then
			echo
		elif [ "$yesno" != "y" ] && [ "$yesno" != "n" ]; then
			clear
			joinDomain
			return 0
		elif [ "$yesno" = "n" ]; then
			pam
			return 0
		fi

	# Joins the machine to the Active Directory domain
		echo -e '\e[33;01mPlease type in the name of the user you would like to use to join your domain:\e[0m'
		read user
		echo -e '\e[33;01mPlease type in that user'\''s password:\e[0m'
		read passwd
		echo
		echo -e '\e[01;34m+++ Joining your Active Directory domain...\e[0m'
		echo
		/usr/bin/net ads join -U"$user"%"$passwd"
		echo
		echo -e '\e[01;37;42mYou have successfully joined your Active Directory domain!\e[0m'
		echo
	# Restarts the samba and winbind service
		echo -e '\e[01;34m+++ Restarting the Samba and Winbind services...\e[0m'
		echo
		service samba restart
		service winbind restart
		echo
		echo -e '\e[01;37;42mThe Samba and Winbind services have been successfully restarted!\e[0m'
		echo

	# Calls Function 'pam'
		pam
}
function pam()
{
	# Calls Function 'pam'
		echo -e "\e[33m=== Configure PAM's configuration files ? (y/n)\e[0m"
		read yesno
		if [ "$yesno" = "y" ]; then
			echo
		elif [ "$yesno" != "y" ] && [ "$yesno" != "n" ]; then
			clear
			pam
			return 0
		elif [ "$yesno" = "n" ]; then
			check_sudo
			return 0
		fi

	# Edits the /etc/pam.d/common-account file
		echo -e '\e[01;34m+++ Editing the /etc/pam.d/commin-account file...\e[0m'
		cat <<EOD> /etc/pam.d/common-account
account sufficient       pam_winbind.so
account required         pam_unix.so
EOD
		echo
		echo -e '\e[01;37;42mYou have successfully edited the /etc/pam.d/common-account file!\e[0m'

	# Edits the /etc/pam.d/common-auth file
		echo
		echo -e '\e[01;34m+++ Editing the /etc/pam.d/commin-auth file...\e[0m'
		cat <<EOE> /etc/pam.d/common-auth
auth sufficient pam_winbind.so
auth sufficient pam_unix.so nullok_secure use_first_pass
auth required   pam_deny.so
EOE
		echo
		echo -e '\e[01;37;42mYou have successfully edited the /etc/pam.d/common-auth file!\e[0m'

	# Edits the /etc/pam.d/common-session file
		echo
		echo -e '\e[01;34m+++ Editing the /etc/pam.d/commin-session file...\e[0m'
		cat <<EOF> /etc/pam.d/common-session
session required pam_unix.so
session required pam_mkhomedir.so umask=0022 skel=/etc/skel
EOF
		echo
		echo -e '\e[01;37;42mYou have successfully edited the /etc/pam.d/common-session file!\e[0m'
		echo

	# Calls Function 'sudo'
		check_sudo
}
function check_sudo()
{
	# Calls Function 'sudo'
		echo -e "\e[33m=== Configure the sudo configuration files ? (y/n)\e[0m"
		read yesno
		if [ "$yesno" = "y" ]; then
			sudo
		elif [ "$yesno" != "y" ] && [ "$yesno" != "n" ]; then
			clear
			check_sudo
			return 0
		fi
}
function sudo()
{
	# Install sudo
		echo
		echo -e '\e[01;34m+++ Installing the sudo package...\e[0m'
		echo
		apt-get install -y sudo
		echo
		echo -e '\e[01;37;42mYou have successfully installed the sudo package!\e[0m'

	# Makes the default home directory
		echo
		echo -e '\e[01;34m+++ Creating your domain'\''s home directory...\e[0m'
		dom_search=$(grep -r "workgroup" /etc/samba/smb.conf)
		dom_short=$(echo $dom_search | awk 'match($0,"="){print substr($0,RSTART+2,99)}')
		mkdir /home/$dom_short
		echo
		echo -e '\e[01;37;42mYou have successfully created your domain'\''s home directory!\e[0m'

	# Edits the /etc/pam.d/sudo file
		echo
		echo -e '\e[01;34m+++ Editing the /etc/pam.d/sudo file...\e[0m'
		cat <<EOG> /etc/pam.d/sudo
auth sufficient pam_winbind.so
auth sufficient pam_unix.so use_first_pass
auth required   pam_deny.so

@include common-auth
@include common-account
@include common-session-noninteractive
EOG
		echo
		echo -e '\e[01;37;42mYou have successfully edited the /etc/pam.d/sudo file!\e[0m'

	# Edits the /etc/sudoers file
		echo
		echo -e '\e[01;34m+++ Editing the /etc/sudoers file...\e[0m'
		cat <<EOH> /etc/sudoers
Defaults	env_reset
Defaults	mail_badpass
Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# User privilege specification
root	ALL=(ALL:ALL) ALL

# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Grant's access to the Domain Admins Active Directory Security Group
%domain\ admins        ALL=(ALL) ALL
EOH
		echo
		echo -e '\e[01;37;42mYou have successfully edited the /etc/sudoers file!\e[0m'

	# Restarts the winbind service
		echo
		echo -e '\e[01;34m+++ Restarting the Samba service...\e[0m'
		echo
		service winbind restart
		echo
		echo -e '\e[01;37;42mThe Samba service has been successfully restarted!\e[0m'
		echo
}
function freeradiusInstall()
{
	# Downloads the required packages- mainly OpenSSL
		echo
		echo -e '\e[34;01m+++ Installing Required Packages...\e[0m'
		echo
		apt-get update
		apt-get install -y build-essential libtalloc-dev libssl-dev
		echo
		echo -e '\e[01;37;42mThe required packages have been installed!\e[0m'

	# Downloads the latest FreeRADIUS installation files
		echo
		echo -e '\e[34;01m+++ Getting FreeRADIUS Installation Files...\e[0m'
		echo
		wget ftp://ftp.freeradius.org/pub/freeradius/freeradius-server-$rad_ver.tar.gz
		tar xzf freeradius-server-$rad_ver.tar.gz
		cd freeradius-server-$rad_ver
		echo -e '\e[01;37;42mThe latest version of FreeRADIUS has been acquired!\e[0m'

	# Installing FreeRADIUS
		echo
		echo -e '\e[34;01m+++ Installing FreeRADIUS...\e[0m'
		echo
		./configure
		make
		make install
		echo -e '\e[01;37;42mFreeRADIUS has been installed!\e[0m'

	# Grant the FreeRADIUS user access to the winbindd_priv group
		echo
		echo -e '\e[34;01m+++ Adding the radiusd user to the winbindd_priv group...\e[0m'
		echo
		useradd -G winbindd_priv radiusd
		echo -e '\e[01;37;42mThe radiud user has been added to the winbindd_priv group!\e[0m'
		echo
}
function configureFreeradius()
{
	# Change to the FreeRADIUS directory
		cd /usr/local/etc/raddb

	# Requests the domain name to be used for FreeRADIUS authentication
		echo
		echo -e '\e[33mPlease type in the domain name that you would like to use for FreeRADIUS authentication:\e[0m'
		echo -e '\e[33;01mFor Example:  example.com\e[0m'
		read dom_name

	# Edits the ntlm_auth file to reflect the correct settings
		echo
		echo -e '\e[34;01m+++ Configuring mods-available/ntlm_auth...\e[0m'
		echo
		sed -i 's@/path/to/ntlm_auth@/usr/bin/ntlm_auth@g' /usr/local/etc/raddb/mods-available/ntlm_auth
		sed -i "s@MYDOMAIN@$dom_name@g" /usr/local/etc/raddb/mods-available/ntlm_auth
		echo -e '\e[01;37;42mmods-available/ntlm_auth has been successfully edited!\e[0m'

	# Edits the sites-available/default file
		echo
		echo -e '\e[34;01m+++ Configuring sites-available/default...\e[0m'
		echo
		sed -i '260 s/^/#/g' sites-available/default
		sed -i '274 s/^/#/g' sites-available/default
		sed -i '331 s/^/#/g' sites-available/default
		sed -i '338 s/^/#/g' sites-available/default
		sed -i '348 s/^/#/g' sites-available/default
		sed -i '369 s/^/#/g' sites-available/default
		sed -i '414,416 s/^/#/g' sites-available/default
		sed -i '423,425 s/^/#/g' sites-available/default
		sed -i '437 s/^/#/g' sites-available/default
		sed -i '530 s/^/#/g' sites-available/default
		sed -i '551 s/^/#/g' sites-available/default
		sed -i '568 s/^/#/g' sites-available/default
		sed -i '642 s/^/#/g' sites-available/default
		echo -e '\e[01;37;42msites-available/default has been successfully edited!\e[0m'

	# Edits the sites-available/inner-tunnel file
		echo
		echo -e '\e[34;01m+++ Configuring sites-available/inner-tunnel...\e[0m'
		echo
		sed -i '52 s/^/#/g' sites-available/inner-tunnel
		sed -i '125 s/^/#/g' sites-available/inner-tunnel
		sed -i '132 s/^/#/g' sites-available/inner-tunnel
		sed -i '142 s/^/#/g' sites-available/inner-tunnel
		sed -i '162 s/^/#/g' sites-available/inner-tunnel
		sed -i '190,192 s/^/#/g' sites-available/inner-tunnel
		sed -i '199,201 s/^/#/g' sites-available/inner-tunnel
		sed -i '274 s/^/#/g' sites-available/inner-tunnel
		echo -e '\e[01;37;42msites-available/inner-tunnel has been successfully edited!\e[0m'

	# Edits the mods-available/mschap file
		echo
		echo -e '\e[34;01m+++ Configuring mods-available/mschap...\e[0m'
		echo
		sed -i "24 s/#//" mods-available/mschap
		sed -i "29 s/#//" mods-available/mschap
		sed -i "58s/#//" mods-available/mschap
		sed -i 's@/path/to/ntlm_auth@/usr/bin/ntlm_auth@g' mods-available/mschap
		echo -e '\e[01;37;42mmods-available/mschap has been successfully edited!\e[0m'

	# Edits the mods-available/eap file
		echo
		echo -e '\e[34;01m+++ Configuring mods-available/eap...\e[0m'
		echo
		sed -i 's/default_eap_type = md5/default_eap_type = peap/g' mods-available/eap
		sed -i '69,144d' mods-available/eap
		sed -i "173 s/#//" mods-available/eap
		sed -i 's/enable = yes/enable = no/g' mods-available/eap
		sed -i '379,453d' mods-available/eap
		echo -e '\e[01;37;42mmods-available/eap has been successfully edited!\e[0m'

	# Comments out the testing123 secrets
		echo
		echo -e '\e[34;01m+++ Changing the default secret in the clients.conf and proxy.conf files for security purposes...\e[0m'
		echo
		sed -i 's/secret = testing123/secret = Thisisth3n3wsecret!/g' clients.conf
		sed -i 's/secret = testing123/secret = Thisisth3n3wsecret/g' proxy.conf
		echo -e '\e[01;37;42mclients.conf has been successfully edited!\e[0m'
		echo
}
function freeradiusCerts()
{
	# Setup the FreeRADIUS Certificates
		cd /usr/local/etc/raddb/certs/
		rm -f *.pem *.der *.csr *.crt *.key *.p12 serial* index.txt*
		days=3650
		echo
		echo -e '\e[33mCountry:	(US)\e[0m'
		read country
		echo -e '\e[33mState:		(Tennessee)\e[0m'
		read state
		echo -e '\e[33mCity:		(Chattanooga)\e[0m'
		read city
		echo -e '\e[33mCompany Name:	(Midacts Tech)\e[0m'
		read company
		echo -e '\e[33mEmail Address:	(midactsmystery@gmail.com)\e[0m'
		read email
		echo -e '\e[33mInput/output password:\e[0m'
		read passwd
		echo
		echo -e '\e[34;01m+++ Editing the ca.cnf and server.cnf files and creating the ca and server certificates...\e[0m'
		echo

		file=('ca.cnf' 'server.cnf')
		old_pass=$(grep "input_password" ca.cnf | awk 'match($0,"="){print substr($0,RSTART+2,99)}')
		for (( i=0; i<=1; i++ ))
		do
			grep -rl "default_days" | xargs sed -i "s/60/$days/g" ${file[$i]}
			grep -rl "countryName" | xargs sed -i "s/FR/$country/g" ${file[$i]}
			grep -rl "stateOrProvinceName" | xargs sed -i "s/Radius/$state/g" ${file[$i]}
			grep -rl "localityName" | xargs sed -i "s/Somewhere/$city/g" ${file[$i]}
			grep -rl "organizationName" | xargs sed -i "s/Example Inc./$company/g" ${file[$i]}
			grep -rl "emailAddress" | xargs sed -i "s/admin@example.com/$email/g" ${file[$i]}
			grep -rl "input_password" | xargs sed -i "s/$old_pass/$passwd/g" ${file[$i]}
		done
		grep -rl "commonName" | xargs sed -i "s/Example Certificate Authority/FreeRADIUS Certificate Authority/g" ca.cnf
		grep -rl "commonName" | xargs sed -i "s/Example Server Certificate/FreeRADIUS Server Certificate/g" server.cnf

	# Updates the mods-available/eap file to the new input/output password
		old_key=$(grep -r "private_key_password = " ../mods-available/eap | awk 'match($0,"="){print substr($0,RSTART+2,99)}')
		grep -r "private_key_password" | xargs sed -i "s/$old_key/$passwd/g" /usr/local/etc/raddb/mods-available/eap

		make ca.pem
		make ca.der
		make server.pem
		make server.csr
		echo
		echo -e '\e[01;37;42mca and server certificates have been successfully created!\e[0m'

	# Restarts that pesky winbind service (It occasionally likes to break and say it has an error unless you restart it)
		echo
		echo -e '\e[01;34m+++ Restarting the Samba service...\e[0m'
		echo
		service winbind restart
		echo
		echo -e '\e[01;37;42mThe Samba service has been successfully restarted!\e[0m'
		echo
}
function freeradiusClient()
{
	# Gets the domain and domain controller's names
		echo -e '\e[33mPlease type in the IP of the client (the AP you want to use WPA-Enterprise with):\e[0m'
		echo -e '\e[33;01mFor Example:  192.168.1.5\e[0m'
		read client_ip
		echo -e '\e[33mPlease type in the secret for your client :\e[0m'
		echo -e '\e[33;01mFor Example:  testing123\e[0m'
		read secret
		cat <<EOI>> /usr/local/etc/raddb/clients.conf

client $client_ip {
        secret = $secret
        shortname = $client_ip
        nas_type = other
}
EOI
}
function doAll()
{
	# Calls Function 'check_joinDomain'
		check_joinDomain

	# Calls Function 'freeradiusInstall'
		echo -e "\e[33m=== Install FreeRADIUS ? (y/n)\e[0m"
		read yesno
		if [ "$yesno" = "y" ]; then
			freeradiusInstall
		fi

	# Calls Function 'configureFreeradius'
		echo -e "\e[33m=== Configure FreeRADIUS for Active Directory Authentication with PEAP ? (y/n)\e[0m"
		read yesno
		if [ "$yesno" = "y" ]; then
			configureFreeradius
		fi

	# Calls Function 'freeradiusCerts'
		echo -e "\e[33m=== Configure the FreeRADIUS SSL Certificates ? (y/n)\e[0m"
		read yesno
		if [ "$yesno" = "y" ]; then
			freeradiusCerts
		fi

	# Calls Function 'freeradiusClient'
		echo -e "\e[33m=== Setup a FreeRADIUS client ? (y/n)\e[0m"
		read yesno
		if [ "$yesno" = "y" ]; then
			freeradiusClient
		fi

	# End of Script Congratulations, Farewell and Additional Information
		clear
		FARE=$(cat << 'EOZ'


          \e[01;37;42mWell done! You have completed your FreeRADIUS Installation!\e[0m
    \e[31;01mNOTE: "domain admins" was the only group added to the /etc/sudoers file\e[0m

  \e[30;01mCheckout similar material at midactstech.blogspot.com and github.com/Midacts\e[0m

                            \e[01;37m########################\e[0m
                            \e[01;37m#\e[0m \e[31mI Corinthians 15:1-4\e[0m \e[01;37m#\e[0m
                            \e[01;37m########################\e[0m
EOZ
)

		#Calls the End of Script variable
		echo -e "$FARE"
		echo
		echo
		exit 0
}

# Check privileges
[ $(whoami) == "root" ] || die "You need to run this script as root."

# Welcome to the script
clear
echo
echo
echo -e '               \e[01;37;42mWelcome to Midacts Mystery'\''s FreeRADIUS Installer!\e[0m'
echo
case "$go" in
        * )
                        doAll ;;
esac

exit 0
