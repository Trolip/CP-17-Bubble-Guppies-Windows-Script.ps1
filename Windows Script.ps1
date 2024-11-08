#Enables script running
Set-ExecutionPolicy Unrestricted

#rename local user 
if(get-localuser -name Administator) {
  (rename-localuser Administator ExAdmin)
}
if(get-localuser -name Guest) {
  (rename-localuser Administator ExGuest)
}
#audit policy
auditpol /restore /file\audit.csv

#secedit policy
secedit /import /cfg\Password Policies.inf

#windows defender firewall in advanced
Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultInboundAction Block -DefaultOutboundAction Allow
Get-NetFirewallProfile
#disable FTP
Disable-WindowsOptionalFeature -FeatureName "Microsoft-Ftp-Client" -Online -NoRestart
#todo
#removed unauth users
#change users from admin to standard and back
#see if users have a good password and set their password to a predetermined value
#enable windows firewall
#disable auto play
#Windows SmartScreen configured to warn or block
#World Wide Web Publishing service has been stopped and disabled
#update firefox
#update chrome
#update mozilla thunderbird
#remove media files
#RDP network level authentication enabled
#disables script running
#firewall enabled
#google chrome updated
#notepad updated
#removed wireshark
#limit local use of blank password to console only
#DO not allow anonoymous enumeration of SAM accounts
#Disable FTP
#windows updates majority
restrict global object creation
RDP Security Layer set to SSL
Set-ExecutionPolicy Restricted
