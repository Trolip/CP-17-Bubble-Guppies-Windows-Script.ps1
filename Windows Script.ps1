#Enables script running
#Set-ExecutionPolicy Unrestricted

#Download script in windows / change the name to your current user
#Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Trolip/CP-17-Bubble-Guppies-Windows-Script.ps1/refs/heads/main/Windows%20Script.ps1" -OutFile C:\Users\ashepard\Downloads\Script.ps1

#run script
#C:\Users\ashepard\Downloads\Script.ps1

#rename local user / fix
if(get-localuser -name Administator) {
  rename-localuser Administator ExAdmin
  Disable-LocalUser -Name ExAdmin
  
}
if(get-localuser -name Guest) {
  rename-localuser Guest ExGuest
  Disable-LocalUser -Name ExGuest
}

#audit policy / fix
auditpol /restore /file\audit.csv

#secedit policy / fix
secedit /import /cfg\Password Policies.inf

#windows defender firewall in advanced
Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultInboundAction Block -DefaultOutboundAction Allow
Get-NetFirewallProfile

#disable FTP / fix
Disable-WindowsOptionalFeature -FeatureName Microsoft-Ftp-Client -Online -NoRestart
#todo

#create users/change name and replicate for each user
$Password = ConvertTo-SecureString "20-R1p-CdR-24" -AsPlainText -Force
New-LocalUser -Name "JohnDoe" -Password $Password 

#Add users to a group/change group and member names as needed
Add-LocalGroupMember -Group "Users" -Member "JohnDoe", "JaneSmith"
#removed unauth users
Remove-localuser -Name "JohnDoe"
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
#restrict global object creation
#RDP Security Layer set to SSL
#log allowed, blocked, and ignored for advanced windows firewall
#Disable-Bitlocker
#Find-Script
#stop services
Set-Service -Name "wuauserv" -StartupType "Disabled"
Get-Service
#stop process
Get-Process
Stop-Process -Name "notepad"
Stop-Process -Id 1234



#Disables script running
Set-ExecutionPolicy Restricted
