read-host "Before running this script, please go document all the info in the readme. Press enter to continue."
#rename local user
if(get-localuser -name Administator) {
  rename-localuser Administator ExAdmin
  Disable-LocalUser -Name ExAdmin
  
}
if(get-localuser -name Guest) {
  rename-localuser Guest ExGuest
  Disable-LocalUser -Name ExGuest
}
                                                            
                                                            #SECPOL
#audit policy / fix
auditpol /restore /file:.\audit.csv
C:\Users\ashepard\Downloads\audit.csv
#auditpol /set /category:* /file:C:\Users\ashepard\Downloads\audit.csv
#AuditPol /set /subcategory:"Object Access" /success:enable /failure:enable
read-host "Check the audits to make sure they are all set. Then, press Enter to continue..."

#secedit
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Trolip/CP-17-Bubble-Guppies-Windows-Script.ps1/refs/heads/main/Windows%20Script.ps1" -OutFile C:\Windows\System32\Secpol.inf
secedit /configure /db C:\Windows\security\local.sdb /cfg "Secpol.inf" /areas SECURITYPOLICY GROUP_MGMT USER_RIGHTS REGKEYS FILESTORE SERVICES
read-host "Check local security policy to make sure they are all set. Then, press Enter to continue..."

                                                            #FIREWALL
# enable Windows Defender firewall in advanced and logging
Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultInboundAction Block -DefaultOutboundAction Allow
Set-NetFirewallProfile -Profile Domain, Public, Private -LogFileName "C:\FirewallLog.log" -LogAllowed True -LogBlocked True -LogIgnored True

#Windows Defender no longer runs in passive mode'
Set-MpPreference -DisableRealtimeMonitoring $false

Get-NetFirewallProfile
read-host "Check the firewall domain, private, and public for blocked inbound action and allowed outbound action. Then, press Enter to continue..."


#Enable Windows firewall and cloud-delivered protection
Set-MpPreference -DisableAntiSpyware $false
Set-MpPreference -CloudBlockLevel 2
Start-Service -Name WinDefend
Set-Service -Name WinDefend -StartupType Automatic

                                              #SERVICES, PROCESSES, AND OPTIONAL FEATURES
AssignedAccessManager
BitLocker Drive Encryption.
Bluetooth Audio Gateway Service, Bluetooth Support Service, and Bluetooth User Support Service.
Connected User Experiences and Telemetry.
Diagnostic Execution Service, Diagnostic Policy Service, Diagnostic Service Host, and Diagnostic System Host.
Geolocation Service and Downloaded Maps Manager.
Optimize Drives. 
Parental Controls.
Phone Service.
Print Spooler. 
Remote Desktop Configuration, Remote Desktop Services, and Remote Desktop Services UserMode Port Redirector.
Sensor Service.
Smart Card, Smart Card Device Enumeration Service, and Smart Card Removal Policy.
Windows Biometric Service.
Windows Error Reporting Service.
Xbox Accessory Management Service, Xbox Live Auth Manager, Xbox Live Game Save, and Xbox Live Networking Service. 
Window Insider Service.
Fax. 
WalletService.
Windows Mobile Hotspot Service.
Touch Keyboard and Handwriting Panel Service. 
DevicePicker.
AllJoyn Router Service 
Adobe Acrobat Update Service.

#Server Message Block (SMB)
Service Name: srv2, lanmanserver

#NetBIOS
Service Name: NetBIOS, NetBT

#Remote Desktop Protocol (RDP)
Service Name: TermService

#Windows Remote Management (WinRM)
Service Name: WinRM

#Telnet
Service Name: Telnet

#Simple Network Management Protocol (SNMP)
Service Name: SNMP

#Windows Management Instrumentation (WMI)
Service Name: Winmgmt

#Print Spooler
Service Name: Spooler

#Bluetooth Support Service
Service Name: bthserv

#IPv6 (If Not Used)
Service Name: TCP/IP NetBIOS Helper

#Windows Insider Service
Service Name: wisvc

#Function Discovery
Service Name: fdPHost

#set secondary logon to disabled

#World Wide Web Publishing service has been stopped and disabled
Stop-Service -Name w3svc

#UPnP is not enabled
Stop-Service -Name upnphost
Set-Service -Name upnphost -StartupType Disabled

#stop services
stop-service -name nc
Set-Service -Name "nc.exe" -StartupType "Disabled"

#disable FTP
Stop-Service -Name ftpsvc
Set-Service -Name ftpsvc -StartupType Disabled
Disable-WindowsOptionalFeature -Online -FeatureName "IIS-FTPServer" -Remove

#Removed Telnet from Windows features
Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient
#disable smbv1 protocol
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
#disable powershellv2
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
#disable tftp
Disable-WindowsOptionalFeature -Online -FeatureName TFTPClient
#disable simple tcpip services
#Disable SNMP
#disable Internet Information Services
#disable Internet Information Services Hostable Web Core
#Windows Update services are running (WaaSMedicSvc)
Start-Service -Name WaaSMedicSvc

#Windows Automatic Updates are enabled'
Set-Service -Name wuauserv -StartupType Automatic
Start-Service -Name wuauserv

#Windows Event Log service is running
Start-Service -Name eventlog

#The system requires approval from an administrator before running unknown software and Users cannot bypass attempts to run unknown software
Set-MpPreference -EnableSmartScreen $true

#Windows SmartScreen configured to warn or block
Set-MpPreference -EnableSmartScreen $true -SmartScreenAppInstallControl "Block"

#disable Bitlocker
Disable-BitLocker -MountPoint "C:"

                                                            #USERS
#password for users
$password = ConvertTo-SecureString "20-R1p-CdR-24" -AsPlainText -Force
                                                              #EDIT
#create users
get-localuser
$names = @()
while ($true) {
  $input = read-host "Add the name of a user that should be created or done to continue the script."
  if ($input -eq "done") {
    break
  }
  else {
    $names += $input
    }
}
  
foreach ($name in $names) {
  New-LocalUser -Name $names -Password $password
  set-localuser -name $names -password $password
}




#removed unauthorized users
get-localuser
$names = @()
while ($true) {
  $input = read-host "Add the name of a user that should be deleted or done to continue the script."
  if ($input -eq "done") {
    break
  }
  else {
    $names += $input
  }
}
  
foreach ($name in $names) {
  Remove-localuser -Name $name
}

#add users to a group / create groups
get-localgroup
while ($true) {
  $input = read-host "Enter 1 to add a user to a group, 2 to create a group, or done to continue the script."
  if ($input -eq "done") {
    break
  }
  elseif ($input -eq "1") {
    $username = read-host "Enter the name of a user who will be joining a group."
    $group = read-host "Enter the group name they'll be joining."
    Add-LocalGroupMember -Group $group -Member $username
  }
 elseif ($input -eq "2") {
    $group = read-host "Enter the group name that will be created."
    New-LocalGroup -Name $group
  }
}

#remove users from a group / delete groups
Get-LocalGroup
$names = @()
while ($true) {
  $input = read-host "Enter 1 to remove a user from a group, 2 to delete a group, or done to continue the script."
  if ($input -eq "done") {
    break
  }
  elseif ($input -eq "1") {
    $group = read-host "Enter the group name they'll be leaving."
    Get-LocalGroupMember -Group "GroupName"
    $username = read-host "Enter the name of a user who will be removed from a group."
    Remove-LocalGroupMember -Group $group -Member $username
  }
 elseif ($input -eq "2") {
   $group = read-host "Enter the group name that will be deleted."
   remove-LocalGroup -Name $group
  }
}

#limit local use of a blank password to console only
Set-LocalUser -Name "UserName" -PasswordNeverExpires $false


                                                              
#delete proxies that allow for MitM attacks
netsh interface portproxy delete v4tov4
                                                        #REGISTRY

#DO not allow anonymous enumeration of SAM accounts
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1

#restrict global object creation
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RestrictGlobalObjects" -Value 1

#RDP Security Layer set to SSL
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "SecurityLayer" -Value 1

#passwords stored using reversible encryption
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "AllowPasswordsToBeStoredUsingReversibleEncryption" -Value 0

#LAN Manager only sends NTLMv2 responses'
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5

#NULL session fallback is prohibited'
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1

#Elevation prompts run on the secure desktop'
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1

#Users cannot add or logon with Microsoft accounts
read-host "Go to security options in local security policies and enable Accounts: Block Microsoft accounts. Press enter to continue."

#Nobody can access Credential Manager as a trusted caller
read-host "Navigate to gpedit.msc. Press enter to continue."
read-host "Go to Computer Configuration > Administrative Templates > System > Credentials Delegation. Press enter to continue."
read-host "disable the following policies to ensure Credential Manager is protected:. Press enter to continue."
write-host "Allow delegating saved credentials with NTLM-only server authentication"
write-host "Allow delegating saved credentials with NTLM authentication"
write-host "Allow delegating saved credentials"
read-host "Press enter when you are ready to move on"


#Firefox profiles and sync disabled'
Set-ItemProperty -Path "HKCU:\Software\Mozilla\Firefox" -Name "FirefoxProfile" -Value ""

#Core dumps are disabled on system crash'
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -Value 0

#Only administrators can install printer drivers
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Print\Environments\Windows x64\Drivers" -Name "RestrictDriverInstall" -Value 1

#File/registry write failures are virtualized to per-user locations
read-host "navigate to gpedit.msc. Press enter to continue."
read-host "Go to Computer Configuration > Administrative Templates > Windows Components > User Account Control. Press enter to continue."
write-host "Find and disable the Policy:"
write-host "Virtualize file and registry write failures to per-user locations"
read-host "Press enter to move on."

#App notifications do not show on the lock screen
#Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" -Value 0

#User access to the Store application is prohibited'
read-host "navigate to gpedit.msc. Press enter to continue."
read-host "Go to Computer Configuration > Administrative Templates > Windows Components > Store. Press enter to continue."
write-host "Find and disable the Policy:"
write-host "Locate the policy: Turn off the Store application"
read-host "Press enter to move on."

#UEFI Secure Boot is enabled
Get-WmiObject -Class Win32_BIOS | Select-Object SecureBoot

#RDP connections require SSL'
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "SecurityLayer" -Value 1

#disable rdp
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
read-host "Wait a minute or two for your score to update. If you lose points, RDP can be reenabled in Windows settings just search for RDP and turn it on. Press enter to continue."

#The system is configured to use FIPS 140-compliant cryptographic algorithms
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "FIPSAlgorithmPolicy" -Value 1

#check for hidden network shares
#Get-WmiObject -Class Win32_Share | Where-Object { $_.Type -eq 0 }

#stop process
#Get-Process
#Stop-Process -Name "notepad"
#Stop-Process -Id 1234

                                                                              #UPDATES
#install winget

#update firefox
#if(Get-ChildItem "C:\Program Files\Mozilla Firefox" -Recurse -Filter firefox.exe -or Get-ChildItem "C:\Program Files (x86)\Mozilla Firefox" -Recurse -Filter firefox.exe
#){
# winget upgrade "Mozilla Firefox"
#}

#update chrome
#if(Get-ChildItem "C:\Program Files\Google Chrome" -Recurse -Filter Chrome.exe -or Get-ChildItem "C:\Program Files (x86)\Google Chrome" -Recurse -Filter chrome.exe
#){
 # winget upgrade "Google Chrome"
#}

#update mozilla thunderbird
#if(Get-ChildItem "C:\Program Files\Mozilla Thunderbird" -Recurse -Filter thunderbird.exe -or Get-ChildItem "C:\Program Files (x86)\Mozilla Thunderbird" -Recurse -Filter thunderbird.exe
#){
 # winget upgrade "Mozilla Thunderbird"
#}

#notepad updated
#if(Get-ChildItem "C:\Program Files\Notepad" -Recurse -Filter notepad.exe -or Get-ChildItem "C:\Program Files (x86)\Notepad" -Recurse -Filter notepad.exe
#){
#  winget upgrade "Notepad"
#}

#updates all apps
#winget upgrade --all

#removed Wireshark
#winget uninstall "Wireshark"

#removed npcap
#winget uninstall "Npcap"
                                                          
#windows update majority
#Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser
#Install-WindowsUpdate -AcceptAll -AutoReboot

#Find-Script
#find-script

#check for shell backdoor in windows/systemresources
#Get-ChildItem -Path "C:\Windows\System32" -Recurse -Include *backdoor*

#Restart the computer
#Restart-computer

read-host "The script is finished. To make sure that settings are properly configured, go through the Battle Plan STEP BY STEP. DON'T SKIP ANYTHING. Fix any settings that weren't already done by the script, delete software, run updates, configure apps, delete mp3 files, and then try scrounging for points in group policies. You've got this! Press enter to continue."

#Disables script running
Set-ExecutionPolicy Restricted
