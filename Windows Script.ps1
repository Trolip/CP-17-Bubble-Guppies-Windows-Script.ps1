#The next three code inputs (4,7,10) must be run manually before the script is run.

#Enables script running
#Set-ExecutionPolicy Unrestricted
#y

#Download the script in Windows / change the name to your current user
#Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Trolip/CP-17-Bubble-Guppies-Windows-Script.ps1/refs/heads/main/Windows%20Script.ps1" -OutFile C:\Users\ashepard\Downloads\Script.ps1

#run script / change name to current user
#C:\Users\ashepard\Downloads\Script.ps1

#find .mp3 files
Get-ChildItem -Path "C:\Users" -Filter "*.mp3" -Force -Recurse
write-host "Go delete these mp3 files before continuing the script. Press Enter to continue"
read-host

#rename local user / fix
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
auditpol /restore /file:audit.csv
AuditPol /set /subcategory:"Object Access" /success:enable /failure:enable
auditpol /get /category:*
read-host "Check the audits to make sure they are all set. Then, press Enter to continue..."

#secedit policy/fix
secedit /import /cfg:Password Policies.inf
read-host "Check the audits to make sure they are all set. Then, press Enter to continue..."

                                                            #FIREWALL
# enable Windows Defender firewall in advanced and logging
Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultInboundAction Block -DefaultOutboundAction Allow
Set-NetFirewallProfile -Profile Domain,Public,Private -LogFileName "C:\FirewallLog.log" -LogAllowed True -LogBlocked True -LogIgnored True

#UPnP is not enabled
Get-NetFirewallRule -DisplayGroup "Network Discovery" | Where-Object { $_.Enabled -eq "False" }

#Windows Defender no longer runs in passive mode'
Set-MpPreference -DisableRealtimeMonitoring $false

Get-NetFirewallProfile
read-host "Check the firewall domain, private, and public for blocked inbound action and allowed outbound action. Then, press Enter to continue..."


#Enable Windows firewall and cloud-delivered protection
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableAntiSpyware $false
Set-MpPreference -CloudBlockLevel 2
Start-Service -Name WinDefend
Set-Service -Name WinDefend -StartupType Automatic

                                              #SERVICES, PROCESSES, AND OPTIONAL FEATURES
#stop process
#Get-Process


#disable FTP
Stop-Service -Name ftpsvc
Set-Service -Name ftpsvc -StartupType Disabled
Disable-WindowsOptionalFeature -Online -FeatureName "IIS-FTPServer" -Remove

#Windows Automatic Updates are enabled'
Set-Service -Name wuauserv -StartupType Automatic
Start-Service -Name wuauserv

#Disable AutoPlay for all drives
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 1

#Disable AutoPlay for CD/DVD and other media types
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 0x000000FF

#The system requires approval from an administrator before running unknown software and Users cannot bypass attempts to run unknown software
Set-MpPreference -EnableSmartScreen $true

#Windows SmartScreen configured to warn or block
Set-MpPreference -EnableSmartScreen $true -SmartScreenAppInstallControl "Block"

#World Wide Web Publishing service has been stopped and disabled
Stop-Service -Name w3svc

#disable Bitlocker
Disable-BitLocker -MountPoint "C:"

#Windows Event Log service is running
Start-Service -Name eventlog

#Removed Telnet from Windows features
Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient

#stop services
Get-Service
Set-Service -Name "nc.exe" -StartupType "Disabled"

#Windows Update services are running (WaaSMedicSvc)
Start-Service -Name WaaSMedicSvc
                                                            #USERS
#password for users
$password = ConvertTo-SecureString "20-R1p-CdR-24" -AsPlainText -Force
                                                              #EDIT
#create users
get-localuser
$names = @()
while ($true) {
  $input = read-host "Add the name of a user that should be deleted or DONE to continue the script."
  if ($input -eq "DONE") {
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
  $input = read-host "Add the name of a user that should be deleted or DONE to continue the script."
  if ($input -eq "DONE") {
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
  $input = read-host "Enter 1 to add a user to a group, 2 to create a group, or DONE to continue the script."
  if ($input -eq "DONE") {
    break
  }
  elseif ($input -eq "1") {
    $username = read-host "Enter the name of a user who will be joining a group."
    $group = read-host "Enter the group name that they'll be joining."
    Add-LocalGroupMember -Group $group -Member $username
  }
 elseif ($input -eq "2") {
    $group = read-host "Enter the group name that will be created."
    New-LocalGroup -Name $group
  }
}

#remove users from a group / delete groups
get-localuser
$names = @()
while ($true) {
  $input = read-host "Enter 1 to remove a user from a group, 2 to delete a group, or DONE to continue the script."
  if ($input -eq "DONE") {
    break
  }
  elseif ($input -eq "1") {
    $username = read-host "Enter the name of a user who will be removed from a group."
    $group = read-host "Enter the group name they'll be leaving."
    Remove-LocalGroupMember -Group $group -Member $username
  }
 elseif ($input -eq "2") {
    $group = read-host "Enter the group name that will be created."
    New-LocalGroup -Name $group
  }
}

#limit local use of a blank password to console only
Set-LocalUser -Name "UserName" -PasswordNeverExpires $false
                                                                #FIX
#see if users have a good password and set their password to a predetermined value
#foreach (get-localuser -Group "Users") {
  #if(

                                                              

                                                                                  #REGISTRY

#DO not allow anonymous enumeration of SAM accounts
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1

#restrict global object creation
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RestrictGlobalObjects" -Value 1

#RDP Security Layer set to SSL
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "SecurityLayer" -Value 1

#passwords stored using reversible encryption
Set-ADDomain -Identity "DomainName" -AllowReversiblePasswordEncryption $false

#LAN Manager only sends NTLMv2 responses'
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5

#NULL session fallback is prohibited'
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1

#Elevation prompts run on the secure desktop'
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1

#Users cannot add or logon with Microsoft accounts'
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoConnectedUser" -Value 1

#Nobody can access Credential Manager as a trusted caller'
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI" -Name "DisableDomainCreds" -Value 1

#Firefox profiles and sync disabled'
Set-ItemProperty -Path "HKCU:\Software\Mozilla\Firefox" -Name "FirefoxProfile" -Value ""

#Core dumps are disabled on system crash'
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -Value 0

#Only administrators can install printer drivers'
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Print\Environments\Windows x64\Drivers" -Name "RestrictDriverInstall" -Value 1

#File/registry write failures are virtualized to per-user locations'
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableVirtualization" -Value 1

#App notifications do not show on the lock screen
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" -Value 0

#User access to the Store application is prohibited'
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -Value 1

#UEFI Secure Boot is enabled'
Get-WmiObject -Class Win32_BIOS | Select-Object SecureBoot

#RDP connections require SSL'
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "SecurityLayer" -Value 1

#RDP requires a secure RPC connection'
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1

#The system is configured to use FIPS 140 compliant cryptographic algorithms'
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "FIPSAlgorithmPolicy" -Value 1

#check for hidden network shares
Get-WmiObject -Class Win32_Share | Where-Object { $_.Type -eq 0 }

#stop process
Get-Process
Stop-Process -Name "notepad"
Stop-Process -Id 1234

                                                                              #UPDATES
#update firefox
if(Get-ChildItem "C:\Program Files\Mozilla Firefox" -Recurse -Filter firefox.exe -or Get-ChildItem "C:\Program Files (x86)\Mozilla Firefox" -Recurse -Filter firefox.exe
){
 winget upgrade "Mozilla Firefox"
}

#update chrome
if(Get-ChildItem "C:\Program Files\Google Chrome" -Recurse -Filter Chrome.exe -or Get-ChildItem "C:\Program Files (x86)\Google Chrome" -Recurse -Filter chrome.exe
){
  winget upgrade "Google Chrome"
}

#update mozilla thunderbird
if(Get-ChildItem "C:\Program Files\Mozilla Thunderbird" -Recurse -Filter thunderbird.exe -or Get-ChildItem "C:\Program Files (x86)\Mozilla Thunderbird" -Recurse -Filter thunderbird.exe
){
  winget upgrade "Mozilla Thunderbird"
}

#notepad updated
if(Get-ChildItem "C:\Program Files\Notepad" -Recurse -Filter notepad.exe -or Get-ChildItem "C:\Program Files (x86)\Notepad" -Recurse -Filter notepad.exe
){
  winget upgrade "Notepad"
}

#updates all apps
winget upgrade --all

#removed Wireshark
winget uninstall "Wireshark"

#removed npcap
winget uninstall "Npcap"
                                                          
#windows update majority
Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser
Install-WindowsUpdate -AcceptAll -AutoReboot

#Find-Script
find-script

#check for shell backdoor in windows/systemresources
Get-ChildItem -Path "C:\Windows\System32" -Recurse -Include *backdoor*

#Restart the computer
Restart-computer

write-host "Script Finished"

#Disables script running
Set-ExecutionPolicy Restricted
