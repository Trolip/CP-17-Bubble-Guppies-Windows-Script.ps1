read-host "Before running this script, please go document all the info in the readme. Press enter to continue."

#rename local user
if(get-localuser -name Administator) {
  rename-localuser Administator ExPerson1
  Disable-LocalUser -Name ExPerson1
  
}
if(get-localuser -name Guest) {
  rename-localuser Guest ExPerson2
  Disable-LocalUser -Name ExPerson2
}
$current_user = (Get-ChildItem Env:USERNAME).Value
New-Item -Path C:\Users\$current_user\Desktop  -name "God Mode.{ED7BA470-8E54-465E-825C-99712043E01C}" -ItemType Directory
                                                            #SECPOL
#audit policy / fix
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Trolip/CP-17-Bubble-Guppies-Windows-Script.ps1/refs/heads/main/Machine/Microsoft/Windows%20NT/Audit/audit.csv" -OutFile C:\Users\$current_user\Downloads\audit.csv
Invoke-WebRequest -Uri "https://github.com/Trolip/CP-17-Bubble-Guppies-Windows-Script.ps1/blob/main/Machine/Registry.pol" -OutFile C:\Users\$current_user\Downloads\machine.pol
Invoke-WebRequest -Uri "https://github.com/Trolip/CP-17-Bubble-Guppies-Windows-Script.ps1/blob/main/User/Registry.pol" -OutFile C:\Users\$current_user\Downloads\user.pol
Invoke-WebRequest -Uri "https://github.com/Trolip/CP-17-Bubble-Guppies-Windows-Script.ps1/blob/main/LGPO/LGPO_30/LGPO.exe" -OutFile C:\Users\$current_user\Downloads\LGPO.exe
C:\Users\$current_user\Downloads\LGPO.exe /ac C:\Users\$current_user\Downloads\audit.csv
C:\Users\$current_user\Downloads\LGPO.exe /m C:\Users\$current_user\Downloads\machine.pol
C:\Users\$current_user\Downloads\LGPO.exe /U C:\Users\$current_user\Downloads\user.pol
C:\Users\$current_user\Downloads\LGPO.exe /g C:\Users\$current_user\Downloads\machine.pol
C:\Users\$current_user\Downloads\LGPO.exe /g C:\Users\$current_user\Downloads\user.pol
read-host "Check audit policies and advanced audit policies to make sure that they are set. Then, press Enter to continue..."

#secedit
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Trolip/CP-17-Bubble-Guppies-Windows-Script.ps1/refs/heads/main/Secpol.inf" -OutFile C:\Windows\System32\Secpol.inf
secedit /configure /db C:\Windows\security\local.sdb /cfg "Secpol.inf" /areas SECURITYPOLICY GROUP_MGMT USER_RIGHTS REGKEYS FILESTORE SERVICES
read-host "Check local security policy to make sure they are all set. Then, press Enter to continue..."

                                                            #FIREWALL
# enable Windows Defender firewall in advanced and logging
Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultInboundAction Block -DefaultOutboundAction Allow
Set-NetFirewallProfile -Profile Domain, Public, Private -LogFileName "C:\FirewallLog.log" -LogAllowed True -LogBlocked True -LogIgnored True
#add rules that block insecure ports

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
#Disable Services
stop-service -name nc | set-service -name nc.exe -startuptype Disabled
#AllJoyn Router Service
stop-service -name AJRouter | set-service -name AJRouter -startuptype Disabled
#AssignedAccessManager
stop-service -name AssignedAccessManagerSvc | set-service -name AssignedAccessManagerSvc -startuptype Disabled
#BitLocker Drive Encryption.
stop-service -name BDESVC | set-service -name BDESVC -startuptype Disabled
#Bluetooth Audio Gateway Service, Bluetooth Support Service, and Bluetooth User Support Service.
stop-service -name BTAGService | set-service -name BTAGService -startuptype Disabled
stop-service -name bthserv | set-service -name bthserv -startuptype Disabled
stop-service -name BluetoothUserService_63bcf | set-service -name BluetoothUserService_63bcf -startuptype Disabled
#Connected User Experiences and Telemetry.
stop-service -name DiagTrack | set-service -name DiagTrack -startuptype Disabled
#DevicePicker.
stop-service -name DevicePickerUserSvc_63bcf | set-service -name DevicePickerUserSvc_63bcf -startuptype Disabled
#Diagnostic Execution Service, Diagnostic Policy Service, Diagnostic Service Host, and Diagnostic System Host.
stop-service -name DiagTrack | set-service -name DiagTrack -startuptype Disabled
stop-service -name DiagTrack | set-service -name DiagTrack -startuptype Disabled
stop-service -name DiagTrack | set-service -name DiagTrack -startuptype Disabled
stop-service -name DiagTrack | set-service -name DiagTrack -startuptype Disabled
#Fax.
stop-service -name Fax | set-service -name Fax -startuptype Disabled
#Geolocation Service and Downloaded Maps Manager.
stop-service -name lfsvc | set-service -name lfsvc -startuptype Disabled
stop-service -name MapsBroker | set-service -name MapsBroker -startuptype Disabled
#Optimize Drives. 
stop-service -name defragsvc | set-service -name defragsvc -startuptype Disabled
#Parental Controls.
stop-service -name WpcMonSvc | set-service -name WpcMonSvc -startuptype Disabled
#Phone Service.
stop-service -name PhoneSvc | set-service -name PhoneSvc -startuptype Disabled
#Print Spooler. 
stop-service -name Spooler | set-service -name Spooler -startuptype Disabled
#Remote Desktop
while (true){
  $input = read-host "Enter 1 to disable remote desktop, 2 to enable it, or done to continue the script."
    if ($input -eq "done") {
      break
    }
    elseif ($input -eq "1") {
      stop-service -name SessionEnv | set-service -name SessionEnv -startuptype Disabled
      stop-service -name TermService | set-service -name TermService -startuptype Disabled
      stop-service -name UmRdpService | set-service -name UmRdpService -startuptype Disabled
      stop-service -name WinRM | set-service -name WinRM -startuptype Disabled
      Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-RemoteDesktopConnection" -Remove
    }
    elseif ($input -eq "2") {
      set-service -name SessionEnv -startuptype automatic | start-service -name SessionEnv
      set-service -name TermService -startuptype automatic | start-service -name TermService
      set-service -name UmRdpService -startuptype automatic | start-service -name UmRdpService
      set-service -name WinRM -startuptype automatic | start-service -name WinRM
    }
}
#Sensor Service.
stop-service -name SensorService | set-service -name SensorService -startuptype Disabled
#Smart Card, Smart Card Device Enumeration Service, and Smart Card Removal Policy.
stop-service -name SCardSvr | set-service -name SCardSvr -startuptype Disabled
stop-service -name ScDeviceEnum | set-service -name ScDeviceEnum -startuptype Disabled
stop-service -name SCPolicySvc | set-service -name SCPolicySvc -startuptype Disabled
#WalletService.
stop-service -name WalletService | set-service -name WalletService -startuptype Disabled
#Window Insider Service.
stop-service -name wisvc | set-service -name wisvc -startuptype Disabled
#Windows Biometric Service.
stop-service -name WbioSrvc | set-service -name WbioSrvc -startuptype Disabled
#Windows Mobile Hotspot Service.
stop-service -name icssvc | set-service -name icssvc -startuptype Disabled
#Xbox Accessory Management Service, Xbox Live Auth Manager, Xbox Live Game Save, and Xbox Live Networking Service.
stop-service -name XboxGipSvc | set-service -name XboxGipSvc -startuptype Disabled
stop-service -name XblAuthManager | set-service -name XblAuthManager -startuptype Disabled
stop-service -name XblGameSave | set-service -name XblGameSave -startuptype Disabled
stop-service -name XboxNetApiSvc | set-service -name XboxNetApiSvc -startuptype Disabled
#Remote Procedure Call (RPC) Locator
stop-service -name RpcLocator | set-service -name RpcLocator -startuptype Disabled
#Simple Network Management Protocol (SNMP)
#stop-service -name RpcLocator | set-service -name RpcLocator -startuptype Disabled
#World Wide Web Publishing service has been stopped and disabled
Stop-Service -Name w3svc | set-service -name w3svc -startuptype disabled
#UPnP is not enabled
Stop-Service -Name upnphost | Set-Service -Name upnphost -StartupType Disabled
#disable Bitlocker
Disable-BitLocker -MountPoint "C:"
#disable FTP
Stop-Service -Name ftpsvc | Set-Service -Name ftpsvc -StartupType Disabled
Disable-WindowsOptionalFeature -Online -FeatureName "IIS-FTPServer" -Remove
#Removed Telnet from Windows features
Disable-WindowsOptionalFeature -Online -FeatureName "TelnetClient" -remove
#disable smbv1 protocol
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -remove
#disable powershellv2
Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -remove
#disable tftp
Disable-WindowsOptionalFeature -Online -FeatureName "TFTPClient" -remove
#disable legacy scripts
Disable-WindowsOptionalFeature -Online -FeatureName "IIS-LegacyScripts" -remove
#disable legacy componenets
Disable-WindowsOptionalFeature -Online -FeatureName "LegacyComponenets" -Remove



#start services
#Windows Update services are running
set-service -name WaasMedicSVC -startuptype automatic | Start-Service -Name WaaSMedicSvc
#Windows Defender Advanced Threat Protection Service
#set-service -name WaasMedicSVC -startuptype automatic | Start-Service -Name WaaSMedicSvc
#Windows Defender Antivirus Service
#set-service -name WaasMedicSVC -startuptype automatic | Start-Service -Name WaaSMedicSvc
#Windows Defender Antivirus Network Inspection Service
#set-service -name WaasMedicSVC -startuptype automatic | Start-Service -Name WaaSMedicSvc
#Windows Security Service
set-service -name SecurityHealthService -startuptype automatic | Start-Service -Name SecurityHealthService
#Windows Defender Firewall
set-service -name mpssvc -startuptype automatic | Start-Service -Name mpssvc
#Windows Event Log
set-service -name EventLog -startuptype automatic | Start-Service -Name EventLog
#Security Center
set-service -name wscsvc -startuptype automatic | Start-Service -Name wscsvc
#CCS Client
set-service -name CCSClient -startuptype automatic | Start-Service -Name CCSClient
#Windows Automatic Updates are enabled'
Set-Service -Name wuauserv -StartupType Automatic | Start-Service -Name wuauserv
#Windows Event Log service is running
set-service -name eventlog -startuptype automatic | Start-Service -Name eventlog
#Group policy
set-service -name gpsvc -startuptype automatic | start-service -name gpsvc 
#The system requires approval from an administrator before running unknown software and Users cannot bypass attempts to run unknown software
Set-MpPreference -EnableSmartScreen $true
#Windows SmartScreen configured to warn or block
Set-MpPreference -EnableSmartScreen $true -SmartScreenAppInstallControl "Block"
}

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

#RDP Security Layer set to SSL
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "SecurityLayer" -Value 1

#LAN Manager only sends NTLMv2 responses'
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5

#NULL session fallback is prohibited'
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1


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

#disable rdp
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
read-host "Wait a minute or two for your score to update. If you lose points, RDP can be reenabled in Windows settings just search for RDP and turn it on. Press enter to continue."

#The system is configured to use FIPS 140-compliant cryptographic algorithms
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "FIPSAlgorithmPolicy" -Value 1


                                                                              #UPDATES
#install winget
Invoke-WebRequest -Uri "https://github.com/Trolip/CP-17-Bubble-Guppies-Windows-Script.ps1/blob/main/winget.exe" -OutFile C:\Program Files\WindowsApps\winget.exe
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

read-host "The script is finished. To make sure that settings are properly configured, go through the Battle Plan STEP BY STEP. DON'T SKIP ANYTHING. Fix any settings that weren't already done by the script, delete software, run updates, configure apps, delete mp3 files, and then try scrounging for points in group policies. You've got this! Press enter to continue."

#Disables script running
Set-ExecutionPolicy Restricted
