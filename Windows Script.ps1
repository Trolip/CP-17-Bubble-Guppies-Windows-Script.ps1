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
import module .\services.psm1
disableservices{}
startservices{}

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

#screensaver password

#check for hidden network shares
#Get-WmiObject -Class Win32_Share | Where-Object { $_.Type -eq 0 }

#stop process
#Get-Process
#Stop-Process -Name "notepad"
#Stop-Process -Id 1234

                                                                              #UPDATES
#install winget
$progressPreference = 'silentlyContinue'
Write-Host "Installing WinGet PowerShell module from PSGallery..."
Install-PackageProvider -Name NuGet -Force | Out-Null
Install-Module -Name Microsoft.WinGet.Client -Force -Repository PSGallery | Out-Null
Write-Host "Using Repair-WinGetPackageManager cmdlet to bootstrap WinGet..."
Repair-WinGetPackageManager
Write-Host "Done."
update firefox
if(Get-ChildItem "C:\Program Files\Mozilla Firefox" -Recurse -Filter firefox.exe -or Get-ChildItem "C:\Program Files (x86)\Mozilla Firefox" -Recurse -Filter firefox.exe
){
 winget upgrade "Mozilla Firefox"
}

#update chrome
if(Get-ChildItem "C:\Program Files\Google Chrome" -Recurse -Filter Chrome.exe -or Get-ChildItem "C:\Program Files (x86)\Google Chrome" -Recurse -Filter chrome.exe
){
  winget upgrade "Google Chrome"
}

update mozilla thunderbird
if(Get-ChildItem "C:\Program Files\Mozilla Thunderbird" -Recurse -Filter thunderbird.exe -or Get-ChildItem "C:\Program Files (x86)\Mozilla Thunderbird" -Recurse -Filter thunderbird.exe
){
  winget upgrade "Mozilla Thunderbird"
}

notepad updated
if(Get-ChildItem "C:\Program Files\Notepad" -Recurse -Filter notepad.exe -or Get-ChildItem "C:\Program Files (x86)\Notepad" -Recurse -Filter notepad.exe
){
  winget upgrade "Notepad"
}

updates all apps
winget upgrade --all

removed Wireshark
winget uninstall "Wireshark"

removed npcap
winget uninstall "Npcap"
                                                          
windows update majority
Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser
Install-WindowsUpdate -AcceptAll -AutoReboot

read-host "The script is finished. To make sure that settings are properly configured, go through the Battle Plan STEP BY STEP. DON'T SKIP ANYTHING. Fix any settings that weren't already done by the script, delete software, run updates, configure apps, delete mp3 files, and then try scrounging for points in group policies. You've got this! Press enter to continue."

#Disables script running
Set-ExecutionPolicy Restricted
