#The next three code inputs (4,7,10) must be run manually before the script is run.

#Enables script running
#Set-ExecutionPolicy Unrestricted

#Download the script in Windows / change the name to your current user
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
auditpol /restore /file:audit.csv

#secedit policy/fix
secedit /import /cfg:Password Policies.inf

# Windows Defender firewall in advanced
Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultInboundAction Block -DefaultOutboundAction Allow
Get-NetFirewallProfile

#disable FTP / fix
Stop-Service -Name ftpsvc
Set-Service -Name ftpsvc -StartupType Disabled
Disable-WindowsOptionalFeature -Online -FeatureName "IIS-FTPServer" -Remove

                                                                  #todo
#create users/change name and replicate the second line for each user
$Password = ConvertTo-SecureString "20-R1p-CdR-24" -AsPlainText -Force
New-LocalUser -Name "JohnDoe" -Password $Password 

#Add users to a group/change group and member names as needed
Add-LocalGroupMember -Group "Users" -Member "JohnDoe", "JaneSmith"

#removed unauthorized users
Remove-localuser -Name "JohnDoe"

#change users from admin to standard and back
Add-LocalGroupMember -Group "Administrators" -Member "JohnDoe"
Remove-LocalGroupMember -Group "Administrators" -Member "JohnDoe"

#see if users have a good password and set their password to a predetermined value

#Enable Windows firewall and cloud-delivered protection
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableAntiSpyware $false
Set-MpPreference -CloudBlockLevel 2
Start-Service -Name WinDefend
Set-Service -Name WinDefend -StartupType Automatic

#disable auto-play
#Disable AutoPlay for all drives
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 1
#Disable AutoPlay for CD/DVD and other media types
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 0x000000FF

#Windows SmartScreen configured to warn or block
Set-MpPreference -EnableSmartScreen $true -SmartScreenAppInstallControl "Block"

#World Wide Web Publishing service has been stopped and disabled
Stop-Service -Name w3svc

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
#updates all apps
winget upgrade --all

#remove media files
#RDP network level authentication enabled

#notepad updated
if(Get-ChildItem "C:\Program Files\Notepad" -Recurse -Filter notepad.exe -or Get-ChildItem "C:\Program Files (x86)\Notepad" -Recurse -Filter notepad.exe
){
  winget upgrade "Notepad"
}
#removed Wireshark
winget uninstall "Wireshark"

#removed npcap
winget uninstall "Npcap"

#limit local use of a blank password to console only
#DO not allow anonymous enumeration of SAM accounts
#windows update majority
#restrict global object creation
#RDP Security Layer set to SSL
#log allowed, blocked, and ignored for advanced windows firewall
#Disable-Bitlocker
#Find-Script



#stop services
Get-Service
Set-Service -Name "wuauserv" -StartupType "Disabled"

#stop process
Get-Process
Stop-Process -Name "notepad"
Stop-Process -Id 1234

Using IIS Manager (GUI)
If you prefer a GUI to manage the service:

Press Windows + R, type inetmgr, and press Enter to open IIS Manager.
In the left pane, expand the Server node.

#Restart the computer
Restart-computer

#Pause and unpause the script
read-host "Press Enter to continue..."
write-host "Continuing script..."

#Disables script running
Set-ExecutionPolicy Restricted
