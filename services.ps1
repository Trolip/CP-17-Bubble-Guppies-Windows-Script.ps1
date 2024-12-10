#Disable Services
#Enable Services
Adobe Acrobat Update Service.
AllJoyn Router Service 
AssignedAccessManager
BitLocker Drive Encryption.
Bluetooth Audio Gateway Service, Bluetooth Support Service, and Bluetooth User Support Service.
Connected User Experiences and Telemetry.
DevicePicker.
Diagnostic Execution Service, Diagnostic Policy Service, Diagnostic Service Host, and Diagnostic System Host.
Fax. 
Geolocation Service and Downloaded Maps Manager.
Optimize Drives. 
Parental Controls.
Phone Service.
Print Spooler. 
Remote Desktop Configuration, Remote Desktop Services, and Remote Desktop Services UserMode Port Redirector.
Sensor Service.
Smart Card, Smart Card Device Enumeration Service, and Smart Card Removal Policy.
Touch Keyboard and Handwriting Panel Service. 
WalletService.
Window Insider Service.
Windows Biometric Service.
Windows Error Reporting Service.
Windows Mobile Hotspot Service.
Xbox Accessory Management Service, Xbox Live Auth Manager, Xbox Live Game Save, and Xbox Live Networking Service. 
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
