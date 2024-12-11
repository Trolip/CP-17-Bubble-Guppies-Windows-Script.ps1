#Disable Services
function disableservices{
stop-service -name nc | set-service -name nc.exe -startuptype Disabled
#AllJoyn Router Service
set-service -name AJRouter -startuptype Disabled | stop-service -name AJRouter 
#AssignedAccessManager
set-service -name AssignedAccessManagerSvc -startuptype Disabled|stop-service -name AssignedAccessManagerSvc 
#BitLocker Drive Encryption.
set-service -name BDESVC -startuptype Disabled|stop-service -name BDESVC 
#Bluetooth Audio Gateway Service, Bluetooth Support Service, and Bluetooth User Support Service.
set-service -name BTAGService -startuptype Disabled|stop-service -name BTAGService
set-service -name bthserv -startuptype Disabled|stop-service -name bthserv
set-service -name BluetoothUserService_63bcf -startuptype Disabled|stop-service -name BluetoothUserService_63bcf
#Connected User Experiences and Telemetry.
stop-service -name DiagTrack|set-service -name DiagTrack -startuptype Disabled
#DevicePicker.
set-service -name DevicePickerUserSvc_63bcf -startuptype Disabled|stop-service -name DevicePickerUserSvc_63bcf
#Diagnostic Execution Service, Diagnostic Policy Service, Diagnostic Service Host, and Diagnostic System Host.
stop-service -name DiagTrack|set-service -name DiagTrack -startuptype Disabled
stop-service -name DiagTrack|set-service -name DiagTrack -startuptype Disabled
stop-service -name DiagTrack|set-service -name DiagTrack -startuptype Disabled
stop-service -name DiagTrack|set-service -name DiagTrack -startuptype Disabled
#Fax.
set-service -name Fax -startuptype Disabled|stop-service -name Fax
#Geolocation Service and Downloaded Maps Manager.
set-service -name lfsvc -startuptype Disabled|stop-service -name lfsvc
set-service -name MapsBroker -startuptype Disabled|stop-service -name MapsBroker
#Optimize Drives. 
stop-service -name defragsvc|set-service -name defragsvc -startuptype Disabled
#Parental Controls.
stop-service -name WpcMonSvc|set-service -name WpcMonSvc -startuptype Disabled
#Phone Service.
stop-service -name PhoneSvc|set-service -name PhoneSvc -startuptype Disabled
#Print Spooler. 
stop-service -name Spooler|set-service -name Spooler -startuptype Disabled
#Remote Desktop Configuration, Remote Desktop Services, and Remote Desktop Services UserMode Port Redirector.
stop-service -name SessionEnv|set-service -name SessionEnv -startuptype Disabled
stop-service -name TermService|set-service -name TermService -startuptype Disabled
stop-service -name UmRdpService|set-service -name UmRdpService -startuptype Disabled
#Sensor Service.
stop-service -name SensorService|set-service -name SensorService -startuptype Disabled
#Smart Card, Smart Card Device Enumeration Service, and Smart Card Removal Policy.
stop-service -name DiagTrack|set-service -name DiagTrack -startuptype Disabled
stop-service -name DiagTrack|set-service -name DiagTrack -startuptype Disabled
stop-service -name DiagTrack|set-service -name DiagTrack -startuptype Disabled
#Touch Keyboard and Handwriting Panel Service. 
stop-service -name DiagTrack|set-service -name DiagTrack -startuptype Disabled
#WalletService.
stop-service -name DiagTrack|set-service -name DiagTrack -startuptype Disabled
#Window Insider Service.
stop-service -name DiagTrack|set-service -name DiagTrack -startuptype Disabled
#Windows Biometric Service.
stop-service -name DiagTrack|set-service -name DiagTrack -startuptype Disabled
#Windows Error Reporting Service.
stop-service -name DiagTrack|set-service -name DiagTrack -startuptype Disabled
#Windows Mobile Hotspot Service.
stop-service -name DiagTrack|set-service -name DiagTrack -startuptype Disabled
#Xbox Accessory Management Service, Xbox Live Auth Manager, Xbox Live Game Save, and Xbox Live Networking Service.
stop-service -name DiagTrack|set-service -name DiagTrack -startuptype Disabled

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
Stop-Service -Name ftpsvc|Set-Service -Name ftpsvc -StartupType Disabled|Disable-WindowsOptionalFeature -Online -FeatureName "IIS-FTPServer" -Remove

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
}
#Windows Update services are running (WaaSMedicSvc)
Start-Service -Name WaaSMedicSvc

#Windows Automatic Updates are enabled'
Set-Service -Name wuauserv -StartupType Automatic
Start-Service -Name wuauserv

#Windows Event Log service is running
Start-Service -Name eventlog

set-service -name gpsvc -startuptype automatic | start-service -name gpsvc 

#The system requires approval from an administrator before running unknown software and Users cannot bypass attempts to run unknown software
Set-MpPreference -EnableSmartScreen $true

#Windows SmartScreen configured to warn or block
Set-MpPreference -EnableSmartScreen $true -SmartScreenAppInstallControl "Block"

#disable Bitlocker
Disable-BitLocker -MountPoint "C:"
