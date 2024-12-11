#Disable Services
function disableservices{
stop-service -name nc | set-service -name nc.exe -startuptype Disabled
#AllJoyn Router Service
stop-service -name AJRouter|set-service -name AJRouter -startuptype Disabled
#AssignedAccessManager
stop-service -name AssignedAccessManagerSvc|set-service -name AssignedAccessManagerSvc -startuptype Disabled
#BitLocker Drive Encryption.
stop-service -name BDESVC|set-service -name BDESVC -startuptype Disabled
#Bluetooth Audio Gateway Service, Bluetooth Support Service, and Bluetooth User Support Service.
stop-service -name BTAGService|set-service -name BTAGService -startuptype Disabled
stop-service -name bthserv|set-service -name bthserv -startuptype Disabled
stop-service -name BluetoothUserService_63bcf|set-service -name BluetoothUserService_63bcf -startuptype Disabled
#Connected User Experiences and Telemetry.
stop-service -name DiagTrack|set-service -name DiagTrack -startuptype Disabled
#DevicePicker.
stop-service -name DevicePickerUserSvc_63bcf|set-service -name DevicePickerUserSvc_63bcf -startuptype Disabled
#Diagnostic Execution Service, Diagnostic Policy Service, Diagnostic Service Host, and Diagnostic System Host.
stop-service -name DiagTrack|set-service -name DiagTrack -startuptype Disabled
stop-service -name DiagTrack|set-service -name DiagTrack -startuptype Disabled
stop-service -name DiagTrack|set-service -name DiagTrack -startuptype Disabled
stop-service -name DiagTrack|set-service -name DiagTrack -startuptype Disabled
#Fax.
stop-service -name Fax|set-service -name Fax -startuptype Disabled
#Geolocation Service and Downloaded Maps Manager.
stop-service -name lfsvc|set-service -name lfsvc -startuptype Disabled
stop-service -name MapsBroker|set-service -name MapsBroker -startuptype Disabled
#Optimize Drives. 
stop-service -name defragsvc|set-service -name defragsvc -startuptype Disabled
#Parental Controls.
stop-service -name WpcMonSvc|set-service -name WpcMonSvc -startuptype Disabled
#Phone Service.
stop-service -name PhoneSvc|set-service -name PhoneSvc -startuptype Disabled
#Print Spooler. 
stop-service -name Spooler|set-service -name Spooler -startuptype Disabled

add if
#Remote Desktop Configuration, Remote Desktop Services, and Remote Desktop Services UserMode Port Redirector.
stop-service -name SessionEnv|set-service -name SessionEnv -startuptype Disabled
stop-service -name TermService|set-service -name TermService -startuptype Disabled
stop-service -name UmRdpService|set-service -name UmRdpService -startuptype Disabled
#Sensor Service.
stop-service -name SensorService|set-service -name SensorService -startuptype Disabled
#Smart Card, Smart Card Device Enumeration Service, and Smart Card Removal Policy.
stop-service -name SCardSvr|set-service -name SCardSvr -startuptype Disabled
stop-service -name ScDeviceEnum|set-service -name ScDeviceEnum -startuptype Disabled
stop-service -name SCPolicySvc|set-service -name SCPolicySvc -startuptype Disabled
#WalletService.
stop-service -name WalletService|set-service -name WalletService -startuptype Disabled
#Window Insider Service.
stop-service -name wisvc|set-service -name wisvc -startuptype Disabled
#Windows Biometric Service.
stop-service -name WbioSrvc|set-service -name WbioSrvc -startuptype Disabled
#Windows Mobile Hotspot Service.
stop-service -name icssvc|set-service -name icssvc -startuptype Disabled
#Xbox Accessory Management Service, Xbox Live Auth Manager, Xbox Live Game Save, and Xbox Live Networking Service.
stop-service -name XboxGipSvc|set-service -name XboxGipSvc -startuptype Disabled
stop-service -name XblAuthManager|set-service -name XblAuthManager -startuptype Disabled
stop-service -name XblGameSave|set-service -name XblGameSave -startuptype Disabled
stop-service -name XboxNetApiSvc|set-service -name XboxNetApiSvc -startuptype Disabled

Remote Procedure Call (RPC) Locator
#NetBIOS
Service Name: NetBIOS, NetBT

#Windows Remote Management (WinRM)
Service Name: WinRM

#Simple Network Management Protocol (SNMP)
Service Name: SNMP

#Windows Management Instrumentation (WMI)
Service Name: Winmgmt

#IPv6 (If Not Used)
Service Name: TCP/IP NetBIOS Helper

#Function Discovery
Service Name: fdPHost

#World Wide Web Publishing service has been stopped and disabled
Stop-Service -Name w3svc

#UPnP is not enabled
Stop-Service -Name upnphost
Set-Service -Name upnphost -StartupType Disabled

#disable Bitlocker
Disable-BitLocker -MountPoint "C:"

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
function startservices{
#Touch Keyboard and Handwriting Panel Service
#Windows Update services are running (WaaSMedicSvc)
Start-Service -Name WaaSMedicSvc

#Windows Defender Advanced Threat Protection Service
#Windows Defender Antivirus Service
#Windows Defender Antivirus Network Inspection Service
#Windows Defender Firewall
#Windows Event Log
#Security Center
#Open TFTP MultiThreaded Server
#Group Policy Client
#CCS Client

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
}
