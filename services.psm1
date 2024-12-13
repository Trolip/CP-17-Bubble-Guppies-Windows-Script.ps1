#Disable Services
function disableservices{
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
}


function startservices{
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
