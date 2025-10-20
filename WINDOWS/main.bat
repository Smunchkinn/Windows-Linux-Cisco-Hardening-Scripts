@echo off

color 0A

echo " /$$      /$$ /$$           /$$                                        "
echo "| $$$    /$$$|__/          | $$                                        "
echo "| $$$$  /$$$$ /$$ /$$$$$$$ | $$$$$$$                                   "
echo "| $$ $$/$$ $$| $$| $$__  $$| $$__  $$                                  "
echo "| $$  $$$| $$| $$| $$  \ $$| $$  \ $$                                  "
echo "| $$\  $ | $$| $$| $$  | $$| $$  | $$                                  "
echo "| $$ \/  | $$| $$| $$  | $$| $$  | $$                                  "
echo "|__/     |__/|__/|__/  |__/|__/  |__/                                  "
echo "                                                                       "                                                  
echo " /$$$$$$$                                            /$$               "
echo "| $$__  $$                                          | $$               "
echo "| $$  \ $$ /$$   /$$ /$$$$$$$   /$$$$$$   /$$$$$$$ /$$$$$$   /$$   /$$ "
echo "| $$  | $$| $$  | $$| $$__  $$ |____  $$ /$$_____/|_  $$_/  | $$  | $$ "
echo "| $$  | $$| $$  | $$| $$  \ $$  /$$$$$$$|  $$$$$$   | $$    | $$  | $$ " 
echo "| $$  | $$| $$  | $$| $$  | $$ /$$__  $$ \____  $$  | $$ /$$| $$  | $$ "
echo "| $$$$$$$/|  $$$$$$$| $$  | $$|  $$$$$$$ /$$$$$$$/  |  $$$$/|  $$$$$$$ "
echo "|_______/  \____  $$|__/  |__/ \_______/|_______/    \___/   \____  $$ "
echo "           /$$  | $$                                         /$$  | $$ "
echo "         |  $$$$$$/                                        |  $$$$$$/  "
echo "          \______/                                          \______/   "

pause
REM Account Policies

REM Password Policy
net accounts /uniquepw:5
net accounts /maxpwage:30
net accounts /minpwage:10
net accounts /minpwlen:10

REM Account Lockout Policy
net accounts  /lockoutduration:30
net accounts  /lockoutthreshold:5
net accounts /lockoutwindow:30

REM Local Policies

REM Audit Policy
auditpol /set /category:* /success:enable
auditpol /set /category:* /failure:enable

REM User Rights Assignment Check Manually

REM Security Options

net user Administrator /active:no
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoConnectedUser" /t REG_DWORD /d 3 /f
net user guest /active:no
reg ADD HKLM\System\CurrentControlSet\Control\Lsa /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
reg ADD HKLM\System\CurrentControlSet\Control\Lsa /v AuditBaseObjects /t REG_DWORD /d 0 /f
reg ADD HKLM\System\CurrentControlSet\Control\Lsa /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f
reg ADD HKLM\System\CurrentControlSet\Control\Lsa /v CrashOnAuditFail /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DCOM" /v "MachineAccessRestriction" /t REG_SZ /d "none" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DCOM" /v "MachineLaunchRestriction" /t REG_SZ /d "none" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "UndockWithoutLogon" /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v "AddPrinterDrivers" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v "RequireSignOrSeal" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v "SealSecureChannel" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v "SignSecureChannel" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v "DisablePasswordChange" /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v "MaximumPasswordAge" /t REG_DWORD /d 30 /f
reg add "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v "RequireStrongKey" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "DontDisplayLastUserName" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableCAD" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "InactivityTimeoutSecs" /t REG_DWORD /d 900 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "CachedLogonsCount" /t REG_SZ /d 4 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "PasswordExpiryWarning" /t REG_DWORD /d 14 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ScForceOption" /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f
reg ADD HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters /v EnablePlainTextPassword /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v autodisconnect /t REG_DWORD /d 15 /f
reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f
reg ADD HKLM\System\CurrentControlSet\Services\LanManServer\Parameters /v EnableForcedLogOff /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "RestrictAnonymousSAM" /t REG_DWORD /d 1 /f
reg ADD HKLM\System\CurrentControlSet\Control\Lsa /v RestrictAnonymous /t REG_DWORD /d 1 /f
reg ADD HKLM\System\CurrentControlSet\Control\Lsa /v DisableDomainCreds /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "EveryoneIncludesAnonymous" /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v "NullSessionPipes" /t REG_MULTI_SZ /d "" /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "RestrictNullSessAccess" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "ForceGuest" /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "UseMachineId" /t REG_DWORD /d 1 /f
reg ADD HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0 /v allownullsessionfallback /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Control\Lsa\pku2u" /v "AllowOnlineID" /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "NoLMHash" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LDAP" /v "LDAPClientIntegrity" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0" /v "RestrictReceivingNTLMTraffic" /t REG_DWORD /d 2 /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole" /v "SecurityLevel" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole" /v "SetCommand" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ShutdownWithoutLogon" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "ClearPageFileAtShutdown" /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Kernel" /v "ObCaseInsensitive" /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\SubSystems" /v "Optional" /t REG_SZ /d "" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers" /v "AuthenticodeEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "FilterAdministratorToken" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableUIADesktopToggle" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableInstallerDetection" /t REG_DWORD /d 1 /f
reg ADD HKLM\System\CurrentControlSet\Control\Lsa /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PasswordComplexity /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoConnectedUser" /t REG_DWORD /d 3 /f
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableVirtualization /t REG_DWORD /d 1 /f
reg ADD HKLM\System\CurrentControlSet\Control\Lsa /v AuditBaseObjects /t REG_DWORD /d 0 /f
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableSecureUIAPaths /t REG_DWORD /d 1 /f
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ValidateAdminCodeSignatures /t REG_DWORD /d 0 /f

REM Disabling Services

sc stop TapiSrv
sc config TapiSrv start= disabled
sc stop TlntSvr
sc config TlntSvr start= disabled
sc stop ftpsvc
sc config ftpsvc start= disabled
sc stop SNMP
sc config SNMP start= disabled
sc stop SessionEnv
sc config SessionEnv start= disabled
sc stop TermService
sc config TermService start= disabled
sc stop UmRdpService
sc config UmRdpService start= disabled
sc stop SharedAccess
sc config SharedAccess start= disabled
sc stop remoteRegistry 
sc config remoteRegistry start= disabled
sc stop SSDPSRV
sc config SSDPSRV start= disabled
sc stop SNMPTRAP
sc config SNMPTRAP start= disabled
sc stop remoteAccess
sc config remoteAccess start= disabled
sc stop RpcSs
sc config RpcSs start= disabled
sc stop HomeGroupProvider
sc config HomeGroupProvider start= disabled
sc stop HomeGroupListener
sc config HomeGroupListener start= disabled
sc config spooler start= disabled
sc stop spooler
sc stop ALG
sc config ALG start= disabled
sc stop AJRouter
sc config AJRouter start= disabled
sc stop AVCTP
sc config AVCTP start= disabled
sc stop BDESVC
sc config BDESVC start= disabled
sc stop bthserv
sc config bthserv start= disabled
sc stop DiagTrack
sc config DiagTrack start= disabled
sc stop CertPropSvc
sc config CertPropSvc start= disabled
sc stop DPS
sc config DPS start= disabled
sc stop wdi-service-host
sc config wdi-service-host"start= disabled
sc stop WdiSystemHost
sc config WdiSystemHost start= disabled
sc stop TrkWks
sc config TrkWks start= disabled
sc stop Downloaded Maps Manager
sc config Downloaded Maps Manager start= disabled
sc stop AppMgmt
sc config AppMgmt start= disabled
sc stop Fax
sc config Fax start= disabled
sc stop fhsvc
sc config fhsvc start= disabled
sc stop GameDVR
sc config GameDVR start= disabled
sc stop lfsvc
sc config lfsvc start= disabled
sc stop iphlpsvc
sc config iphlpsvc start= disabled
sc stop icssvc
sc config icssvc start= disabled
sc stop Netlogon
sc config Netlogon start= disabled
sc stop CscService
sc config CscService start= disabled
sc stop WPCSvc
sc config WPCSvc start= disabled
sc stop WpnUserService
sc config WpnUserService start= disabled
sc stop XblAuthManager
sc config XblAuthManager start= disabled
sc stop PhoneSvc
sc config PhoneSvc start= disabled
sc stop PcaSvc
sc config PcaSvc start= disabled
sc stop WPCSvc
sc config WPCSvc start= disabled
sc stop RetailDemo
sc config RetailDemo start= disabled
sc stop seclogon
sc config seclogon start= disabled
sc stop ScDeviceEnum
sc config ScDeviceEnum start= disabled
sc stop EapHost
sc config EapHost start= disabled
sc stop TabletInputService
sc config TabletInputService start= disabled
sc stop WdiServiceHost
sc config WdiServiceHost start= disabled
sc stop WerSvc
sc config WerSvc start= disabled
sc stop wisvc
sc config wisvc start= disabled
sc stop WSearch
sc config WSearch start= disabled
sc stop XboxGipSvc
sc config XboxGipSvc start= disabled
sc stop XblAuthManager
sc config XblAuthManager start= disabled
sc stop XblGameSave
sc config XblGameSave start= disabled

REM group policies
REM do that later

REM remote desktop sharing off (make sure in read me says if should be on or off)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d "1" /f

REM file sharing off
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=No

REM disable features
dism /online /disable-feature /featurename:IIS-WebServerRole >NUL
dism /online /disable-feature /featurename:IIS-WebServer >NUL
dism /online /disable-feature /featurename:IIS-CommonHttpFeatures >NUL
dism /online /disable-feature /featurename:IIS-HttpErrors >NUL
dism /online /disable-feature /featurename:IIS-HttpRedirect >NUL
dism /online /disable-feature /featurename:IIS-ApplicationDevelopment >NUL
dism /online /disable-feature /featurename:IIS-NetFxExtensibility >NUL
dism /online /disable-feature /featurename:IIS-NetFxExtensibility45 >NUL
dism /online /disable-feature /featurename:IIS-HealthAndDiagnostics >NUL
dism /online /disable-feature /featurename:IIS-HttpLogging >NUL
dism /online /disable-feature /featurename:IIS-LoggingLibraries >NUL
dism /online /disable-feature /featurename:IIS-RequestMonitor >NUL
dism /online /disable-feature /featurename:IIS-HttpTracing >NUL
dism /online /disable-feature /featurename:IIS-Security >NUL
dism /online /disable-feature /featurename:IIS-URLAuthorization >NUL
dism /online /disable-feature /featurename:IIS-RequestFiltering >NUL
dism /online /disable-feature /featurename:IIS-IPSecurity >NUL
dism /online /disable-feature /featurename:IIS-Performance >NUL
dism /online /disable-feature /featurename:IIS-HttpCompressionDynamic >NUL
dism /online /disable-feature /featurename:IIS-WebServerManagementTools >NUL
dism /online /disable-feature /featurename:IIS-ManagementScriptingTools >NUL
dism /online /disable-feature /featurename:IIS-IIS6ManagementCompatibility >NUL
dism /online /disable-feature /featurename:IIS-Metabase >NUL
dism /online /disable-feature /featurename:IIS-HostableWebCore >NUL
dism /online /disable-feature /featurename:IIS-StaticContent >NUL
dism /online /disable-feature /featurename:IIS-DefaultDocument >NUL
dism /online /disable-feature /featurename:IIS-DirectoryBrowsing >NUL
dism /online /disable-feature /featurename:IIS-WebDAV >NUL
dism /online /disable-feature /featurename:IIS-WebSockets >NUL
dism /online /disable-feature /featurename:IIS-ApplicationInit >NUL
dism /online /disable-feature /featurename:IIS-ASPNET >NUL
dism /online /disable-feature /featurename:IIS-ASPNET45 >NUL
dism /online /disable-feature /featurename:IIS-ASP >NUL
dism /online /disable-feature /featurename:IIS-CGI >NUL
dism /online /disable-feature /featurename:IIS-ISAPIExtensions >NUL
dism /online /disable-feature /featurename:IIS-ISAPIFilter >NUL
dism /online /disable-feature /featurename:IIS-ServerSideIncludes >NUL
dism /online /disable-feature /featurename:IIS-CustomLogging >NUL
dism /online /disable-feature /featurename:IIS-BasicAuthentication >NUL
dism /online /disable-feature /featurename:IIS-HttpCompressionStatic >NUL
dism /online /disable-feature /featurename:IIS-ManagementConsole >NUL
dism /online /disable-feature /featurename:IIS-ManagementService >NUL
dism /online /disable-feature /featurename:IIS-WMICompatibility >NUL
dism /online /disable-feature /featurename:IIS-LegacyScripts >NUL
dism /online /disable-feature /featurename:IIS-LegacySnapIn >NUL
dism /online /disable-feature /featurename:IIS-FTPServer >NUL
dism /online /disable-feature /featurename:IIS-FTPSvc >NUL
dism /online /disable-feature /featurename:IIS-FTPExtensibility >NUL
dism /online /disable-feature /featurename:TFTP >NUL
dism /online /disable-feature /featurename:TelnetClient >NUL
dism /online /disable-feature /featurename:TelnetServer >NUL

REM disableing weak services
dism /online /disable-feature /featurename:IIS-WebServerRole
dism /online /disable-feature /featurename:IIS-WebServer
dism /online /disable-feature /featurename:IIS-CommonHttpFeatures
dism /online /disable-feature /featurename:IIS-HttpErrors
dism /online /disable-feature /featurename:IIS-HttpRedirect
dism /online /disable-feature /featurename:IIS-ApplicationDevelopment
dism /online /disable-feature /featurename:IIS-NetFxExtensibility
dism /online /disable-feature /featurename:IIS-NetFxExtensibility45
dism /online /disable-feature /featurename:IIS-HealthAndDiagnostics
dism /online /disable-feature /featurename:IIS-HttpLogging
dism /online /disable-feature /featurename:IIS-LoggingLibraries
dism /online /disable-feature /featurename:IIS-RequestMonitor
dism /online /disable-feature /featurename:IIS-HttpTracing
dism /online /disable-feature /featurename:IIS-Security
dism /online /disable-feature /featurename:IIS-URLAuthorization
dism /online /disable-feature /featurename:IIS-RequestFiltering
dism /online /disable-feature /featurename:IIS-IPSecurity
dism /online /disable-feature /featurename:IIS-Performance
dism /online /disable-feature /featurename:IIS-HttpCompressionDynamic
dism /online /disable-feature /featurename:IIS-WebServerManagementTools
dism /online /disable-feature /featurename:IIS-ManagementScriptingTools
dism /online /disable-feature /featurename:IIS-IIS6ManagementCompatibility
dism /online /disable-feature /featurename:IIS-Metabase
dism /online /disable-feature /featurename:IIS-HostableWebCore
dism /online /disable-feature /featurename:IIS-StaticContent
dism /online /disable-feature /featurename:IIS-DefaultDocument
dism /online /disable-feature /featurename:IIS-DirectoryBrowsing
dism /online /disable-feature /featurename:IIS-WebDAV
dism /online /disable-feature /featurename:IIS-WebSockets
dism /online /disable-feature /featurename:IIS-ApplicationInit
dism /online /disable-feature /featurename:IIS-ASPNET
dism /online /disable-feature /featurename:IIS-ASPNET45
dism /online /disable-feature /featurename:IIS-ASP
dism /online /disable-feature /featurename:IIS-CGI
dism /online /disable-feature /featurename:IIS-ISAPIExtensions
dism /online /disable-feature /featurename:IIS-ISAPIFilter
dism /online /disable-feature /featurename:IIS-ServerSideIncludes
dism /online /disable-feature /featurename:IIS-CustomLogging
dism /online /disable-feature /featurename:IIS-BasicAuthentication
dism /online /disable-feature /featurename:IIS-HttpCompressionStatic
dism /online /disable-feature /featurename:IIS-ManagementConsole
dism /online /disable-feature /featurename:IIS-ManagementService
dism /online /disable-feature /featurename:IIS-WMICompatibility
dism /online /disable-feature /featurename:IIS-LegacyScripts
dism /online /disable-feature /featurename:IIS-LegacySnapIn
dism /online /disable-feature /featurename:IIS-FTPServer
dism /online /disable-feature /featurename:IIS-FTPSvc
dism /online /disable-feature /featurename:IIS-FTPExtensibility
dism /online /disable-feature /featurename:TFTP
dism /online /disable-feature /featurename:TelnetClient
dism /online /disable-feature /featurename:TelnetServer

REM enable firewall
netsh advfirewall set allprofiles state on

netsh advfirewall firewall set rule name="Remote Assistance (DCOM-In)" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance (PNRP-In)" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance (RA Server TCP-In)" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance (SSDP TCP-In)" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance (SSDP UDP-In)" new enable=no 
netsh advfirewall firewall set rule name="Remote Assistance (TCP-In)" new enable=no 
netsh advfirewall firewall set rule name="Telnet Server" new enable=no 
netsh advfirewall firewall set rule name="netcat" new enable=no

        netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files (x86)\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\system32\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\SysWOW64\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\system32\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\SysWOW64\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\system32\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\SysWOW64\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\system32\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\SysWOW64\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\system32\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\SysWOW64\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\system32\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\SysWOW64\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\system32\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\SysWOW64\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\system32\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\SysWOW64\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\system32\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\SysWOW64\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\system32\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\SysWOW64\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\system32\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\SysWOW64\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\system32\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\SysWOW64\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\system32\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\SysWOW64\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\system32\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\SysWOW64\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\system32\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\SysWOW64\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\system32\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\SysWOW64\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\system32\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\SysWOW64\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\system32\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\SysWOW64\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\system32\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\SysWOW64\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block rpcping.exe netconns" program="%systemroot%\SysWOW64\rpcping.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\system32\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\SysWOW64\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\system32\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\SysWOW64\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\system32\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\SysWOW64\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\system32\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\SysWOW64\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\system32\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\SysWOW64\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\system32\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
        netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\SysWOW64\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any


pause

