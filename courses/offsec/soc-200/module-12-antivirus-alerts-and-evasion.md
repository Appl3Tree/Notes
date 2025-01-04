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



## Antimalware Scan Interface (AMSI)

### Understanding AMSI



### Bypassing AMSI

