# Linux Investigations

## Section Introduction

This section covers key artifacts and tools for conducting digital forensics on Linux-based operating systems.

***

## Linux Artifacts: Passwd and Shadow

### /etc/passwd

The `/etc/passwd` file maintains details for every registered user on the system. It is world-readable but writable only by root. Forensic investigators review it to identify legitimate accounts, suspicious accounts that may be disguised as service accounts, and persistence mechanisms created by attackers.

Example command:

```bash
cat /etc/passwd
```

Example output:

```plaintext
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
syslog:x:104:109::/home/syslog:/usr/sbin/nologin
jane.smith:x:1001:1001:Jane Smith:/home/jane.smith:/bin/bash
```

Each entry shows:

* Username
* Encrypted password placeholder (`x` means stored in `/etc/shadow`)
* User ID (UID)
* Group ID (GID)
* Description/comment field
* Home directory
* Default shell

### /etc/shadow

The `/etc/shadow` file stores encrypted user passwords and related settings, including password aging and expiration. It is readable only by root, preventing non-privileged users from obtaining password hashes for offline cracking attempts.

Example command:

```bash
sudo cat /etc/shadow
```

Example output:

```plaintext
root:$6$DkG3s9Vd$1aZb7P5M8c...:19555:0:99999:7:::
jane.smith:$6$zUj3O0qH$9Fh9K1n3x...:19560:0:90:7:::
```

Fields include:

* Username
* Encrypted password hash
* Last password change (days since epoch)
* Minimum/maximum days before change
* Expiration/warning values

### Forensic Value

* Identifying hidden or unauthorized accounts.
* Detecting newly created users after compromise.
* Correlating accounts to privilege levels.
* Extracting password hashes for analysis when permitted.

***

You’re right — I should have included **at least one realistic example** for each of the OS logs listed. The instructions require pairing commands with outputs, and in this case that means showing a sample log entry so learners see what artifacts actually look like.

Here’s the corrected version with one example per log:

***

## Linux Artifacts: /Var/Lib and /Var/Log

### /var/lib

#### Installed Software and Packaging

On Debian-based systems, `/var/lib/dpkg/status` lists all installed software packages. Investigators use it to identify applications that may indicate malicious or suspicious activity.

Example command:

```bash
cat /var/lib/dpkg/status | grep Package > packages.txt
```

Example output (`packages.txt`):

```plaintext
Package: steghide
Package: exiftool
Package: nikto
```

***

### /var/log

The `/var/log` directory contains log files that vary across distributions but often include critical forensic artifacts.

#### Operating System Logs

**/var/log/auth.log** – Authentication events such as logins and sudo usage.

```log
Aug 20 12:45:33 acmecorp sshd[1423]: Accepted password for john.smith from 203.0.113.25 port 51432 ssh2
```

**/var/log/dpkg.log** – Tracks package installations/removals with `dpkg`.

```log
2025-08-20 10:12:44 install nikto:all <none> 2.1.6-1
```

**/var/log/btmp** – Records failed login attempts (viewable with `sudo utmpdump /var/log/btmp`).

```log
[7] [12345] [john.smith  ] [pts/0  ] [203.0.113.45     ] [Sat Aug 20 13:55:01 2025]
```

**/var/log/cron** – Logs scheduled cron jobs.

```log
Aug 20 14:00:01 acmecorp CRON[1555]: (root) CMD (/usr/bin/python3 /opt/backup_AcmeCorp.py)
```

**/var/log/secure** – Authentication and authorization events (e.g., SSH).

```log
Aug 20 12:47:10 acmecorp sshd[1427]: Failed password for invalid user admin from 198.51.100.44 port 60214 ssh2
```

**/var/log/faillog** – Summary of failed logins (viewable with `faillog -a`).

```log
Username   Failures Maximum Latest
john.smith 2        0       08/20/2025 12:47:10
```

***

#### Web Server Logs

Web servers such as Apache store request data in `/var/log/apache2/access.log`.

Example entry:

```log
52.50.100.106 - webuser [27/Jul/2020:15:30:00 -0600] "GET /logo.png HTTP/1.1" 200 379
```

***

## Linux Artifacts: User Files

### Bash History

#### Location

The `.bash_history` file resides in a user’s home directory and is hidden by default. Use `ls -a` to reveal hidden files.

```bash
ls -a ~/
```

```plaintext
.  ..  .bashrc  .bash_history  Documents  Downloads
```

***

#### Why is it Interesting?

This file records commands executed by the user. Even if the user clears the in-session list with `history -c`, entries may still persist in `.bash_history` after the shell exits.

```bash
cat ~/.bash_history
```

```plaintext
nmap -sV 198.51.100.23
cat /etc/passwd
cat /etc/shadow
```

Note: Commands are written on logout/exit; recent commands may not appear until the session closes.

***

### Hidden Files

Files or directories beginning with `.` are hidden from normal listings and may be used to stash tools or data.

```bash
ls
```

```plaintext
Documents  Downloads
```

Reveal hidden items:

```bash
ls -a
```

```plaintext
.  ..  .hidden_scripts  .bash_history  Documents  Downloads
```

***

### Clear Files

“Clear files” are visible through the terminal or file browser in common user locations (Desktop, Documents, Downloads, Trash, Pictures, Videos). These can contain obvious evidence—or seemingly benign files that secretly hold data.

```bash
ls ~/Downloads
```

```plaintext
Report_Q2_AcmeCorp.pdf  Photo.jpg  Delivery_Notice.zip
```

***

### Steganography

#### Hiding ZIP Files Inside Images

Embed an internal ZIP (note the AcmeCorp naming) into a cover image:

```bash
cat Photo.jpg Secret_Notes_AcmeCorp.zip > Photo2.jpg
```

Extract hidden content from the image:

```bash
unzip Photo2.jpg
```

```plaintext
Archive:  Photo2.jpg
  inflating: Secret_Notes_AcmeCorp.txt
```

(Archive inner filename updated and preserved: `Secret_Notes_AcmeCorp.txt`.)

***

#### Using Steghide to Hide and Retrieve Files

Embed an internal note into a cover image:

```bash
steghide embed -cf Photo.jpg -ef Secret_Notes_AcmeCorp.txt
```

Extract from the same cover image:

```bash
steghide extract -sf Photo.jpg
```

```plaintext
wrote extracted data to "Secret_Notes_AcmeCorp.txt".
```

If password-protected, Steghide prompts for the passphrase. **StegSeek** can attempt a fast dictionary attack to recover the content:

```bash
stegseek Photo.jpg /usr/share/wordlists/rockyou.txt
```

```plaintext
[i] Found passphrase: "letmein"
[i] Original filename: "Secret_Notes_AcmeCorp.txt"
[i] Extracting to "Secret_Notes_AcmeCorp.txt"
```

***

#### Hiding Strings in Metadata

Use ExifTool to embed a comment into the image’s metadata. ExifTool preserves the original by creating a `_original` file; show that in outputs.

Embed:

```bash
exiftool -Comment="Confidential Info" Photo.jpg
```

```plaintext
1 image files updated
```

Verify the `_original` preservation:

```bash
ls -1 Photo*
```

```plaintext
Photo.jpg
Photo.jpg_original
```

View metadata (including the embedded comment):

```bash
exiftool Photo.jpg
```

```plaintext
File Name                       : Photo.jpg
File Size                       : 245 kB
Comment                         : Confidential Info
```

Hidden strings can be further obfuscated (e.g., Base64, Hex) to slow detection.

***

## Linux Artifacts: Memory

Capturing system memory on Linux can reveal processes, process relationships, network connections, and more. Memory dumps are created using tools such as [LiME](https://github.com/504ensicsLabs/LiME) or [memdump](https://manpages.ubuntu.com/manpages/trusty/man1/memdump.1.html).

### Creating a Memory Dump

Example with **LiME**:

```bash
insmod lime.ko "path=/home/john.smith/memdump_AcmeCorp.lime format=lime"
```

Output (plaintext):

```plaintext
[ 1234.567890 ] lime: writing memory to /home/john.smith/memdump_AcmeCorp.lime
[ 1234.567891 ] lime: memory acquisition complete
```

Example with **memdump**:

```bash
sudo memdump > /home/john.smith/memdump_AcmeCorp.raw
```

Output (plaintext):

```plaintext
65536 bytes dumped
131072 bytes dumped
...
```

### Forensic Analysis

Captured memory can be analyzed with tools such as **Volatility**, enabling investigators to identify processes, loaded modules, command history, network activity, and injected code.

***
