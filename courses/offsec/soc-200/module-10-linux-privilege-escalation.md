# Module 10: Linux Privilege Escalation

## Attacking the Users

### Becoming a User

In Linux, users are identifed by UID and GID.

_Inspecting the /etc/passwd file_

```bash
offsec@linux01:~$ cat /etc/passwd | grep offsec
...
offsec:x:1000:1000:offsec,,,:/home/offsec:/bin/bash
```

_Passwd file fields explained_

* **Login Name**: "offsec" - Indicates the username used for login.
* **Encrypted Password**: "x" - This field typically contains the hashed version of the user's password. In this case, the value _x_ means that the entire password hash is contained in the /etc/shadow file (more on that shortly).
* **UID**: "1000" - Aside from the root user that has always a UID of _0_, Linux starts counting regular user IDs from 1000. This value is also called _real user ID_.
* **GID**: "1000" - Represents the user's specific Group ID.
* **Comment**: "offsec,,," - This field generally contains a description about the user, often simply repeating username information.
* **Home Folder**: "/home/offsec" - Describes the user's home directory prompted upon login.
* **Login Shell**: "/bin/bash" - Indicates the initial directory from which the user is prompted to login.

_Checking our user's sudo permissions_

{% code overflow="wrap" %}
```bash
offsec@linux01:~$ sudo -l
Matching Defaults entries for offsec on linux01:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+=LD_PRELOAD

User offsec may run the following commands on linux01:
    (ALL : ALL) ALL
```
{% endcode %}

All privileged operations using _sudo_ and _sui_ are logged by default to **/var/log/auth.log**

_Inspecting sudo related events_

{% code overflow="wrap" %}
```log
offsec@linux01:~$ sudo cat /var/log/auth.log | grep "sudo:"
...
Aug 16 15:28:19 linux01 sudo:   offsec : TTY=pts/0 ; PWD=/home/offsec ; USER=root ; COMMAND=list
Aug 16 15:28:35 linux01 sudo:      bob : TTY=pts/0 ; PWD=/home/offsec ; USER=root ; COMMAND=list
```
{% endcode %}

{% hint style="info" %}
Unlike Ubuntu/Debian, Linux distributions such as CentOS and Fedora store authentication logs in /var/log/secure.
{% endhint %}

_Blocked attempt to read /etc/shadow_

{% code overflow="wrap" %}
```bash
bob@linux01:/home/offsec$ sudo cat /etc/shadow
[sudo] password for bob:
Sorry, user bob is not allowed to execute '/usr/bin/cat /etc/shadow' as root on linux01.
```
{% endcode %}

_Reviewing the log entry for the blocked attempt_

{% code overflow="wrap" %}
```log
offsec@linux01:~$ sudo cat /var/log/auth.log | grep shadow
Aug 16 15:39:08 linux01 sudo:      bob : command not allowed ; TTY=pts/0 ; PWD=/home/offsec ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
```
{% endcode %}

_aureport_ can be used to efficiently inspect very detailed logs generated by the audit daemon.

_Enabling aureport detailed keylogging_

```bash
session required pam_tty_audit.so enable=*
```

_Running aureport to fetch user's keylogs_

{% code overflow="wrap" %}
```bash
offsec@linux01:~$ sudo  aureport --tty
[sudo] password for offsec:

TTY Report
===============================================
# date time event auid term sess comm data
===============================================
...
4. 08/17/21 05:30:02 2183 1002 pts0 153 bash <up>,<up>,<^U>,"ssh bob@localhost -i /home/alice/stolen_id_rsa",<ret>,"exit",<ret>
```
{% endcode %}

_Searching for the UID identified_

```bash
offsec@linux01:~$ grep 1002 /etc/passwd
alice:x:1002:1002::/home/alice:/bin/bash
```

A more accurate and controlled approach would be to inspect the auditd logs.

_Inspecting audit TTY events_

{% code overflow="wrap" %}
```log
offsec@linux01:~$ sudo cat /var/log/audit/audit.log | grep "type=TTY" | grep " uid=1002"
type=TTY msg=audit(1629358931.307:4407): tty pid=34388 uid=1002 auid=1002 ses=375 major=136 minor=0 comm="ssh" data=657869740D
type=TTY msg=audit(1629358932.867:4413): tty pid=34376 uid=1002 auid=1002 ses=375 major=136 minor=0 comm="bash" data=73736820626F62406C6F63616C686F7374202D69202F686F6D652F616C6963652F73746F6C656E5F69645F7273610D657869740D
```
{% endcode %}

The data can be decoded via _xxd_.

_Decoding the hex-encoded commands_

{% code overflow="wrap" %}
```bash
offsec@linux01:~$ echo "73736820626F62406C6F63616C686F7374202D69202F686F6D652F616C6963652F73746F6C656E5F69645F7273610D657869740D" | sed 's/0D/20/g'  | xxd -r -p
ssh bob@localhost -i /home/alice/stolen_id_rsa exit offsec@linux01:~$
```
{% endcode %}

### Backdooring a User

User config files tend to reside in the home directory and shouldn't be editable by other users. Two specific configuration files are responsible for executing aliases and bash functions (**.bashrc**) and setting environmental variables (**.profile**).

_Weak .bashrc permissions discovered_

```bash
alice@linux01:~$ ls -asl /home/bob/.bashrc
4 -rw-r--rw- 1 bob bob 3771 Aug 27 03:24 /home/bob/.bashrc
```

_"Backdooring" (PoC) bob's .bashrc_

```bash
alice@linux01:~$ echo 'echo "hello from bob .bashrc"' >> /home/bob/.bashrc
```

_Triggering the "backdoor" with a new login_

```bash
kali@kali:~$ ssh bob@192.168.51.12
...
hello from bob .bashrc
bob@linux01:~$
```

Now from a defender's perspective, we can enable auditing rule to detect these. We can use _auditctl_ to watch configuration files for any write and attribute change operations.

_Configuring audit rules for privilege escalation detection_

```bash
offsec@linux01:~ sudo auditctl -w /home/bob/.bashrc  -p wa -k privesc

offsec@linux01:~ sudo auditctl -w /home/bob/.profile -p wa -k privesc
```

_Verifying the audit rule_

```bash
offsec@linux01:~$ sudo auditctl -l
-w /home/bob/.bashrc -p wa -k privesc
-w /home/bob/.profile -p wa -k privesc
```

{% hint style="info" %}
Audit rules configured through auditctl will not be persistent across reboots. To make them permanent, rules have to be added to the /etc/audit/rules.d/audit.rules file.
{% endhint %}

_Inspecting the auditd rule report_

{% code overflow="wrap" %}
```bash
offsec@linux01:~$ sudo aureport -k

Key Report
===============================================
# date time key success exe auid event
===============================================
1. 08/30/21 07:29:46 privesc yes /usr/sbin/auditctl 1000 232
2. 08/30/21 07:29:51 privesc yes /usr/sbin/auditctl 1000 239
3. 08/30/21 07:44:20 privesc yes /home/offsec/SOC-200/Linux_Server_Side_Attacks/Shellshock/bash-4.3/bash 1002 287
```
{% endcode %}

{% hint style="info" %}
To enhance analysis, the aureport tool supports the -i option that interprets user IDs and translates them into usernames.
{% endhint %}

The _auid_ value is assigned every time a user logs in and is unchanged for the duration of that session.

## Attacking the System

### Abusing System Programs



### Extra Mile I

Extend the audit\_key\_search.py script to extract and print out the euid field. Once done, print an extra warning if the euid is zero and the auid is a standard user.

### Weak Permissions



### Extra Mile II

