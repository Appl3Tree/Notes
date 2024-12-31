# Module 8: Linux Endpoint Introduction

## Linux Applications and Daemons

### Daemons

Daemons are background programs that run without any user interaction. The terminology comes from Maxwell's demon, an imaginary entity that works in the background to help with experiments.

Any non-privileged user can query a daemon status through **systemctl**.

_Querying the SSH daemon status_

{% code overflow="wrap" %}
```bash
[offsec@linux02 ~]$ systemctl status sshd
● sshd.service - OpenSSH server daemon
   Loaded: loaded (/usr/lib/systemd/system/sshd.service; enabled; vendor preset: enabled)
   Active: inactive (dead) since Tue 2021-06-15 09:52:57 CEST; 2s ago
     Docs: man:sshd(8)
           man:sshd_config(5)
...
```
{% endcode %}

_Starting the SSH daemon_

{% code overflow="wrap" %}
```bash
[offsec@linux02 ~]$ sudo systemctl start sshd
[sudo] password for offsec: 
```
{% endcode %}

_Verifying the SSH daemon status_

{% code overflow="wrap" %}
```bash
[offsec@linux02 ~]$ systemctl status sshd
● sshd.service - OpenSSH server daemon
   Loaded: loaded (/usr/lib/systemd/system/sshd.service; enabled; vendor preset: enabled)
   Active:active (running) since Tue 2021-06-15 09:53:55 CEST; 4s ago
     Docs: man:sshd(8)
           man:sshd_config(5)
 Main PID: 78962 (sshd)
    Tasks: 1 (limit: 4627)
   Memory: 1.3M
   CGroup: /system.slice/sshd.service
           └─78962 /usr/sbin/sshd -D -oCiphers=aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes256-cbc,aes128-gcm@openssh.com,aes128->
```
{% endcode %}

### Logging on Linux and the Syslog Framework

Log files are saved w ithin the **/var/log** folder and named after their category/role.

_Linux log files locations_

| **Purpose**             | **Source Process**       | **CentOS Location** | **Ubuntu Location** |
| ----------------------- | ------------------------ | ------------------- | ------------------- |
| Authentication          | sudo, sshd, etc.         | secure              | auth.log            |
| Web Server              | apache                   | httpd/              | apache2/            |
| System Logs             | systemd,kernel, rsyslogd | messages            | syslog              |
| Package management Logs | dpkg                     | yum.log             | dpkg.log            |

_Raw log example of ssh attempt_

{% code overflow="wrap" %}
```log
[offsec@linux02 ~]$ sudo grep sshd /var/log/secure
...
Jun 28 11:22:55 linux02 sshd[156299]: pam_unix(sshd:session): session opened for user offsec by (uid=0)
...
```
{% endcode %}

_Rsyslog configuration supporting RFC3164 translation and multiple optional transport protocols_

{% code overflow="wrap" %}
```bash
...
#### RULES ####
$template RFC3164fmt,"<%PRI%>%TIMESTAMP% %HOSTNAME% %syslogtag%%msg%\n"
...
# The authpriv file has restricted access.
authpriv.*                                              /var/log/secure;RFC3164fmt
...
# Forwarding to remote syslog collectors
# ----------------------------
#*.*	@linux01     # udp transport
#*.*	@@linux01    # tcp transport
```
{% endcode %}

_Inspecting the SSH log event for failed login_

{% code overflow="wrap" %}
```log
[offsec@linux02 ~]$ sudo cat /var/log/secure | grep "Failed password"
<86>Jun 28 12:05:21 linux02 sshd[157165]:Failed password for offsec from 192.168.51.50 port 54209 ssh2
```
{% endcode %}

The event above is structed as so: Priority, Timestamp, Hostname, App Name, Process ID, Message.

_Syslog Facilities Codes_

| **Facility code** | **Keyword**     | **Description**                          |
| ----------------- | --------------- | ---------------------------------------- |
| 0                 | kern            | Kernel messages                          |
| 1                 | user            | User-level messages                      |
| 2                 | mail            | Mail system                              |
| 3                 | daemon          | System daemons                           |
| 4                 | auth            | Security/authentication messages         |
| 5                 | syslog          | Messages generated internally by syslogd |
| 6                 | lpr             | Line printer subsystem                   |
| 7                 | news            | Network news subsystem                   |
| 8                 | uucp            | UUCP subsystem                           |
| 9                 | cron            | Cron subsystem                           |
| 10                | authpriv        | Security/authentication messages         |
| 11                | ftp             | FTP daemon                               |
| 12                | ntp             | NTP subsystem                            |
| 13                | security        | Log audit                                |
| 14                | console         | Log alert                                |
| 15                | solaris-cron    | Scheduling daemon                        |
| 16–23             | local0 – local7 | Locally used facilities                  |

_Syslog Severity Levels_

| **Value** | **Severity**  | **Keyword** | **Description**                        |
| --------- | ------------- | ----------- | -------------------------------------- |
| 0         | Emergency     | emerg       | System is unusable - A panic condition |
| 1         | Alert         | alert       | Action must be taken immediately       |
| 2         | Critical      | crit        | Critical conditions                    |
| 3         | Error         | err         | Error conditions                       |
| 4         | Warning       | warning     | Warning conditions                     |
| 5         | Notice        | notice      | Normal but significant conditions      |
| 6         | Informational | info        | Informational messages                 |
| 7         | Debug         | debug       | Debug-level messages                   |

### Rsyslog Meets Journal

By default, systemd\_journald, or _journal_ is responsible for processing log events first.

_Inspecting Journal Logs_

{% code overflow="wrap" %}
```bash
[offsec@linux02 ~]$ journalctl -u sshd.service --since "1 hour ago"
-- Logs begin at Tue 2021-06-01 16:05:01 CEST, end at Tue 2021-06-22 15:00:31 CEST. --
Jun 22 15:00:31 linux02 sshd[131733]: Accepted password for offsec for offsec from 192.168.51.50 port 58379 ssh2
```
{% endcode %}

### Web Daemon Logging

_Inspecting an Apache log_

{% code overflow="wrap" %}
```log
[offsec@linux02 ~]$ sudo cat /var/log/httpd/access_log
192.168.51.50  - - [12/Jul/2021:08:57:30 -0400] "GET / HTTP/1.1" 403 199691 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
...
```
{% endcode %}

* **192.168.51.50** : The source IP that requested the web resource
* **- -**: As Remote Log Name and User ID do not appear in the log, these are replaced with a hyphen (-)
* **\[12/Jul/2021:08:57:30 -0400]**: Date and Time Zone (timestamp)
* **GET**: Request method
* **/**: The resource path, in this case the web server's root folder
* **HTTP/1.1**: Request version
* **403**: Response status[3](https://portal.offsec.com/courses/soc-200-28387/learning/linux-endpoint-introduction-31981/linux-applications-and-daemons-32254/web-daemon-logging-32043#fn-local_id_146-3)
* **199691**: The resource size
* **-** : Since the referrer of the resource is also not present, it is replaced with a hyphen (-)
* **Mozilla/5.0 (X11; Linux x86\_64; rv:78.0) Gecko/20100101 Firefox/78.0**: Client User Agent

_Filtering Apache Logs_

{% code overflow="wrap" %}
```log
[offsec@linux02 ~]$ sudo cat /var/log/httpd/access_log | grep " 403 "
192.168.51.50  - - [12/Jul/2021:08:57:30 -0400] "GET / HTTP/1.1" 403 199691 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
...
```
{% endcode %}

_Extracting a single log parameter_

{% code overflow="wrap" %}
```bash
[offsec@linux02 ~]$ sudo cat /var/log/httpd/access_log  | cut -d " " -f 7
/
/icons/poweredby.png
```
{% endcode %}

## Automating the Defensive Analysis

### Python for Log Analysis

The following four regex operators are essential to building more complex expressions:

* _^_ matches position just before the first character of the string
* _$_ matches position just after the last character of the string
* _._ matches a single character, except the newline (\n) character
* _\*_ matches preceding match zero or more times
* \+ matches preceding match one or more times

_Importing modules_

```python
import re
import os.path
```

_Declaring log path variables_

```python
centos_ssh_log_file_path = "/var/log/secure"
ubuntu_ssh_log_file_path = "/var/log/auth.log"
```

_Filling the array with variables_

```python
ssh_log_files = [centos_ssh_log_file_path, ubuntu_ssh_log_file_path]
```

_Declaring the regex variable_

```python
regex_pattern = 'sshd\[.*\]'
```

_Parsing the log files with nested for-loops_

<pre class="language-python" data-overflow="wrap" data-line-numbers><code class="lang-python"><strong># Loop through each file in our array
</strong><strong>for log_file in ssh_log_files:
</strong><strong>  # If the file exists, open it in read mode
</strong>  if os.path.isfile(log_file):
    with open(log_file, "r") as file:
      # For each line in the file, search for the regex pattern
      for line in file:
        for match in re.finditer(regex_pattern, line, re.S):
          # If pattern is found, print the line without adding a newline character
          print(line, end='')
</code></pre>

{% hint style="info" %}
An easy way to test regular expressions is to use the [_regex101_ online tool](https://regex101.com/), which when given a regex input, indicates whether we have any match on the target text.
{% endhint %}

### DevOps Tools

DevOps is an effort to combine traditional development practices and operational strategies into a joint mechanism that focuses on orchestration, automation, and consistency.

There are a few options available, such as Puppet, Chef, Ansible, etc.

_Ansible Log Parser Playbook_

```yaml
---
- name: logparser
  hosts: soc200
  tasks:

   - name: list files in folder
     become: yes
     become_user: root
     script: /home/kali/SOC-200/Linux_Endpoint_Introduction/ssh_log_parser.py
     args:
        executable: python3
     register: output
   - debug: var=output.stdout_lines
```

_Ansible Ping Reachability Test_

{% code overflow="wrap" %}
```bash
kali@attacker01:~$ sudo ansible soc200 -m ping -u offsec  --key-file=/home/kali/.ssh/ansible_rsa
192.168.51.12 | SUCCESS => {
    "ansible_facts": {
        "discovered_interpreter_python": "/usr/bin/python3"
    },
    "changed": false,
    "ping": "pong"
}
192.168.51.13 | SUCCESS => {
    "ansible_facts": {
        "discovered_interpreter_python": "/usr/libexec/platform-python"
    },
    "changed": false,
    "ping": "pong"
}
```
{% endcode %}

_Running the Ansible Playbook_

{% code overflow="wrap" %}
```bash
kali@attacker01:~/SOC-200/Linux_Endpoint_Introduction$ ansible-playbook ./log_parser.yml -u offsec  --key-file='/home/kali/.ssh/ansible_rsa' -K
BECOME password:

PLAY [logparser] *************************************************************************************************************************************************************************************

TASK [Gathering Facts] *******************************************************************************************************************************************************************************
ok: [192.168.51.12]
ok: [192.168.51.13]

TASK [list files in folder] **************************************************************************************************************************************************************************
changed: [192.168.51.12]
changed: [192.168.51.13]

TASK [debug] *****************************************************************************************************************************************************************************************
ok: [192.168.51.12] => {
    "output.stdout_lines": [
        "",
        "Jun 15 13:13:36 linux02 sshd[81613]: Failed password for offsec from 192.168.51.50 port 60040 ssh2",
        "Jun 16 09:11:28  linux02 sshd[84486]: Accepted password for offsec from 192.168.51.50 port 51741 ssh2"
    ]
}
ok: [192.168.51.13] => {
    "output.stdout_lines": [
        "",
        "Jun 16 09:16:11 linux01 sshd[47847]: Accepted password for offsec from 192.168.51.50 port 55660 ssh2",

    ]
}

PLAY RECAP *******************************************************************************************************************************************************************************************
192.168.51.12              : ok=3    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
192.168.51.13              : ok=3    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
```
{% endcode %}

{% hint style="info" %}
Ideally, we would parse distributed log files with a full-fledged SIEM solution. However, what we've practiced here can be useful as an initial proof-of-concept or a small-scaled log parsing alternative.
{% endhint %}

### Hunting for Login Attempts

_Walking through a "hunt"._
