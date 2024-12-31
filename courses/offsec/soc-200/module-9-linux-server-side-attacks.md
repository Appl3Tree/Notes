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



### Extra Mile II



## Web Application Attacks

### Command Injection



### Extra Mile II



### SQL Injection



### Extra Mile IV

