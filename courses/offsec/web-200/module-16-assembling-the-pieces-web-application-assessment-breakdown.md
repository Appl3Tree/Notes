# Module 16: Assembling the Pieces: Web Application Assessment Breakdown

## Introduction to WEB-200 Challenge Machines

### Welcome to the Challenge Machines

_These fall between the sandbox and the cast study machines, running custom-designed applications intended to mimic real-world applications. You may need to combine multiple attacks or apply techniques in different ways to exploit them._

### Starting and Accessing Challenge Machines

_Start, revert, or stop the challenge machines from the **Labs** page. Add them to your hosts file for ease of access._

### Completing Challenge Machines

Each challenge machine contains two flags. Each machine may be different, but generally, there is a **local.txt** obtained within the application after performing an authenticated bypass attack. The **proof.txt** requires gaining a shell on the machine.

## Web Application Enumeration

### Accessing the Challenge Machine

_Start the VPN, the VM, and add its ip/hostname to your hosts file._

### Basic Host Enumeration and OS Detection

_Run nmap to identify open ports and other information._

Basic nmap scan of the challenge machine

```bash
kali@kali:~$ nmap asio
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-18 15:11 EST
Nmap scan report for asio (192.168.50.131)
Host is up (0.059s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 5.80 seconds
```

Nmap scan with OS discovery enabled

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo nmap -O -Pn asio       
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-18 15:12 EST
Nmap scan report for asio (192.168.50.131)
Host is up (0.059s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
3389/tcp open  ms-wbt-server
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: specialized|general purpose
Running (JUST GUESSING): AVtech embedded (87%), Microsoft Windows XP (85%)
OS CPE: cpe:/o:microsoft:windows_xp::sp3
Aggressive OS guesses: AVtech Room Alert 26W environmental monitor (87%), Microsoft Windows XP SP3 (85%)
No exact OS matches for host (test conditions non-ideal).

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.69 seconds
```
{% endcode %}

### Content Discovery

<figure><img src="../../../.gitbook/assets/c9a82e75da6afd9de5188a98b2cb18f3-atp_content_discovery_01.png" alt=""><figcaption><p><em>Strigi's Pizzeria Home Page</em></p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/67d68628c6b5f8c2ba9ee732da0249a6-atp_content_discovery_02.png" alt=""><figcaption><p>HTTP History includes external requests</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/6fc0f553d2b138486537c4797ca30e64-atp_content_discovery_03.png" alt=""><figcaption><p>Adding a Request to scope</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/6513d6fc5f0604b482409e0d09b90fb3-atp_content_discovery_04.png" alt=""><figcaption><p>Proxy history logging dialog window</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/f444bb3e55781b1f2946b2775074866d-atp_content_discovery_05.png" alt=""><figcaption><p>HTTP History Filter Settings</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/e2af12e01107aa1834eea59289c366c5-atp_content_discovery_06.png" alt=""><figcaption><p>HTTP POST Request from clicking Subscribe</p></figcaption></figure>

_Running gobuster against the challenge machine_

{% code overflow="wrap" %}
```bash
kali@kali:~$ gobuster dir -u http://asio -w /usr/share/wordlists/dirb/common.txt   
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://asio
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/01/18 15:38:10 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 302) [Size: 0] [--> http://asio/login]
/contact              (Status: 405) [Size: 105]                            
/error                (Status: 500) [Size: 73]                             
/login (Status: 200) [Size: 2746]
/logout               (Status: 302) [Size: 0] [--> http://asio/]     
/newsletter           (Status: 405) [Size: 108]                            
/redirect             (Status: 302) [Size: 0] [--> http://asio/]     
/specials             (Status: 400) [Size: 99]                             
                                                                           
===============================================================
2022/01/18 15:38:53 Finished
===============================================================
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/b0ae0b7dfd9c2b5be5a65f07af3e719a-atp_content_discovery_07.png" alt=""><figcaption><p>Login page</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/df033c741489ba677054742fa20f3707-atp_content_discovery_08.png" alt=""><figcaption><p>Whitelabel Error Page</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/58e109dcc50437b9e0393489443e9e41-atp_content_discovery_09.png" alt=""><figcaption><p>Burp Suite Site Map</p></figcaption></figure>

## Authentication Bypass

### Finding a Directory Traversal























### Exploiting a Directory Traversal



## Remote Code Execution

### Finding SQL Injection



### Exploit SQL Injection for RCE



### Obtaining a Shell



### Conclusion

