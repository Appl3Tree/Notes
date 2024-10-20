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

# Module 5: Wireshark Essentials

## Getting Started

Putting the wireless adapter into monitor mode:

```bash
kali@kali:~$ sudo ip link set wlan0 down
kali@kali:~$ sudo iwconfig wlan0 mode monitor
kali@kali:~$ sudo ip link set wlan0 up
```

### Welcome Screen

<figure><img src="../../../.gitbook/assets/image (27).png" alt=""><figcaption><p>Wireshark startup screen</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption><p>Interface types selector</p></figcaption></figure>

### Packet Display

<figure><img src="../../../.gitbook/assets/image (29).png" alt=""><figcaption><p>Capturing - Packet list</p></figcaption></figure>

Rearrange the packet list layout via _Edit > Preferences > Appearance > Layout_.

### Wireless Toolbar

<figure><img src="../../../.gitbook/assets/image (30).png" alt=""><figcaption><p>Wireless toolbar checkbox</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (31).png" alt=""><figcaption><p>Wireless toolbar</p></figcaption></figure>

{% hint style="info" %}
Wireshark doesn't _channel hop_ and will stay on whatever channel the wireless adapter is currently on.
{% endhint %}

Changing the channel via script while listening with Wireshark:

```bash
for channel in 1 6 11 2 7 10 3 8 4 9 5
do
    iw dev wlan0mon set channel ${channel}
    sleep 1
done
```

_airodump-ng_ could also be used for channel hopping. Running `sudo airodump-ng wlan0mon` would have a similar result to the above script.

### Saving and Exporting Packets

We can save the whole contents of a packet capture via _File > Save_ or _File > Save As..._ When saving the packets, we are also able to use a filter to save specified packets via _File > Export Specified Packets..._

<figure><img src="../../../.gitbook/assets/image (32).png" alt=""><figcaption><p>Export specified packets</p></figcaption></figure>

## Wireshark Filters

### Wireshark Display Filters

These filters just affect what packets are visible in Wireshark's packet list. Wireshark will still capture packets not shown due to a Display Filter.

<figure><img src="../../../.gitbook/assets/image (33).png" alt=""><figcaption><p>Packet list columns</p></figcaption></figure>

The best way to understand the Display Filter syntax is to create one with the Display Filter Expression screen found at _Analyze > Display Filter Expression..._

<figure><img src="../../../.gitbook/assets/image (34).png" alt=""><figcaption><p>Display Filter Expression builder</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (35).png" alt=""><figcaption><p>Display Filter Expression builder - Relation explanations</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (38).png" alt=""><figcaption><p>Display filter autocomplete</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (39).png" alt=""><figcaption><p>Invalid filter</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (40).png" alt=""><figcaption><p>Filter with possibly unexpected results</p></figcaption></figure>

Display filters can be bookmarked for later/repeated use via the bookmark button on the left of the Display Filter tool bar. Shortcuts can be created by clicking the + on the very right of the Display Filter toolbar.

### Wireshark Capture Filters

Capture Filters (AKA Berkeley Packet Filters (BPF)) allow Wireshark to only collect a specific type of data. They decrease the amount of data _received_ rather than the amount _displayed_ like a Display Filter. Capture filters are documented in the _pcap-filter_ man page.

## Wireshark at the Command Line

Getting help for wireshark at the command line:

```bash
kali@kali:~$ wireshark --help
Wireshark 3.2.1 (Git v3.2.1 packaged as 3.2.1-1)
Interactively dump and analyze network traffic.
See https://www.wireshark.org for more information.

Usage: wireshark [options] ... [ <infile> ]

Capture interface:
  -i <interface>, --interface <interface>
                           name or idx of interface (def: first non-loopback)
  -f <capture filter>      packet filter in libpcap filter syntax
  -s <snaplen>, --snapshot-length <snaplen>
                           packet snapshot length (def: appropriate maximum)
...
  -k                       start capturing immediately (def: do nothing)
...
  -I, --monitor-mode       capture in monitor mode, if available
...
  -D, --list-interfaces    print list of interfaces and exit
...
```

Listing all available interfaces along with their index numbers:

```bash
kali@kali:~$ sudo wireshark -D
Capture-Message: 14:05:44.552: Capture Interface List ...
Capture-Message: 14:05:44.697: Loading External Capture Interface List ...
1. eth0
2. lo (Loopback)
3. any
4. wlan0mon
5. nflog
6. nfqueue
7. ciscodump (Cisco remote capture)
8. dpauxmon (DisplayPort AUX channel monitor capture)
9. randpkt (Random packet generator)
10. sdjournal (systemd Journal Export)
11. sshdump (SSH remote capture)
12. udpdump (UDP Listener remote capture)
```

Starting a capture, specifying our interface in monitor mode (this will automatically open the GUI with the packet capture running):

```bash
kali@kali:~$ sudo wireshark -i wlan0mon -k
QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-root'
...
```

## Remote Packet Capture

Covering multiple tools, it's good to understand pros and cons. Dumpcap has lower overhead compared to tcpdump and tshark. This difference in CPU usage will likely not be noticeable until transferring more data or using low power devices as the capture devices.

### Remote Packet Capture Setup

TCPdump output on stdout:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo tcpdump -i wlan0mon -w - -U
�ò�tcpdump: listening on wlan0mon, link-type IEEE802_11_RADIO (802.11 plus radiotap header), capture size 262144 bytes
```
{% endcode %}

dumpcap output on stdout:

```bash
kali@kali:~$ sudo dumpcap -w - -P -i wlan0mon
Capturing on 'wlan0mon'
�ò�File: -
9UY^m*.Hl	�������������5����5��1�d
...
```

tshark output on stdout:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo tshark -w - -i wlan0mon
Running as user "root" and group "root". This could be dangerous.
Capturing on 'wlan0mon'

�M<+���������6Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz (with SSE4.2)Linux 5.4.0-kali3-amd64:Dumpcap (Wireshark) 3.2.1 (Git v3.2.1 packaged as 3.2.1-1)�wlan0mon
...
```
{% endcode %}

#### Pipes

_Named pipes_, also known as First in, First out (FIFO) IPC objects, are present on the filesystem and allow bi-directional communications.

_Unnamed pipes_, also known as unnamed IPC objects, make use of the _pipe()_ function. One way we might use this function is when we chain commands in terminals by using the pipe (|) character.

One pipe example:

```bash
kali@kali:~$ ls /var/log | more
```

Capturing traffic and piping it to Wireshark:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo tcpdump -U -w - -i wlan0mon | wireshark -k -i -
tcpdump: listening on wlan0mon, link-type IEEE802_11_RADIO (802.11 plus radiotap header), capture size 262144 bytes
```
{% endcode %}

Creating a named pipe using **mkfifo**:

```bash
kali@kali:~$ mkfifo /tmp/named_pipe
kali@kali:~$ ls -l /tmp/named_pipe
prw-r--r-- 1 kali kali 0 Jul 27 20:47 /tmp/named_pipe
```

Configuring the named pipe in Wireshark:

1. _Capture > Options..._
2. _Manage Interfaces > Pipes_ tab _> +_
3. Enter the pipe's path name, in our case **/tmp/named\_pipe**
4. Click OK

Initiating a packet capture, writing to our named pipe:

```bash
kali@kali:~$ sudo tcpdump -U -w - -i wlan0mon > /tmp/named_pipe
```

Capturing traffic with tcpdump on a remote host and piping it to Wireshark on our device:

{% code overflow="wrap" %}
```bash
kali@kali:/$ ssh root@10.11.0.196 "sudo -S tcpdump -U -w - -i wlan0mon" | sudo wireshark -k -i -
QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-root'
root@10.11.0.196's password:******
tcpdump: listening on wlan0mon, link-type IEEE802_11_RADIO (802.11 plus radiotap header), capture size 262144 bytes
```
{% endcode %}

### Built-in Wireshark

<figure><img src="../../../.gitbook/assets/image (41).png" alt=""><figcaption><p>External virtual interfaces in dropdown box</p></figcaption></figure>

Select _SSH remote capture: sshdump_ then _Capture_ to open the options window.

{% hint style="info" %}
Wireshark typically captures from interfaces on the local system. These "External Capture" interfaces are using _ExtCap_, which allows executables to be seen as capture interfaces. All of these are separate binaries: ciscodump, dpauxmon, randpkt, sdjournal, sshdump, and udpdump. They provide data in PCAP format and can be found in the /usr/lib/x86\_64-linux-gnu/wireshark/extcap/ directory (on a 64bit Kali). Some of these tools have man pages but they all are executed with a few arguments. All of them are similarly configured in the Wireshark GUI.
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (42).png" alt=""><figcaption><p>SSHdump - Server tab</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (43).png" alt=""><figcaption><p>SSHdump - Authentication tab</p></figcaption></figure>

{% hint style="info" %}
In this example, we are authenticating to the remote system as root. To use a standard user instead, you will need to run 'sudo dpkg-reconfigure wireshark-common / yes' to reconfigure the wireshark package and 'sudo usermod -a -G wireshark kali' to add the user (kali in this example) to the wireshark group
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (44).png" alt=""><figcaption><p>SSHdump - Capture tab</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (45).png" alt=""><figcaption><p>SSHdump - Debug tab</p></figcaption></figure>

{% hint style="info" %}
When _Save parameter(s) on capture start_ is checked, the next time SSHdump is used, it won't prompt for settings and will start automatically. If the settings are not properly set and an error results, Wireshark does not make resetting to the defaults easy. They can be reset via _Edit_ > _Preferences..._ > _Advanced_. In the resulting _Search:_ textbox, we type "sshdump". Then double click every modified parameter (anything in bold) to set SSHDump back to the default values. Click on _OK_ and SSHDump is back to its default configuration.
{% endhint %}

## Advanced Preferences

### Coloring Rules

To make analysis easier, apply colored highlights to packets in the packet list via _View > Colorize Packet List_. Rules can be viewed under _View > Coloring rules_. When a rule matches, the processing stops. It also skips disabled (unchecked) rules.

### Wireshark Columns

Columns can be moved, resized, removed, hidden, and added in the Wireshark Packet List. They can be managed in _Edit > Preferences..._ then selecting _Columns_ under _Appearance_. They can also by managed by right-clicking the columns/drag-drop.

### Capture snaplen

Setting a _snaplen_ or snapshot length, allows us to limit how much data we capture. All mentioned tools can set the snaplen for a capture. The default snaplen value is 262144.

### IEEE 802.11 Preferences

Various settings regarding 802.11 can be managed by going to _Edit > Preferences_ then expanding _Protocols_ and clicking on _IEEE 802.11_.

### WEP and WPA1/2 Decryption

To decrypt WEP and/or WPA1/2, we have to check _Enable decryption_ and provide decryption keys. This can be done by clicking on _Edit..._ to the right of _Decryption keys_. Adding a WEP key requires selecting _wep_ in the _Key type_ then filling in the _Key_ field with the WEP key in hexadecimal.

<figure><img src="../../../.gitbook/assets/image (46).png" alt=""><figcaption><p>Adding a WEP key</p></figcaption></figure>

The _wpa-pwd_ is for WPA passphrases. The format is PASSPHRASE:ESSID.

<figure><img src="../../../.gitbook/assets/image (47).png" alt=""><figcaption><p>Adding a WPA PSK key with SSID</p></figcaption></figure>

Omitting the ESSID results in Wireshark applying this passphrase to any network, using it along with the last found ESSID in the packet list.

The last option, _wpa-psk_ allows us to enter the hexadecimal Pairwise Master Key (PMK). Thi sis useful for decrypting WPA1/2 Enterprise paackets, when using PSK and the ESSID, or when the passphrase contains a colon character.

<figure><img src="../../../.gitbook/assets/image (48).png" alt=""><figcaption><p>Adding a WPA PMK</p></figcaption></figure>

_wpa\_passphrase_ is part of _wpa\_supplicant_ can be used to generate the PMK. The wpa\_passphrase command requires one parameter, the SSID. The second parameter, a passphrase, is optional. If we don't provide a passphrase, it will prompt for user input.

{% code overflow="wrap" %}
```bash
kali@kali:~$ wpa_passphrase test abcdefg:
network={
	ssid="test"
	#psk="abcdefg:"
	psk=a1c425c0f4e5ff3746920c90cc55d17f4773512b6c1ed415526a3bcea3351b5b
}
```
{% endcode %}

### WLAN Statistics

WLAN Statistics display an overview for all the wireless frames in the packet list. This can be viewed in _Wireless > WLAN traffic_.&#x20;
