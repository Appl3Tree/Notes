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

# Module 7: Aircrack-ng Essentials

## Airmon-ng

Running **airmon-ng** without any parameters displays the status and information about the wireless interfaces on the system:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo airmon-ng

PHY	Interface	Driver		Chipset

phy0	wlan0		ath9k_htc	Atheros Communications, Inc. AR9271 802.11n


```
{% endcode %}

{% hint style="info" %}
While the interface name can be changed, "phy" is a unique and immutable identifier that a mac80211[1](https://portal.offsec.com/courses/pen-210-9545/learning/aircrack-ng-essentials-15808/aircrack-ng-essentials-15935#fn-local\_id\_45-1) interface gets until a reboot or each time a Wi-Fi adapter is plugged in and its driver is loaded. Therefore, plugging and unplugging the same Wi-Fi adapter will result in incremented "phy" numbers.
{% endhint %}

### Airmon-ng check

It's important to identify and terminate processes like Newtork Manager which can interfere with the tools in the Aircrack-ng suite. The **check** parameters checks for and lists these processes:

```bash
kali@kali:~$ sudo airmon-ng check

Found 3 processes that could cause trouble.
Kill them using 'airmon-ng check kill' before putting
the card in monitor mode, they will interfere by changing channels
and sometimes putting the interface back in managed mode

   PID Name
  1885 NetworkManager
  1955 wpa_supplicant
  2015 dhclient
```

Using airmon-ng with the **check kill** paremeters will try to gracefully stop known services and kill the rest of the processes:

```bash
kali@kali:~$ sudo airmon-ng check kill

Killing these processes:

   PID Name
  1955 wpa_supplicant
  2015 dhclient
```

{% hint style="info" %}
If Internet access is needed, it should be configured manually after putting the interface in monitor mode using tools such as _dhclient_ and/or _wpa\_supplicant_ on another interface. If access point mode is required, it should be manually configured as well using _hostapd_.
{% endhint %}

### Airmon-ng start

Placing our wlan0 interface in monitor mode:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo airmon-ng start wlan0

PHY	Interface	Driver		Chipset

phy0	wlan0		ath9k_htc	Atheros Communications, Inc. AR9271 802.11n

		(mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)
		(mac80211 station mode vif disabled for [phy0]wlan0)
```
{% endcode %}

Starting monitor mode on a specific channel:

```bash
kali@kali:~$ sudo airmon-ng start wlan0 3

PHY	Interface	Driver		Chipset

phy0	wlan0		ath9k_htc	Atheros Communications, Inc. AR9271 802.11n

		(mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)
		(mac80211 station mode vif disabled for [phy0]wlan0)
```

Running **iw** to show our monitor mode interface's information:

```bash
kali@kali:~$ sudo iw dev wlan0mon info
Interface wlan0mon
	ifindex 6
	wdev 0x4
	addr 00:13:a7:12:3c:5b
	type monitor
	wiphy 0
	channel 3 (2422 MHz), width: 20 MHz (no HT), center1: 2422 MHz
	txpower 20.00 dBm
```

We can also use **iwconfig** however it is deprecated:

{% code fullWidth="false" %}
```bash
kali@kali:~$ sudo iwconfig wlan0mon
wlan0mon  IEEE 802.11  Mode:Monitor  Frequency:2.422 GHz  Tx-Power=20 dBm   
          Retry short limit:7   RTS thr:off   Fragment thr:off
          Power Management:off
```
{% endcode %}

The **--verbose** option outputs release information from lsb\_release -a, kernel information from uname -a, virtual machine detection, and details about connected interfaces.

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo airmon-ng --verbose

No LSB modules are available.
Distributor ID:	Kali
Description:	Kali GNU/Linux Rolling
Release:	2019.3
Codename:	kali-rolling

Linux kali 4.19.0-kali5-amd64 #1 SMP Debian 4.19.37-6kali1 (2019-07-22) x86_64 GNU/Linux
Detected VM using lspci
This appears to be a VMware Virtual Machine
If your system supports VT-d, it may be possible to use PCI devices
If your system does not support VT-d, you can only use USB wifi cards

K indicates driver is from 4.19.0-kali5-amd64
V indicates driver comes directly from the vendor, almost certainly a bad thing
S indicates driver comes from the staging tree, these drivers are meant for reference not actual use, BEWARE
? indicates we do not know where the driver comes from... report this


X[PHY]Interface		Driver[Stack]-FirmwareRev		Chipset										Extended Info

K[phy0]wlan0		ath9k_htc[mac80211]-1.4			Qualcomm Atheros Communications AR9271 802.11n					mode managed
```
{% endcode %}

In comparison, the output with **--debug** provides slightly more details derived from system commands:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo airmon-ng --debug

/bin/sh -> /usr/bin/dash

SHELL is GNU bash, version 5.0.3(1)-release (x86_64-pc-linux-gnu)
Copyright (C) 2019 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>

This is free software; you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

No LSB modules are available.
Distributor ID:	Kali
Description:	Kali GNU/Linux Rolling
Release:	2019.3
Codename:	kali-rolling

Linux kali 4.19.0-kali5-amd64 #1 SMP Debian 4.19.37-6kali1 (2019-07-22) x86_64 GNU/Linux
Detected VM using lspci
This appears to be a VMware Virtual Machine
If your system supports VT-d, it may be possible to use PCI devices
If your system does not support VT-d, you can only use USB wifi cards

K indicates driver is from 4.19.0-kali5-amd64
V indicates driver comes directly from the vendor, almost certainly a bad thing
S indicates driver comes from the staging tree, these drivers are meant for reference not actual use, BEWARE
? indicates we do not know where the driver comes from... report this


X[PHY]Interface		Driver[Stack]-FirmwareRev		Chipset										Extended Info

getStack mac80211
getBus usb
getdriver() ath9k_htc
getchipset() Qualcomm Atheros Communications AR9271 802.11n
BUS = usb
BUSINFO = 0CF3:9271
DEVICEID = 
getFrom() K
getFirmware 1.4	
K[phy0]wlan0		ath9k_htc[mac80211]-1.4			Qualcomm Atheros Communications AR9271 802.11n					mode managed
```
{% endcode %}

### Airmon-ng stop

Disabling monitor mode with the **stop** parameter:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo airmon-ng stop wlan0mon

PHY	Interface	Driver		Chipset

phy0	wlan0mon	ath9k_htc	Atheros Communications, Inc. AR9271 802.11n

		(mac80211 station mode vif enabled on [phy0]wlan0)

		(mac80211 monitor mode vif disabled for [phy0]wlan0mon)
```
{% endcode %}

## Airodump-ng

### Airodump-ng Usage

Run **airodump-ng** without parameters to display the options. The options most often used are for saving to a file, filtering by BSSID, and capturing only on a specific channel:

| Option        | Description                                                 |
| ------------- | ----------------------------------------------------------- |
| -w prefix     | Saves the capture dump to the specified filename            |
| --bssid BSSID | Filters Airodump-ng to only capture the specified BSSID     |
| -c channel(s) | Forces Airodump-ng to only capture the specified channel(s) |

### Sniffing with Airodump-ng

Initiating our first sniffing session, only capturing on channel 2:

```bash
kali@kali:~$ sudo airodump-ng wlan0mon -c 2
```

{% code title="airodump-ng output" overflow="wrap" %}
```bash
CH  2 ][ Elapsed: 12 s ][ 2011-11-06 13:31 ][ WPA handshake: C8:BC:C8:FE:D9:65                                         

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID

 C8:BC:C8:FE:D9:65  -23  87      579       69    1   2  54e. WPA2 CCMP   PSK  secnet
 34:08:04:09:3D:38  -30   0      638       24    0   3  54e  OPN              wifu
 00:18:E7:ED:E9:69  -84  10      104        0    0   3  54e. OPN              dlink        

 BSSID              STATION            PWR   Rate    Lost  Packets  Probes        

 C8:BC:C8:FE:D9:65  0C:60:76:57:49:3F  -69    0 - 1      0       35  secnet
 34:08:04:09:3D:38  00:18:4D:1D:A8:1F  -26   54 -54      0       31  wifu
 30:46:9A:FE:79:B7  30:46:9A:FE:69:BE  -73    0 - 1      0        1
```
{% endcode %}

#### Airodump-ng Fields in the top section

| Field   | Description                                                                                                                                                                                                                      |
| ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| BSSID   | The MAC address of the AP                                                                                                                                                                                                        |
| PWR     | The signal level reported by the card, which will get higher as we get closer to the AP or station                                                                                                                               |
| RXQ     | Receive Quality as measured by the percentage of frames successfully received over the last 10 seconds                                                                                                                           |
| Beacons | Number of announcement frames sent by the AP                                                                                                                                                                                     |
| # Data  | Number of captured data packets (if WEP, this is the unique IV count), including data broadcast packets                                                                                                                          |
| #/s     | Number of data packets per second measured over the last 10 seconds                                                                                                                                                              |
| CH      | Channel number taken from beacon frames. Note that sometimes frames from other channels are captured due to overlapping channels                                                                                                 |
| MB      | Maximum speed supported by the AP. 11=802.11b, 22=802.11b+, up to 54 is 802.11g and anything higher is 802.11n or 802.11ac                                                                                                       |
| ENC     | Encryption algorithm in use. OPN=no encryption, "WEP?"=WEP or higher (not enough data to choose between WEP and WPA/WPA2), WEP=static or dynamic WEP, and WPA or WPA2 if TKIP or CCMP is present. WPA3 and OWE both require CCMP |
| CIPHER  | The cipher detected: CCMP, WRAP, TKIP, WEP, WEP40, or WEP104                                                                                                                                                                     |
| AUTH    | The authentication protocol used. One of MGT (WPA/WPA2/WPA3 Enterprise), SKA (WEP shared key), PSK (WPA/WPA2/WPA3 pre shared key), or OPN (WEP open authentication)                                                              |
| ESSID   | The so-called SSID, which can be empty if the SSID is hidden                                                                                                                                                                     |

#### Airodump-ng Fields in the bottom section

| Field   | Description                                                                      |
| ------- | -------------------------------------------------------------------------------- |
| BSSID   | The MAC address of the AP                                                        |
| STATION | The MAC address of each associated station                                       |
| Rate    | Station's receive rate, followed by transmit rate                                |
| Lost    | Number of data frames lost over the last 10 seconds based on the sequence number |
| Packets | Number of data packets sent by the client                                        |
| Probes  | The ESSIDs probed by the client                                                  |

### Precision Sniffing

Specifying the channel, bssid, and the output file we'd like when performing a dump:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo airodump-ng -c 3 --bssid 34:08:04:09:3D:38 -w cap1 wlan0mon
...
CH  3 ][ Elapsed: 4 mins ][ 2011-11-06 15:14                                         

BSSID              PWR RXQ  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID                                         

34:08:04:09:3D:38  -29  62     2369      381    1   3  54e  OPN              wifu                                          

BSSID              STATION            PWR   Rate    Lost  Packets  Probes                                                  

34:08:04:09:3D:38  00:18:4D:1D:A8:1F  -26    6 -48      0      399 wifu
```
{% endcode %}

### Airodump-ng Output Files

By default, using the **-w** option will output to PCAP, CSV, Kismet legacy CSV, Kismet legacy NetXML, and Log CSV. GPS coordinates _can_ be included with the **-g** option and the Initialization Vectors with the **--ivs** option (only useful for WEP cracking).

We can limit file formats generated by using the **--output-format** option followed by a comma separated list of file formats.

```bash
kali@kali:~$ sudo airodump-ng --output-format csv,pcap wlan0mon
```

### Airodump-ng Interactive Mode

| Key Press      | Action                                                                                                                                                                                                                                                                                         |
| -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Space          | Pause/Resume output                                                                                                                                                                                                                                                                            |
| Tab            | Enables/Disables scrolling through the AP list                                                                                                                                                                                                                                                 |
| Up/Down Arrows | When scrolling through the AP list is enabled, provides scrolling                                                                                                                                                                                                                              |
| M              | Cycles through color options for a selected AP                                                                                                                                                                                                                                                 |
| A              | <p>Cycles through display options:</p><ul><li>APs and stations (default)</li><li>APs and stations plus ACK statistics</li><li>APs only</li><li>Stations only</li></ul>                                                                                                                         |
| S              | <p>Cycles through sorting options:</p><ul><li>Amount of beacons</li><li>Amount of data packets</li><li>Packet rate</li><li>Channel</li><li>Max data rate</li><li>Encryption</li><li>Cipher</li><li>Authentication</li><li>ESSID</li><li>First seen</li><li>BSSID</li><li>Power level</li></ul> |
| I              | Inverts the sorting                                                                                                                                                                                                                                                                            |
| D              | Resets to the default sorting (by power level)                                                                                                                                                                                                                                                 |

### Airodump-ng Troubleshooting

#### No APs or Clients are Shown

* _Verify there are APs on current channel._
* _Make sure card works in managed mode._&#x20;
* _Unload the driver (**rmmod**) and reload it with **modprobe**._
* _Check **dmesg** for errors._

#### Little or No Data Being Captured

* _Specify a channel._
* _Get closer to the AP._
* _Confirm in monitor mode._
* _Confirm no network processes/services causing interference._

#### Airodump-ng Stops Capturing After a Short Period of Time

* _Confirm no network processes/services causing interference._
* _Check **dmesg** for firmware issues._

#### SSIDs Displayed as "\<length: ?>"

* _Get closer to the AP._

#### "Fixed channel" Error Message

* _Confirm no network processes/services causing interference._
* _Confirm your card can use the specified channel._

#### No Output Files

* _Confirm the **-w** or **--write** parameters were used with a filename prefix._
* _Confirm you're looking in the directory included in the path for output files (default is directory airodump-ng was run from)._

## Aireplay-ng

#### Aireplay-ng supports the following attacks:

| Attack # | Attack Name                          |
| -------- | ------------------------------------ |
| 0        | Deauthentication                     |
| 1        | Fake Authentication                  |
| 2        | Interactive Packet Replay            |
| 3        | ARP Request Replay Attack            |
| 4        | KoreK ChopChop Attack                |
| 5        | Fragmentation Attack                 |
| 6        | Café-Latte Attack                    |
| 7        | Client-Oriented Fragmentation Attack |
| 8        | WPA Migration Mode Attack            |
| 9        | Injection Test                       |

### Aireplay-ng Replay Options

#### All available options for aireplay-ng attacks:

| Option    | Description                             |
| --------- | --------------------------------------- |
| -x nbpps  | Number of packets per second            |
| -p fctrl  | Set frame control word (hex)            |
| -a bssid  | Access point MAC address                |
| -c dmac   | Destination MAC address                 |
| -h smac   | Source MAC address                      |
| -e essid  | Target AP SSID                          |
| -j        | arpreplay attack: inject FromDS packets |
| -g value  | Change ring buffer size (default: 8)    |
| -k IP     | Destination IP in fragments             |
| -l IP     | Source IP in fragments                  |
| -o npckts | Number of packets per burst (-1)        |
| -q sec    | Seconds between keep-alives (-1)        |
| -y prga   | Keystream for shared key authentication |
| -B        | Bit rate test                           |
| -D        | Disable AP detection                    |
| -F        | Chooses first matching packet           |
| -R        | Disables /dev/rtc usage                 |

### Aireplay-ng Injection Test

#### Basic Injection Test:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo airmon-ng start wlan0 3

PHY	Interface	Driver		Chipset

phy0	wlan0		ath9k_htc	Atheros Communications, Inc. AR9271 802.11n

		(mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)
		(mac80211 station mode vif disabled for [phy0]wlan0)

kali@kali:~$ sudo aireplay-ng -9 wlan0mon
12:02:10  Trying broadcast probe requests...
12:02:10  Injection is working!
12:02:11  Found 2 APs

12:02:12  34:08:04:09:3D:38 - channel: 3 - 'wifu'
12:02:13  Ping (min/avg/max): 1.455ms/4.163ms/12.006ms Power: -37.63
12:02:13  30/30: 100%

12:02:13  C8:BC:C8:FE:D9:65 - channel: 2 - 'secnet'
12:02:13  Ping (min/avg/max): 1.637ms/4.516ms/18.474ms Power: -28.90
12:02:13  30/30: 100%
```
{% endcode %}

#### Injection test for a specific SSID:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo aireplay-ng -9 -e wifu -a 34:08:04:09:3D:38 wlan0mon
12:26:14  Waiting for beacon frame (BSSID: 34:08:04:09:3D:38) on channel 3
12:26:14  Trying broadcast probe requests...
12:26:14  Injection is working!
12:26:16  Found 1 AP 

12:26:16  Trying directed probe requests...
12:26:16  34:08:04:09:3D:38 - channel: 3 - 'wifu'
12:26:16  Ping (min/avg/max): 1.968ms/3.916ms/11.581ms Power: -35.73
12:26:16  30/30: 100%
```
{% endcode %}

#### Card-to-Card (Attack) Injection Test:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo aireplay-ng -9 -i wlan1mon wlan0mon

12:50:57  Trying broadcast probe requests...
12:50:57  Injection is working!
12:50:59  Found 2 APs

12:50:59  Trying directed probe requests...
12:50:59  34:08:04:09:3D:38 - channel: 3 - 'wifu'
12:51:00  Ping (min/avg/max): 1.735ms/4.619ms/12.689ms Power: -47.33
12:51:00  27/30:  90%

12:51:01  C8:BC:C8:FE:D9:65 - channel: 2 - 'secnet'
12:51:01  Ping (min/avg/max): 2.943ms/17.900ms/49.663ms Power: -117.10
12:51:01  29/30:  96%

12:51:01  Trying card-to-card injection...
12:51:01  Attack -0:           OK
12:51:02  Attack -1 (open):    OK
12:51:02  Attack -1 (psk):     OK
12:51:02  Attack -2/-3/-4/-6:  OK
12:51:02  Attack -5/-7:        OK
```
{% endcode %}

### Aireplay-ng Troubleshooting

#### Aireplay-ng does not Inject Frames

* _Ensure you're using the correct monitor mode interface._

#### Aireplay-ng Hangs with No Output

* _Confirm wireless card is on the same channel as the AP._

#### interfacexmon is on channel Y, but the AP uses channel Z

* _Confirm monitor mode was started in the correct channel._
* _Check for network processes/services causing interference._

#### Aireplay-ng General Troubleshooting Tips

* _Look for deauthentication or disassociation messages during injection._
* _Ensure wireless card driver is properly patched and installed._
* _Be physically close enough to the AP._
* _Verify monitor mode._
* _Verify channel matches the AP._

## Aircrack-ng

{% hint style="warning" %}
Aircrack-ng is CPU intensive and will fully use all the CPUs. Laptops typically aren't built for constant CPU load for long periods of time. This can raise the temperature of the CPU significantly. If the laptop's cooling system is inadequate, the CPU will be throttled, which will reduce performance. Sometimes, the cooling system can't even handle throttled CPUs, and the CPU may end up suddenly turning off to protect itself and other components from damage. Adding an active cooling pad might help. We can also monitor the temperatures. In Linux we'll do this with the _lm-sensors_ command.
{% endhint %}

### Aircrack-ng Benchmark

Running benchmark mode:

```bash
kali@kali:~$ aircrack-ng -S
11117.918 k/s
```

## Airdecap-ng

### Removing Wireless Headers

Removing wireless headers from an unencrypted capture file. Using **-b** to specify the BSSID and setting the AP MAC to keep:

```bash
kali@kali:~$ sudo airdecap-ng -b 34:08:04:09:3D:38 opennet-01.cap
Total number of stations seen            0
Total number of packets read           307
Total number of WEP data packets         0
Total number of WPA data packets         0
Number of plaintext data packets         0
Number of decrypted WEP  packets         0
Number of corrupted WEP  packets         0
Number of decrypted WPA  packets         0
Number of bad TKIP (WPA) packets         0
Number of bad CCMP (WPA) packets         0
```

Airdecap-ng saved the data packets linked to 34:08:04:09:3D:38 into a new capture file, with -dec (decrypted) appended to the original filename: opennet-01-dec.cap.

## Airgraph-ng

### Clients to AP Relationship Graph

The Clients to AP Relationship (CAPR) graph type displays the relationships between clients and APs. Running airgraph-ng with the **-o** option to output to a file name, the **-i** option to input an airodump-ng .csv file, and **-g** to define a CAPR graph:

```bash
kali@kali:~$ mkdir support

kali@kali:~$ cd support

kali@kali:~$ wget http://standards-oui.ieee.org/oui.txt

kali@kali:~$ cd ..

kali@kali:~$ airgraph-ng -o Picture1_png -i dump-01.csv -g CAPR
```

<figure><img src="../../../.gitbook/assets/image (5).png" alt=""><figcaption><p>A CAPR graph</p></figcaption></figure>

### Clients Probe Graph

The Client Probe Graph (CPG) displays relationships between wireless clients and probed networks. Creating this graph with a airodump-ng **.csv** file, and specifiying the graph type as CPG with **-g CPG:**

```bash
kali@kali:~$ airgraph-ng -o Picture2.png -i dump-01.csv -g CPG
```

<figure><img src="../../../.gitbook/assets/image (1) (1).png" alt=""><figcaption><p>A CPG graph</p></figcaption></figure>
