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

# Module 4: Linux Wireless Tools, Drivers, and Stacks

## Loading and Unloading Wireless Drivers

&#x20;Determining our wireless device's driver:

```bash
kali@kali:~$ sudo airmon-ng

PHY     Interface       Driver          Chipset

phy0    wlan0           ath9k_htc       Qualcomm Atheros Communications AR9271 802.11n
```

Listing our system's USB devices with detailed information for each one:

```bash
kali@kali:~# sudo lsusb -vv

Bus 001 Device 002: ID 0cf3:9271 Qualcomm Atheros Communications AR9271 802.11n
Device Descriptor:
  bLength                18
  bDescriptorType         1
  bcdUSB               2.00
  bDeviceClass          255 Vendor Specific Class
  bDeviceSubClass       255 Vendor Specific Subclass
  bDeviceProtocol       255 Vendor Specific Protocol
  bMaxPacketSize0        64
  idVendor           0x0cf3 Qualcomm Atheros Communications
  idProduct          0x9271 AR9271 802.11n
  bcdDevice            1.08
  iManufacturer          16 ATHEROS
  iProduct               32 USB2.0 WLAN
  iSerial                48 12345
  bNumConfigurations      1
...
```

{% hint style="info" %}
In Linux, one driver can cover multiple devices, and sometimes multiple similar chipsets. In Windows, each and every piece of hardware needs to have its own driver installed.
{% endhint %}

Kernel modules often have parameters to adjust settings of the hardware. These settings are displayed with the _modinfo_ command and the name of the driver:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo modinfo ath9k_htc
filename:       /lib/modules/4.16.0-kali2-amd64/kernel/drivers/net/wireless/ath/ath9k/ath9k_htc.ko
firmware:       ath9k_htc/htc_9271-1.4.0.fw
firmware:       ath9k_htc/htc_7010-1.4.0.fw
description:    Atheros driver 802.11n HTC based wireless devices
license:        Dual BSD/GPL
author:         Atheros Communications
alias:          usb:v0CF3p20FFd*dc*dsc*dp*ic*isc*ip*in*
...
alias:          usb:v0CF3p1006d*dc*dsc*dp*ic*isc*ip*in*
alias:          usb:v0CF3p9271d*dc*dsc*dp*ic*isc*ip*in*
depends:        mac80211,ath9k_hw,ath9k_common,ath,cfg80211,usbcore
retpoline:      Y
intree:         Y
name:           ath9k_htc
vermagic:       4.16.0-kali2-amd64 SMP mod_unload modversions
parm:           debug:Debugging mask (uint)
...
parm:           blink:Enable LED blink on activity (int)
```
{% endcode %}

As an example, disabling blinking on network activity on the ath9k\_htc driver by resetting the _blink_ parameter when loading the driver:

```bash
kali@kali:~$ sudo modprobe ath9k_htc blink=0
```

Linux distributions allow users to set and change parameters for modules using **/etc/modprobe.d** as well as allows users to blacklist modules. An example case of needing to blacklist a module is an open source and closed source driver being present with both sharing similar IDs. There should only ever be one driver claiming a device at a time, so we blacklist one of them.

**lsmod** lists all the loaded modules as well as the dependencies of each module.

```
kali@kali:~$ lsmod
Module                  Size  Used by
ath9k_htc              81920  0
ath9k_common           20480  1 ath9k_htc
ath9k_hw              487424  2 ath9k_htc,ath9k_common
ath                    32768  3 ath9k_htc,ath9k_hw,ath9k_common
mac80211              802816  1 ath9k_htc
cfg80211              737280  4 ath9k_htc,mac80211,ath,ath9k_common
rfkill                 28672  3 cfg80211
uhci_hcd               49152  0
ehci_pci               16384  0
ehci_hcd               94208  1 ehci_pci
ata_piix               36864  0
mptscsih               36864  1 mptspi
usbcore               290816  5 ath9k_htc,usbhid,ehci_hcd,uhci_hcd,ehci_pci
usb_common             16384  1 usbcore
...
```

Before unloading a driver, the module the driver is dependent on must be removed. Attempting to remove a module that has remaining dependencies:

```bash
kali@kali:~$ sudo rmmod ath
rmmod: ERROR: Module ath is in use by:  ath9k_htc ath9k_hw ath9k_common
```

Thus we can use **lsmod** as a guide to remove modules not needed by other drivers.

```bash
kali@kali:~$ sudo rmmod ath9k_htc ath9k_common ath9k_hw ath
```

{% hint style="info" %}
In the event you are experimenting with drivers, modifying them or compiling drivers, you can use insmod to manually load a module from a specific path; modprobe loads a module from the kernel modules directory. Example: `insmod rtl8812au.ko`.
{% endhint %}

### iwconfig and Other Utilities&#x20;

Deprecated utilities:

* _iwconfig_ manipulates the basic wireless parameters: change modes, set channels, and keys.
* _iwlist_ allows for the initiation of scanning, listing frequencies, bit rates, and encryption keys.
* _iwspy_ provides per-node link quality (not often implemented by drivers).
* _iwpriv_ allows for the manipulation of the Wireless Extensions specific to a driver.

Listening the channel numbers and corresponding frequencies our wireless interface is able to detect via **iwlist** followed by the **frequency** parameter:

```bash
kali@kali:~$ sudo iwlist wlan0 frequency
wlan0     14 channels in total; available frequencies :
          Channel 01 : 2.412 GHz
          Channel 02 : 2.417 GHz
          Channel 03 : 2.422 GHz
          Channel 04 : 2.427 GHz
          Channel 05 : 2.432 GHz
          Channel 06 : 2.437 GHz
          Channel 07 : 2.442 GHz
          Channel 08 : 2.447 GHz
          Channel 09 : 2.452 GHz
          Channel 10 : 2.457 GHz
          Channel 11 : 2.462 GHz
          Channel 12 : 2.467 GHz
          Channel 13 : 2.472 GHz
```

### The iw Utility

The **iw** utility with its variety of options is the only command needed for configuring a Wi-Fi device -- assuming the drivers have been loaded properly. Running **iw list** will provide us with lots of detailed information about the wireless devices and their capabilities:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo iw list
Wiphy phy0
...
Supported interface modes:
	 * IBSS
	 * managed
	 * AP
	 * AP/VLAN
	 * monitor
	 * mesh point
	 * P2P-client
	 * P2P-GO
	 * outside context of a BSS
Band 1:
  Capabilities: 0x116e
		HT20/HT40
		...
	...
	HT TX/RX MCS rate indexes supported: 0-7
	Bitrates (non-HT):
		* 1.0 Mbps
		* 2.0 Mbps (short preamble supported)
		* 5.5 Mbps (short preamble supported)
		* 11.0 Mbps (short preamble supported)
		* 6.0 Mbps
		* 9.0 Mbps
		* 12.0 Mbps
		* 18.0 Mbps
		* 24.0 Mbps
		* 36.0 Mbps
		* 48.0 Mbps
		* 54.0 Mbps
	Frequencies:
		* 2412 MHz [1] (20.0 dBm)
		* 2417 MHz [2] (20.0 dBm)
		* 2422 MHz [3] (20.0 dBm)
		* 2427 MHz [4] (20.0 dBm)
		* 2432 MHz [5] (20.0 dBm)
		* 2437 MHz [6] (20.0 dBm)
		* 2442 MHz [7] (20.0 dBm)
		* 2447 MHz [8] (20.0 dBm)
		* 2452 MHz [9] (20.0 dBm)
		* 2457 MHz [10] (20.0 dBm)
		* 2462 MHz [11] (20.0 dBm)
		* 2467 MHz [12] (20.0 dBm)
		* 2472 MHz [13] (20.0 dBm)
		* 2484 MHz [14] (disabled)
...
```
{% endcode %}

To get a list of wirless access points within range of our wireless card, use **iw** with the **dev wlan0** option, specifying our wireless interface. Grep for the information wanted:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo iw dev wlan0 scan | egrep "DS Parameter set|SSID:"
	SSID: wifu
	DS Parameter set: channel 3
	SSID: 6F36E6
	DS Parameter set: channel 11
```
{% endcode %}

Creating a new Virtual Interface (VIF) named wlan0mon in monitor mode:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo iw dev wlan0 interface add wlan0mon type monitor
```
{% endcode %}

Bringing the new VIF up with **ip**:

```bash
kali@kali:~$ sudo ip link set wlan0mon up
```

Inspecting our newly created monitor mode interface:

```bash
kali@kali:~$ sudo iw dev wlan0mon info
Interface wlan0mon
	ifindex 4
	wdev 0x1
	addr 0c:0c:ac:ab:a9:08
	type monitor
	wiphy 0
	channel 11 (2462 MHz), width: 20 MHz, center1: 2462 MHz
```

Verifying our card is in monitor mode:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo tcpdump -i wlan0mon
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on wlan0mon, link-type IEEE802_11_RADIO (802.11 plus radiotap header), capture size 262144 bytes
13:39:17.873700 2964927396us tsft 1.0 Mb/s 2412 MHz 11b -20dB signal antenna 1 [bit 14] Beacon (wifu) [1.0* 2.0* 5.5* 11.0* 9.0 18.0 36.0 54.0 Mbit] ESS CH: 3, PRIVACY[|802.11]
```
{% endcode %}

Deleting our VIF:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo iw dev wlan0mon interface del

kali@kali:~$ sudo iw dev wlan0mon info
command failed: No such device (-19)
```
{% endcode %}

_Central Regulatory Domain Agent_ (CRDA) helps radios stay compliant with wireless regulations. **iw reg** interacts with CRDA to query, and in some cases, change it.

Displaying the current regulatory domain:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo iw reg get
global
country 00: DFS-UNSET
	(2402 - 2472 @ 40), (6, 20), (N/A)
	(2457 - 2482 @ 20), (6, 20), (N/A), AUTO-BW, PASSIVE-SCAN
	(2474 - 2494 @ 20), (6, 20), (N/A), NO-OFDM, PASSIVE-SCAN
	(5170 - 5250 @ 80), (6, 20), (N/A), AUTO-BW, PASSIVE-SCAN
	(5250 - 5330 @ 80), (6, 20), (0 ms), DFS, AUTO-BW, PASSIVE-SCAN
	(5490 - 5730 @ 160), (6, 20), (0 ms), DFS, PASSIVE-SCAN
	(5735 - 5835 @ 80), (6, 20), (N/A), PASSIVE-SCAN
	(57240 - 63720 @ 2160), (N/A, 0), (N/A)
```
{% endcode %}

Using **iw reg set** is not permanent; to make sure it is always set at boot time, edit **/etc/defaults/crda.**

### The rfkill Utility

**rfkill** is used to enable/disable connected wireless devices. It can be used for Wi-Fi, Bluetooth, mobile broadband, WiMax, GPS, FM, NFC, and any other radio.

Listing all the enabled Wi-Fi and Bluetooth devices on the system:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo rfkill list
0: hci0: Bluetooth
	Soft blocked: no
	Hard blocked: no
1: phy0: Wireless LAN
	Soft blocked: no
	Hard blocked: no
```
{% endcode %}

"Soft blocked" refers to a block from rfkill, done in software. "Hard blocked" refers to a physical switch or BIOS parameter for hte device. rfkill can only change soft blocks.

Disabled a radio:

```bash
kali@kali:~$ sudo rfkill block 1
```

Confirming our change:

```bash
kali@kali:~$ sudo rfkill list 1
1: phy0: Wireless LAN
	Soft blocked: yes
	Hard blocked: no
```

Re-enabling the Wi-Fi device:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo rfkill unblock 1
```
{% endcode %}

Disabling all radios at the same time:

```bash
kali@kali:~$ sudo rfkill block all
```

## Wireless Stacks and Drivers

### The ieee80211 Wireless Subsystem

_Wireless Extension_ (WE) known as _wext_ is an extension to the Linux networking interface to deal with the specificity of Wi-Fi. It was implemented in three parts:

1. A set of user tools to control the drivers, with **iwconfig**, **iwlist**, **iwspy**, and **iwpriv**.
2. Implementing _wext_ in Wi-Fi drivers to answer actions triggered by wireless tools.
3. _wext_ required a middle-man to communicate the actions of the different user tools to the drivers and respond back, which is in the kernel.

### The mac80211 Wireless Framework

Included in all modern Linux kernels, mac80211 standardized most common functions.

<figure><img src="../../../.gitbook/assets/image (26) (1).png" alt=""><figcaption><p>mac80211, cfg80211 and nl80211 links</p></figcaption></figure>

_MAC Sublayer Management Entity_ (MLME) takes care of the following management operations:

* Authentication
* Deauthentication
* Association
* Disassociation
* Reassociation
* Beaconing
