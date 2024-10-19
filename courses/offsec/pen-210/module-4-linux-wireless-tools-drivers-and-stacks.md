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



### The rfkill Utility



## Wireless Stacks and Drivers

### The ieee80211 Wireless Subsystem



### The mac80211 Wireless Framework

