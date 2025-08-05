# Module 14: Determining Chipsets and Drivers

## Determining the Wireless Chipset

Methods to determine the wireless chipset:

* Take the FCC ID and enter it into fcc.gov and browsing internal photos of the devices.
* Plug in the adapter and run **airmon-ng** without parameters to display the driver and chipset.
* Use **lsmod** to view loaded modules.
* Look at **dmesg** before and after plugging in the device.
* Grep for terms like _ieee80211, mac80211, cfg80211, wireless,_ or _wifi_.
* Inspect output of **lsusb -vv**, **lspci**_**,**_ and **lspci -n**.

## Determining the Wireless Driver

Methods to determine the wireless driver:

* Look up the chipset on DeviWiki.
* Look it up on the Linux-wireless wiki.
* ..._google_.

In nearly all cases, the vendor driver is unusable for monitor mode. Only rare cases provide monitor mode. Examples of vendor drivers with monitor mode include r8187, rtl8812au, and the nexmon driver.

## Example: Alfa AWUS036AC

_Walkthrough of finding the Alfa AWUS036AC chipset and driver._

<figure><img src="../../../.gitbook/assets/image (49).png" alt=""><figcaption><p>AWUS0365AC in DeviWiki</p></figcaption></figure>

Running lsusb for Realtek 8812au:

{% code overflow="wrap" %}
```bash
kali@kali:~$ lsusb
Bus 003 Device 002: ID 0bda:8812 Realtek Semiconductor Corp. RTL8812AU 802.11a/b/g/n/ac 2T2R DB WLAN Adapter
...
```
{% endcode %}

Running airmon-ng for Realtek 8812au:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo airmon-ng

PHY     Interface       Driver          Chipset

phy0    wlan0           88XXau          Realtek Semiconductor Corp. RTL8812AU 802.11a/b/g/n/ac 2T2R DB WLAN Adapter
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (50).png" alt=""><figcaption><p>AWUS0365AC in Windows</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (51).png" alt=""><figcaption><p>Windows driver INF file excerpt</p></figcaption></figure>
