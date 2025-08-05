# Module 16: Manual Network Connections

## Connecting to an Access Point

wpa\_supplicant can either be used via a command line interface, with _wpa\_cli_, or with configuration files containing the settings of the network.

Simple wpa\_supplicant configuration for an open network:

{% code overflow="wrap" %}
```bash
network={
  ssid="hotel_wifi"
  scan_ssid=1
}
```
{% endcode %}

Simple wpa\_supplicant configuration for a WPA or WPA2-PSK network:

{% code overflow="wrap" %}
```bash
network={
  ssid="home_network"
  scan_ssid=1
  psk="correct battery horse staple"
  key_mgmt=WPA-PSK
}
```
{% endcode %}

wpa\_supplicant will automatically choose between TKIP and CCMP based on availability, but it is possible to force one or the other by adding _pairwise=CCMP_ or _pairwise=TKIP_ to the configuration if necessary.

{% hint style="info" %}
A quick and easy alternative is _wpa\_passphrase_. This tool can generate a configuration file for a basic WPA-PSK network. It requires at least one parameter, the ESSID. The second parameter, the passphrase, is optional, for security reasons. If the second parameter is omitted, it will prompt for the passphrase. This tool will output the content of a configuration file. We can redirect the output to a file with 'wpa\_passphrase home\_network > home\_network.conf'
{% endhint %}

Connecting to home\_network:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo wpa_supplicant -i wlan0 -c wifi-client.conf
Successfully initialized wpa_supplicant
wlan0: SME: Trying to authenticate with 00:ef:78:be:0d:98 (SSID='home_network' freq=2437 MHz)
wlan0: Trying to associate with 00:ef:78:be:0d:98 (SSID='home_network' freq=2437 MHz)
wlan0: Associated with 00:ef:78:be:0d:98
wlan0: CTRL-EVENT-SUBNET-STATUS-UPDATE status=0
wlan0: WPA: Key negotiation completed with 00:ef:78:be:0d:98 [PTK=CCMP GTK=CCMP]
wlan0: CTRL-EVENT-CONNECTED - Connection to 00:ef:78:be:0d:98 completed [id=0 id_str=]
...
```
{% endcode %}

With a connection confirmed, we can run wpa\_supplicant with **-B** to run it in the background.

Once connected, request a DHCP lease with _dhclient_:

```bash
kali@kali:~$ sudo dhclient wlan0
```

## Setting up an Access Point

### Internet Access

Listing support modes on all wireless interfaces:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo iw list
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
...
```
{% endcode %}

### Static IP on Access Point Wireless Interface

Setting the IP address for wlan0:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo ip link set wlan0 up

kali@kali:~$ sudo ip addr add 10.0.0.1/24 dev wlan0
```
{% endcode %}

### DHCP Server

dnsmasq configuration file, dnsmasq.conf:

{% code overflow="wrap" %}
```bash
# Main options
# http://www.thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html
domain-needed
bogus-priv
no-resolv
filterwin2k
expand-hosts
domain=localdomain
local=/localdomain/
# Only listen on this address. When specifying an 
# interface, it also listens on localhost.
# We don't want to interrupt any local resolution
listen-address=10.0.0.1

# DHCP range
dhcp-range=10.0.0.100,10.0.0.199,12h
dhcp-lease-max=100
# Router: wlan0
dhcp-option=option:router,10.0.0.1
dhcp-authoritative

# DNS: Primary and secondary Google DNS
server=8.8.8.8
server=8.8.4.4
```
{% endcode %}

Starting dnsmasq:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo dnsmasq --conf-file=dnsmasq.conf
```
{% endcode %}

Checking for dnsmasq in syslog:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo tail /var/log/syslog | grep dnsmasq
Nov 10 19:36:39 kali dnsmasq[158592]: started, version 2.82 cachesize 150
Nov 10 19:36:39 kali dnsmasq[158592]: compile time options: IPv6 GNU-getopt DBus no-UBus i18n IDN2 DHCP DHCPv6 no-Lua TFTP conntrack ipset auth DNSSEC loop-detect inotify dumpfile
Nov 10 19:36:39 kali dnsmasq-dhcp[158592]: DHCP, IP range 10.0.0.100 -- 10.0.0.199, lease time 12h
Nov 10 19:36:39 kali dnsmasq[158592]: using nameserver 8.8.4.4#53
Nov 10 19:36:39 kali dnsmasq[158592]: using nameserver 8.8.8.8#53
...
```
{% endcode %}

### Routing

Enabling IP forwarding:

{% code overflow="wrap" %}
```bash
kali@kali:~$ echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```
{% endcode %}

Installing nftables:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo apt install nftables
```
{% endcode %}

Doing masquerade with nftables:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo nft add table nat

kali@kali:~$ sudo nft 'add chain nat postrouting { type nat hook postrouting priority 100 ; }'

kali@kali:~$ sudo nft add rule ip nat postrouting oifname "eth0" ip daddr != 10.0.0.1/24 masquerade
```
{% endcode %}

### Access Point Mode

hostapd configuration, hostapd.conf:

{% code overflow="wrap" %}
```bash
interface=wlan0
ssid=BTTF
channel=11

# 802.11n
hw_mode=g
ieee80211n=1

# WPA2 PSK with CCMP
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=GreatScott
```
{% endcode %}

Starting hostapd with our AP configuration:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo hostapd hostapd.conf
Configuration file: hostapd.conf
Using interface wlan0 with hwaddr 00:af:8d:09:23:f9 and ssid "BTTF"
wlan0: interface state UNINITIALIZED->ENABLED
wlan0: AP-ENABLED
...
wlan0: STA 00:e4:89:02:7a:0f IEEE 802.11: authenticated
wlan0: STA 00:e4:89:02:7a:0f IEEE 802.11: associated (aid 1)
wlan0: AP-STA-CONNECTED 00:e4:89:02:7a:0f
wlan0: STA 00:e4:89:02:7a:0f RADIUS: starting accounting session 7F52FE0899A8A460
wlan0: STA 00:e4:89:02:7a:0f WPA: pairwise key handshake completed (RSN)
```
{% endcode %}

With hostapd started and clients connecting successfully, we can later run this in the background by using the **-B** switch.
