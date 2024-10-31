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

# Module 15: Kismet Essentials

## Installation

Installing Kismet:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo apt install kismet
Reading package lists... Done
Building dependency tree
Reading state information... Done
The following additional packages will be installed:
  kismet-capture-common kismet-capture-linux-bluetooth kismet-capture-linux-wifi kismet-capture-nrf-51822 kismet-capture-nrf-mousejack
  kismet-capture-nxp-kw41z kismet-capture-ti-cc-2531 kismet-capture-ti-cc-2540 kismet-core kismet-logtools libmicrohttpd12 libprotobuf22
  python3-kismetcapturefreaklabszigbee python3-kismetcapturertl433 python3-kismetcapturertladsb python3-kismetcapturertlamr python3-protobuf
Suggested packages:
  gpsd kismet-doc kismet-plugins festival
The following NEW packages will be installed:
  kismet kismet-capture-common kismet-capture-linux-bluetooth kismet-capture-linux-wifi kismet-capture-nrf-51822 kismet-capture-nrf-mousejack
  kismet-capture-nxp-kw41z kismet-capture-ti-cc-2531 kismet-capture-ti-cc-2540 kismet-core kismet-logtools libmicrohttpd12 libprotobuf22
  python3-kismetcapturefreaklabszigbee python3-kismetcapturertl433 python3-kismetcapturertladsb python3-kismetcapturertlamr python3-protobuf
0 upgraded, 18 newly installed, 0 to remove and 112 not upgraded.
Need to get 0 B/6,237 kB of archives.
After this operation, 29.1 MB of additional disk space will be used.
Do you want to continue? [Y/n] y
Preconfiguring packages ...
...
Setting up kismet (2020.04.R3-0kali1) ...
Processing triggers for man-db (2.9.3-2) ...
Processing triggers for kali-menu (2020.3.2) ...
Processing triggers for libc-bin (2.30-8) ...
```
{% endcode %}

## Configuration Files

Config files can be found in **/etc/kismet/**.

{% code overflow="wrap" %}
```bash
kali@kali:~$ ls -al /etc/kismet/
drwxr-xr-x   2 root root  4096 Sep 17 13:34 .
drwxr-xr-x 164 root root 12288 Sep 17 13:23 ..
-rw-r--r--   1 root root  4033 Sep 14 07:53 kismet_80211.conf
-rw-r--r--   1 root root  3723 Sep 14 07:53 kismet_alerts.conf
-rw-r--r--   1 root root  7768 Sep 14 07:53 kismet.conf
-rw-r--r--   1 root root  3486 Sep 14 07:53 kismet_filter.conf
-rw-r--r--   1 root root  2717 May 15 03:21 kismet_httpd.conf
-rw-r--r--   1 root root  5106 May 15 03:21 kismet_logging.conf
-rw-r--r--   1 root root  4977 Sep 14 07:53 kismet_memory.conf
-rw-r--r--   1 root root  4737 May 15 03:21 kismet_uav.conf
```
{% endcode %}

### Output Files

_Log files are in three formats: kismet, PcapPpi, and PcapNg. Kismet is the default and includes all the gathered data in a SQLite database. PcapPpi is a legacy Pcap format while PcapNg is the modern._

_We can override settings in multiple files by creating a **kismet\_site.conf** file in **/etc/kismet/**._

Converting PcapNg to Pcap:

```bash
kali@kali:~$ tshark -F pcap -r ${pcapng file} -w ${pcap file}
```

Creating an override to store data in a new directory and create log files in kismet and PcapNg formats:

{% code title="kismet_site.conf" %}
```bash
log_prefix=/var/log/kismet/
log_types=kismet,pcapng
```
{% endcode %}

### Data Sources

_Data sources include Wi-Fi, Bluetooth, Software Defined Radio (SDR), and nRF signals._

## Starting Kismet

Running kismet, disabling the ncurses library:

{% code overflow="wrap" %}
```bash
kali@kali:/etc/kismet$ cd ~
kali@kali:~$ sudo kismet -c wlan0 --no-ncurses
INFO: Including sub-config file: /etc/kismet/kismet_httpd.conf
INFO: Including sub-config file: /etc/kismet/kismet_memory.conf
INFO: Including sub-config file: /etc/kismet/kismet_alerts.conf
INFO: Including sub-config file: /etc/kismet/kismet_80211.conf
INFO: Including sub-config file: /etc/kismet/kismet_logging.conf
INFO: Including sub-config file: /etc/kismet/kismet_filter.conf
INFO: Including sub-config file: /etc/kismet/kismet_uav.conf
INFO: More than one override file included; Kismet will process them in the order they were defined.
INFO: Loading config override file '/etc/kismet/kismet_package.conf'
INFO: Optional sub-config file not present: /etc/kismet/kismet_package.conf
INFO: Loading config override file '/etc/kismet/kismet_site.conf'
INFO: Loading optional sub-config file: /etc/kismet/kismet_site.conf
...
KISMET - Point your browser to http://localhost:2501 (or the address of this system) for the Kismet UI
INFO: Starting Kismet web server...
INFO: Started http server on 0.0.0.0:2501
...
INFO: Found type 'linuxwifi' for 'wlan0'
INFO: wlan0 telling NetworkManager not to control interface 'wlan0': you may need to re-initialize this interface later or tell NetworkManager to control it again via 'nmcli'
INFO: wlan0 bringing down parent interface 'wlan0'
INFO: Data source 'wlan0' launched successfully
INFO: Detected new 802.11 Wi-Fi access point 5B:5C:79:0B:A8:F2
INFO: 802.11 Wi-Fi device 5B:5C:79:0B:A8:F2 advertising SSID 'Galain'
INFO: Detected new 802.11 Wi-Fi access point D5:89:1D:35:20:62
INFO: 802.11 Wi-Fi device D5:89:1D:35:20:62 advertising SSID 'Liosan'
INFO: Detected new 802.11 Wi-Fi device AC:D5:64:3B:A7:BB
INFO: Detected new 802.11 Wi-Fi access point 67:CB:81:07:A7:57
INFO: 802.11 Wi-Fi device 67:CB:81:07:A7:57 advertising SSID 'Emurlahn'
^C
*** KISMET IS SHUTTING DOWN ***
Shutting down plugins...
...
Kismet exiting.
kali@kali:~$
```
{% endcode %}

Listing the Kismet log directory:

{% code overflow="wrap" %}
```bash
kali@kali:~$ ls -al /var/log/kismet/
total 76
drwxr-xr-x  2 root root  4096 Sep 17 12:26 .
drwxr-xr-x 19 root root  4096 Sep 17 11:49 ..
-rw-r--r--  1 root root 61440 Sep 17 11:38 Kismet-20200917-15-38-41-1.kismet
-rw-r--r--  1 root root   744 Sep 17 11:38 Kismet-20200917-15-38-41-1.pcapng
```
{% endcode %}

Running Kismet on channels 4, 5, and 6:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo kismet -c wlan0:channels="4,5,6"
...
INFO: Data sources passed on the command line (via -c source), ignoring
      source= definitions in the Kismet config file.
INFO: Probing interface 'wlan0' to find datasource type
...
INFO: Found type 'linuxwifi' for 'wlan0:channels="4,5,6"'
...
INFO: Data source 'wlan0:channels="4,5,6"' launched successfully
INFO: Detected new 802.11 Wi-Fi device AC:D5:64:3B:A7:BB
^C
*** KISMET IS SHUTTING DOWN ***
Shutting down plugins...
...
Kismet exiting.
```
{% endcode %}

Starting Kismet as a daemon:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo kismet --daemonize
Silencing output and entering daemon mode...
INFO: Including sub-config file: /etc/kismet/kismet_httpd.conf
INFO: Including sub-config file: /etc/kismet/kismet_memory.conf
INFO: Including sub-config file: /etc/kismet/kismet_alerts.conf
INFO: Including sub-config file: /etc/kismet/kismet_80211.conf
INFO: Including sub-config file: /etc/kismet/kismet_logging.conf
INFO: Including sub-config file: /etc/kismet/kismet_filter.conf
INFO: Including sub-config file: /etc/kismet/kismet_uav.conf
INFO: More than one override file included; Kismet will process them in the order they were defined.
INFO: Loading config override file '/etc/kismet/kismet_package.conf'
INFO: Optional sub-config file not present: /etc/kismet/kismet_package.conf
INFO: Loading config override file '/etc/kismet/kismet_site.conf'
INFO: Loading optional sub-config file: /etc/kismet/kismet_site.conf
INFO: Setting server UUID 00000000-0000-0000-0000-4B49534D4554
INFO: Serving static content from '/usr/share/kismet/httpd/'
INFO: Serving static userdir content from '/root/.kismet/httpd/'
INFO: Loading saved HTTP sessions
INFO: Opened OUI file '/usr/share/kismet/kismet_manuf.txt
INFO: Indexing manufacturer db
```
{% endcode %}

## Web Interface

_Web Interface is available on localhost:2501 by default._

_OUI database can be found at **/usr/share/kismet/kismet\_manuf.txt**_

### Securing the Web Interface

Restricting access, changing from listening on all interfaces to only our loopback:

{% code title="kismet_site.conf" %}
```bash
log_prefix=/var/log/kismet/
log_types=kismet,pcapng
httpd_bind_address=127.0.0.1
```
{% endcode %}

## Remote Capture

To enable remote capture, we need to setup an SSH tunnel to the server or configure the remote instance of Kismet to listen on a specific network interface. Starting a Kismet server without a data source on Kali:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo kismet
...
INFO: Launching remote capture server on 127.0.0.1:3501
INFO: No data sources defined; Kismet will not capture anything until a
      source is added.
INFO: Opened kismetdb log file '/var/log//Kismet-20200917-15-18-55-1.kismet'
INFO: Saving packets to the Kismet database log.
INFO: Opened pcapng log file '/var/log/kismet//Kismet-20200917-15-18-55-1.pcapng'
ALERT: rootuser Kismet is running as root; this is less secure.  If you
       are running Kismet at boot via systemd, make sure to use `systemctl
       edit kismet.service` to change the user.  For more information, see
       the Kismet README for setting up Kismet with minimal privileges.
INFO: Starting Kismet web server...
INFO: Started http server on port 2501
```
{% endcode %}

Establishing a SSH tunnel with port 8000 forwarded:

{% code overflow="wrap" %}
```bash
kali@kaliremote:~$ ssh kali@192.168.62.192 -L 8000:localhost:3501
kali@192.168.62.192's password:
Linux kali 4.19.0-kali5-amd64 #1 SMP Debian 4.19.37-6kali1 (2019-07-22) x86_64

The programs included with the Kali GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Kali GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Sep 16 10:21:11 2020 from 192.168.62.219
kali@kali:~$
```
{% endcode %}

Starting a remote capture:

{% code overflow="wrap" %}
```bash
kali@kaliremote:~$ sudo kismet_cap_linux_wifi --connect 127.0.0.1:8000 --source=wlan0
INFO - Connected to '127.0.0.1:8000'...
INFO - 127.0.0.1:8000 starting capture...
```
{% endcode %}

## Log Files

Command line switches related to logging:

```bash
 -T, --log-types <types>      Override activated log types
 -p, --log-prefix <prefix>    Directory to store log files
 -n, --no-logging             Disable logging entirely
```

Using **sqlite3** to interact with the database:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo sqlite3 /var/log/kismet/Kismet-20200917-18-45-34-1.kismet
SQLite version 3.33.0 2020-08-14 13:23:32
Enter ".help" for usage hints.
sqlite> .tables
KISMET       data         devices      packets
alerts       datasources  messages     snapshots
```
{% endcode %}

Let's quickly review each table.

* The _KISMET_ table contains the database version and which version of Kismet created the log file.
* The _alerts_ table contains any alerts or WIDS issues.
* The _data_ table contains records that are not packet related, such as SDR data.
* The _datasources_ table contains information about the data sources used to capture data.
* The _devices_ table contains information about the devices Kismet was able to identify.
* The _messages_ table contains informational messages, such as those displayed in the console or web application.
* The _packets_ table contains the raw packets captured by Kismet. The table can contain multiple DLTs.
* The _snapshots_ table contains time-based information.

Schema for the devices table:

{% code overflow="wrap" %}
```bash
sqlite> .schema devices
CREATE TABLE devices (first_time INT, last_time INT, devkey TEXT, phyname TEXT, devmac TEXT, strongest_signal INT, min_lat REAL, min_lon REAL, max_lat REAL, max_lon REAL, avg_lat REAL, avg_lon REAL, bytes_data INT, type TEXT, device BLOB, UNIQUE(phyname, devmac) ON CONFLICT REPLACE);
```
{% endcode %}

Let's review the columns.

* The _first\_time_ and _last\_time_ columns contain when Kismet saw a device, the first time and last time, respectively.
* The _devkey_ column contains a unique identifier for each device.
* The _phyname_ column contains the physical layer for the device.
* The _devmac_ column contains a device's MAC address.
* The _strongest\_signal_ column contains the strongest recorded signal for the device.
* The _min\_lat_, _max\_lat_, and _avg\_lat_ columns contain the minimum, maximum, and average latitude values for the device.
* The _min\_lot_, _max\_lot_, and _avg\_lot_ contain the minimum, maximum, and average longitude values.
* The _bytes\_data_ column contains the number of bytes of data seen for the device.
* The _type_ column contains a human readable value for the physical layer device type.
* Finally, the _device_ column contains a JSON version of the device record, which can be quite lengthy.

Getting MAC addresses from the devices table:

{% code overflow="wrap" %}
```bash
sqlite> .headers on
sqlite> select type, devmac from devices;
type|devmac
Wi-Fi AP|67:CB:81:07:A7:57
Wi-Fi Device|E0:46:9A:29:49:F9
Wi-Fi Client|64:B0:A6:D9:73:52
Wi-Fi Device|AC:D5:64:3B:A7:BB
Wi-Fi AP|5B:5C:79:0B:A8:F2
Wi-Fi AP|D5:89:1D:35:20:62
Wi-Fi Client|00:0F:13:F6:A7:A6
```
{% endcode %}

sqlite one-liner:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo sqlite3 /var/log/kismet/Kismet-20200917-18-45-34-1.kismet "select type, devmac from devices;"
Wi-Fi AP|67:CB:81:07:A7:57
Wi-Fi Device|E0:46:9A:29:49:F9
Wi-Fi Client|64:B0:A6:D9:73:52
Wi-Fi Device|AC:D5:64:3B:A7:BB
Wi-Fi AP|5B:5C:79:0B:A8:F2
Wi-Fi AP|D5:89:1D:35:20:62
Wi-Fi Client|00:0F:13:F6:A7:A6
```
{% endcode %}

### Reading Log Files

Processing a PcapNg file with Kismet:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo kismet -c Documents/Network_Join_Nokia_Mobile.pcap:realtime=true
...
INFO: Pcapfile 'Documents/Network_Join_Nokia_Mobile.pcap' will replay in
      realtime
INFO: Data source 'Documents/Network_Join_Nokia_Mobile.pcap:realtime=true'
      launched successfully
INFO: Detected new 802.11 Wi-Fi access point 00:01:E3:41:BD:6E
INFO: 802.11 Wi-Fi device 00:01:E3:41:BD:6E advertising SSID 'martinet3'
INFO: Detected new 802.11 Wi-Fi device 00:01:E3:42:9E:2B
INFO: Detected new 802.11 Wi-Fi device 00:15:00:34:18:52
INFO: Detected new 802.11 Wi-Fi device 00:16:BC:3D:AA:57
ALERT: noclientmfp IEEE80211 network BSSID 00:01:E3:41:BD:6E client
       00:16:BC:3D:AA:57 does not support management frame protection
       (MFP) which may ease client disassocation or deauthentication
^C
*** KISMET IS SHUTTING DOWN ***
Shutting down plugins...
...
```
{% endcode %}

## Exporting Data

### Pcap

Checking datasources in a kismet file:

{% code overflow="wrap" %}
```bash
kali@kali:~$ kismetdb_to_pcap --in Kismet-20200917-18-45-34-1.kismet --list-datasources
Datasource #0 (5FE308BD-0000-0000-0000-26C65C9CEA7A wlan0 wlan0) 104 packets
   DLT 127: IEEE802_11_RADIO 802.11 plus radiotap header
```
{% endcode %}

Converting a kismet file to a PcapNg file:

{% code overflow="wrap" %}
```bash
kali@kali:~$ kismetdb_to_pcap --in Kismet-20200917-18-45-34-1.kismet --out sample.pcapng --verbose
* Preparing input database 'Kismet-20200917-18-45-34-1.kismet'...
* Found KismetDB version 6
* Collecting info about datasources...
* Opening pcapng file sample.pcapng
kali@kali:~$
```
{% endcode %}

### JSON

Using kismetdb\_dump\_devices to create a .json file:

{% code overflow="wrap" %}
```bash
kali@kali:~$ kismetdb_dump_devices --in /var/log/kismet/Kismet-20200917-17-45-17-1.kismet --out sample.json --skip-clean --verbose
* Preparing input database '/var/log/kismet/Kismet-20200917-17-45-17-1.kismet'...
* Found KismetDB version 6 6 devices
* 17% Processed 1 devices of 6
* 34% Processed 2 devices of 6
* 51% Processed 3 devices of 6
* 67% Processed 4 devices of 6
* 84% Processed 5 devices of 6
* 101% Processed 6 devices of 6
* Processed 6 devices
* Done!
```
{% endcode %}
