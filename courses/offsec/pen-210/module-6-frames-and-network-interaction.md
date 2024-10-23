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

# Module 6: Frames and Network Interaction

## Packets vs. Frames

_Just discussing the difference between Protocol Data Units (PDUs)._

## 802.11 MAC Frames

### MAC Header

<figure><img src="../../../.gitbook/assets/image (14).png" alt=""><figcaption><p>802.11 MAC Header</p></figcaption></figure>

## Frame Types

### Management Frames

Management frames subtypes:

| Subtype | Field Description       |
| ------- | ----------------------- |
| 0       | Association Request     |
| 1       | Association Response    |
| 2       | Re-association Request  |
| 3       | Re-association Response |
| 4       | Probe Request           |
| 5       | Probe Response          |
| 6       | Measurement Pilot       |
| 7       | Reserved                |
| 8       | Beacon                  |
| 9       | ATIM                    |
| 10      | Disassociation          |
| 11      | Authentication          |
| 12      | Deauthentication        |
| 13      | Action                  |
| 14      | Action No ACK           |
| 15      | Reserved                |

<figure><img src="../../../.gitbook/assets/image (15).png" alt=""><figcaption><p>Beacon frame structure</p></figcaption></figure>

{% hint style="info" %}
Although SSID and ESSID are used interchangeably in Wi-Fi tools and AP configuration, there is a small difference. SSID is for single APs. ESSID is when multiple APs in an Extended Service Set (ESS) share the same SSID. The official name of the field in management frames is SSID.
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (18).png" alt=""><figcaption><p>Management frame IE structure</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (16).png" alt=""><figcaption><p>Authentication frame structure</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (17).png" alt=""><figcaption><p>Association request structure</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (19).png" alt=""><figcaption><p>Association response structure</p></figcaption></figure>

### Control Frames

Control frames subtypes:

| Subtype | Field Description |
| ------- | ----------------- |
| 0-6     | Reserved          |
| 7       | Control Wrapper   |
| 8       | Block ACK Request |
| 9       | Block ACK         |
| 10      | PS-Poll           |
| 11      | RTS               |
| 12      | CTS               |
| 13      | ACK               |
| 14      | CF End            |
| 15      | CF End + CF-ACK   |

<figure><img src="../../../.gitbook/assets/image (20).png" alt=""><figcaption><p>ACK Frame diagram</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (21).png" alt=""><figcaption><p>RTS/CTS communication sequence</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (22).png" alt=""><figcaption><p>RTS frame structure</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (23).png" alt=""><figcaption><p>CTS frame structure</p></figcaption></figure>

### Data Frames

Data frames subtypes:

| Subtype | Field Description              |
| ------- | ------------------------------ |
| 0       | Data                           |
| 1       | Data + CF ACK                  |
| 2       | Data + CF Poll                 |
| 3       | Data + CF ACK + CF Poll        |
| 4       | Null Function (No Data)        |
| 5       | CF ACK (No Data)               |
| 6       | CF Poll (No Data)              |
| 7       | CF ACK + CF Poll (No Data)     |
| 8       | QoS Data                       |
| 9       | QoS Data + CF ACK              |
| 10      | QoS Data + CF Poll             |
| 11      | QoS Data + CF ACK + CF Poll    |
| 12      | QoS Null (No Data)             |
| 13      | Reserved                       |
| 14      | QoS CF Poll (No Data)          |
| 15      | QoS CF ACK + CF Poll (No Data) |

## Interacting with Networks

<figure><img src="../../../.gitbook/assets/image (24).png" alt=""><figcaption><p>The stages in connecting to a network</p></figcaption></figure>

### Open Network

In _IEEE 802.11 Wireless Management > Fixed Parameters > Capabilities Information_, we can check the Privacy bit to see if the AP is encrypted.

### WEP

Same process as the Open Network however the _Privacy_ bit will show it is encrypted. The lack of WPA/WPA2 tags indicates WEP.

### EAPoL

_Extensible Authentication Protocol over LAN (EAPoL)_ frames are commonly used during the handshake when connecting to an AP with WPA, WPA2, WPA3, or OWE.

<figure><img src="../../../.gitbook/assets/image (25).png" alt=""><figcaption><p>EAPoL-Key frame structures</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (26).png" alt=""><figcaption><p>KDE structure</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption><p>RSNE structure</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (29).png" alt=""><figcaption><p>RSNE Pairwise Cipher Suite item</p></figcaption></figure>

#### WPA1

Advertises WPA1 PSK TKIP.

#### WPA2

Advertises WPA1 and WPA2, both with AES/CCMP and TKIP.

#### WPA3

Advertises with SAE in the RSN IE, and 802.11w which is mandatory for WPA3.

#### OWE

Advertises an RSN IE with OWE, and 802.11w which is also mandatory for OWE.

#### WPS

Advertises with a WPS beacon tag.

