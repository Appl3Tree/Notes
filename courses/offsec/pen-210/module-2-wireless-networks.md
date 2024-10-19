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

# Module 2: Wireless Networks

## Overview

* _Infrastructure_ is the term used to describe the organization and relationships between access points (APs) and clients.
* _Wireless Distribution System_ is a way to connect multiple APs without Ethernet cables between them in order to create a single network.
* _Ad-Hoc Networks_ are a type of network in which all devices are equal.
* _Mesh Networks_ are a type of network where all APs are equal, and don't have defined roles.
* _Wi-Fi Direct_ is also known as Wi-Fi Peer-to-Peer (P2P).
* _Monitor Mode_ is not an architecture, per se, but a mode used by wireless cards that will help us capture Wi-Fi frames and inject packets during a penetration test.

## Infrastructure

<figure><img src="../../../.gitbook/assets/image (17).png" alt=""><figcaption><p>DS, BSS, and ESS relationships</p></figcaption></figure>

{% hint style="info" %}
On Linux-type operating systems, acting as a station is usually called _Managed_ mode and acting as an AP is usually called _Master_ mode.
{% endhint %}

## Wireless Distribution Systems

WDS has two connectivity modes:

* _Wireless Bridging_: Only allows WDS APs to communicate with each other.
* _Wireless Repeating_: Allows both stations and APs to communicate with each other.

<figure><img src="../../../.gitbook/assets/image (18).png" alt=""><figcaption><p>Wireless Distribution System (WDS) diagram</p></figcaption></figure>

## Ad-Hoc Networks

<figure><img src="../../../.gitbook/assets/image (19).png" alt=""><figcaption><p>Ad-Hoc network diagram</p></figcaption></figure>

{% hint style="info" %}
Neither WDS nor Ad-Hoc (with a routing protocol) are ideal due to both the complexity of the setup and bugs in the implementations of the standard by the various vendors. The more repeaters that are added, the greater the complexity in setting up, as well as in managing and routing packets efficiently. In Ad-Hoc,[1](https://portal.offsec.com/courses/pen-210-9545/learning/wireless-networks-15805/ad-hoc-networks-15871/ad-hoc-networks-16030?category=in-progress#fn-local\_id\_95-1) bugs lead to random disconnection of certain nodes on the network. WDS is often limited to WEP or unencrypted networks, and WPA[2](https://portal.offsec.com/courses/pen-210-9545/learning/wireless-networks-15805/ad-hoc-networks-15871/ad-hoc-networks-16030?category=in-progress#fn-local\_id\_95-2) is tricky to get working.
{% endhint %}

### Ad-Hoc Demo

This is a deviation from a standard Ad-Hoc or IBSS mode. It is also referred to as _Pseudo-IBSS_ because it's a pre-standard, pre-IBSS mode with just data. There are no management frames (at all), and the BSSID is all zeros.&#x20;

## Mesh Networks

There are two peering modes available:

* _Mesh Peering Management (MPM)_: Unsecure peering. (Rogue stations may hijack connections)
* _Authenticated Mesh Peering Exchange (AMPE)_: Secure peering.

<figure><img src="../../../.gitbook/assets/image (20).png" alt=""><figcaption><p>Mesh network diagram</p></figcaption></figure>

* _Mesh Point (MP)_: Devices that establish a link between mesh devices. These can be either Mesh Portals, Mesh APs, or even other Mesh Points.
* _Mesh AP (MAP)_: Devices that have the functionality of a Mesh Point and an Access Point.
* _Mesh Portal (MPP)_: Devices that provide a link between the wired network and the wireless network.

## Wi-Fi Direct

Wi-Fi Direct is also called Wi-Fi P2P. It is not an 802.11 standard or an amendment, but a technical specification from the Wi-Fi alliance. Devices offering a service act as a software access point with WPS-style connections using WPA2 encryption. It must also allow service discovery.

## Monitor Mode

Monitor mode is essential for wireless penetration testing as it enables the capture of raw 802.11 frames and allows packet injection.[1](https://portal.offsec.com/courses/pen-210-9545/learning/wireless-networks-15805/wi-fi-direct-15867/wi-fi-direct-16018?category=in-progress#fn-local\_id\_99-1) The majority of the tools used to test Wi-Fi networks require our wireless interface to be in monitor mode.
