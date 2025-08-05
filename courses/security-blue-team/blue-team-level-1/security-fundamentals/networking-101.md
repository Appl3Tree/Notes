# Networking 101

## Section Introduction

This section introduces key networking concepts essential for cybersecurity work. It covers the **OSI model**, ports and services, and how networks are structured to enable communication between systems. While the content provides enough detail for the course, developing deeper networking knowledge is highly recommended for most security roles.

## Network Fundamentals

This section introduces key networking concepts for students without a strong networking background. It covers **TCP**, **UDP**, **ICMP**, and explains **IP** and **MAC addresses** to build a foundation for understanding network communication.

### TCP (Transmission Control Protocol)

TCP is a **connection-oriented protocol** that ensures reliable, ordered data delivery between two systems. It operates at the **transport layer** of the OSI model and uses the **three-way handshake** to establish connections:

1. Client sends `SYN` to start communication.
2. Server responds with `SYN-ACK` to acknowledge.
3. Client replies with `ACK` and data transfer begins.

TCP/IP forms the basis of most public and private networks.

### UDP (User Datagram Protocol)

UDP is a **connectionless protocol** designed for fast communication.

* Sends datagrams without establishing a session.
* Uses **ports** to direct data to applications.
* Faster than TCP but offers **no guarantee of delivery, order, or security**.
* Commonly used for streaming, VoIP, and gaming where speed matters more than reliability.

### ICMP (Internet Control Message Protocol)

ICMP is used for **diagnosing network connectivity** issues.

* Commonly used in `ping` tests to check if a device or site is reachable.
* Often found in routers and network devices to monitor traffic paths.

### IP Addresses

IP addresses uniquely identify devices on a network.

* **Private IP ranges** (used internally):
  * `192.168.0.0 – 192.168.255.255`
  * `172.16.0.0 – 172.31.255.255`
  * `10.0.0.0 – 10.255.255.255`
* **Public IPs** are assigned by ISPs for communication over the internet.
* **Static IPs** remain fixed; **dynamic IPs** change and are assigned by DHCP.

### MAC Addresses

A **MAC address** is a unique hardware identifier for network devices, embedded into the network card (Ethernet or Wi-Fi).

* Formatted as six two-digit hexadecimal values (e.g., `00:0D:83:B1:C0:8E`).
* Used for device-level communication within a network.
* Can be spoofed by attackers.

## The OSI Model

The **Open Systems Interconnection (OSI) model** is a standardized framework developed by the International Organization for Standardization (ISO) in 1984. It breaks down how data is transmitted and received across networks into **seven layers**, each with a specific function. These layers work together so systems, applications, and networks can communicate reliably.

A simple way to remember the layers:

* **Top to Bottom:** All People Seem To Need Data Processing (APSTNDP)
* **Bottom to Top:** Please Do Not Throw Sausage Pizza Away (PDNTSPA)

### The 7 Layers Explained

#### **Layer 7 – Application Layer**

* Interface where the user interacts with network services.
* Includes applications like web browsers, email clients, and file transfer tools.
* Common protocols: **HTTP**, **SMTP**.

#### **Layer 6 – Presentation Layer**

* Acts as a translator, ensuring data is formatted for the application.
* Handles **encryption, decryption, and encoding** so the data can be displayed correctly.

#### **Layer 5 – Session Layer**

* Manages **sessions** between systems, ensuring proper communication.
* Responsible for **opening, maintaining, and closing sessions** and controlling communication order.

#### **Layer 4 – Transport Layer**

* Ensures reliable **end-to-end data delivery**.
* Performs **packet assembly, fragmentation, error control, and retransmission** when needed.
* Protocols like **TCP** operate at this layer.

#### **Layer 3 – Network Layer**

* Routes data between networks, finding the **best path** for delivery.
* Responsible for **logical addressing** (e.g., IP addresses).

#### **Layer 2 – Data Link Layer**

* Handles **physical addressing** and **data framing** for transmission.
* Breaks data into **frames** for transfer and ensures delivery to the correct device on a local network.

#### **Layer 1 – Physical Layer**

* Deals with the **physical medium** (cables, fiber optics, network hardware).
* Defines the **topology** and electrical/optical standards for data transmission.

## Network Devices

In a network, various devices are used to enable communication between systems, enforce security, and manage data flow. While routers and firewalls are the most commonly known, other components such as switches, hubs, and bridges also play crucial roles. Most enterprise networks are segmented into smaller, manageable parts using these devices.

### Core Network Devices

#### **Router**

* Forwards data based on **IP addresses**.
* Directs traffic between **different networks**, such as between your home and the internet.
* Performs **Network Address Translation (NAT)** and connects LANs to WANs.

📌 _Analogy: Like a postal sorting facility that routes packages (data) to other cities (networks) based on the address._

***

#### **Hub**

* A **basic broadcast device** used in LANs.
* Forwards all incoming data to **all ports** regardless of destination.
* Creates a lot of **unnecessary traffic** and is **not secure**—attackers can easily capture traffic.

📌 _Analogy: Like shouting a message in a crowded room—everyone hears it, even if it’s only meant for one person._

***

#### **Switch**

* More intelligent than a hub; uses **MAC addresses** to forward data to the correct recipient.
* Reduces unnecessary traffic and increases security.
* Core component in most modern networks for **internal communication**.

📌 _Analogy: Like handing a letter directly to the recipient instead of announcing it to everyone._

***

#### **Bridge**

* Connects two separate **LAN segments**, combining them into one.
* Operates at **Layer 2 (Data Link Layer)** of the OSI model.
* Useful for **expanding networks** without routing between them.

📌 _Analogy: Like building a walkway between two separate buildings so people can move freely._

***

#### **Firewall**

* Enforces network security by allowing or denying traffic based on **configured rules**.
* Can be software or hardware.
* Used to **segment and protect** parts of the network from unauthorized access.
* Supports deep inspection of packets, VPNs, and more advanced threat protection in modern setups.

📌 _Analogy: Like a security guard checking ID badges before letting anyone through a building entrance._

## Network Tools

This section introduces essential command-line tools used in both troubleshooting and cybersecurity contexts. Examples highlight common usage in Linux, with notes on Windows equivalents where applicable.

***

### **Command Line Tools**

#### **IP / ipconfig**

* Displays **current network configuration** (IP address, gateway, DNS).
* Useful for diagnosing connectivity issues.\
  **Examples:**
* `ip a` – Show device IPs
* `ip r list` – Display routing table
* `ip link set dev [device] up|down` – Enable or disable network interface

***

#### **Traceroute / tracert**

* Traces the **path packets take** from source to destination.
* Identifies potential routing issues.\
  **Examples:**
* `traceroute example.com` – Basic trace
* `traceroute example.com -p [port]` – Trace with specific port

***

#### **Dig / nslookup**

* Queries **DNS records** for domains.
* Useful for IP lookups, mail server queries, or investigating suspicious domains.\
  **Examples:**
* `dig domain.com` – Query A record
* `dig domain.com MX` – Query mail records
* `dig domain.com ANY +nocomments` – Retrieve all records without extra data

***

#### **Netstat**

* Lists **network connections, listening ports, and statistics**.
* Can help identify **active connections to suspicious hosts**.\
  **Examples:**
* `netstat -a` – All active connections and listening ports
* `netstat -a -b` – Same, showing associated executables
* `netstat -s -p tcp -f` – TCP statistics with FQDNs

***

### **Nmap**

* Versatile **network discovery and port scanning tool**.
* Detects open ports, services, OS details, and network devices.
* Syntax: `nmap [Scan Type] [Options] {target}`

**Common usage:**

* `nmap -v -sT -sV scanme.nmap.org` – TCP Connect scan with service version detection
  * **PORT** – Open port number
  * **STATE** – Port status (open/filtered)
  * **SERVICE** – Service detected on that port

> Example: Port 80 (HTTP, Apache) open for web access; Port 22 (SSH) open for secure remote sessions.

{% hint style="warning" %}
_Only scan hosts you have permission to test. `scanme.nmap.org` is approved for practice._
{% endhint %}

## Protocols and Ports

This section introduces ports, their purpose in networking, and common protocols every cybersecurity professional should know.

***

### **What Are Ports and Services?**

* **Ports**: Communication endpoints used by software to identify specific processes or services.
* **Ranges**:
  * **Well-Known Ports**: `0–1023` (FTP, SSH, DNS, HTTPS)
  * **Registered Ports**: `1024–49151`
  * **Private/Ephemeral Ports**: `49152–65535` (often used as random source ports in client-server communication)

***

### **Common Ports and Protocols**

#### **File Transfer Protocol (FTP)**

* **Ports**: 20, 21 (TCP)
* Transfers files between systems.
* **Weakness**: Credentials and data sent in **cleartext**.

#### **Secure Shell (SSH)**

* **Port**: 22 (TCP)
* Secure, encrypted remote administration (e.g., server maintenance).

#### **Telnet**

* **Port**: 23 (TCP)
* Legacy remote access protocol. **Unencrypted**, insecure; replaced by SSH.

#### **Simple Mail Transfer Protocol (SMTP)**

* **Port**: 25 (TCP)
* Sends email between mail servers (retrieval done via POP or IMAP).

#### **Domain Name System (DNS)**

* **Ports**: 53 (TCP/UDP)
* Translates domain names (e.g., `google.com`) to IP addresses.

#### **Dynamic Host Configuration Protocol (DHCP)**

* **Ports**: 67, 68 (UDP)
* Automatically assigns IP addresses, subnet masks, and gateways to devices.

#### **Hypertext Transfer Protocol (HTTP)**

* **Port**: 80 (TCP)
* Transfers web content between client browsers and servers.
* **Unencrypted**—susceptible to sniffing.

#### **Hypertext Transfer Protocol Secure (HTTPS)**

* **Port**: 443 (TCP)
* Encrypted HTTP using **TLS/SSL** to secure data in transit.

#### **Syslog**

* **Port**: 514 (UDP)
* Collects and forwards system logs to a central server (often feeding into a SIEM).

#### **Remote Desktop Protocol (RDP)**

* **Port**: 3389 (TCP)
* Enables remote graphical desktop connections to Windows systems.

***

{% hint style="info" %}
Testing port knowledge can help reinforce recognition—online port quizzes are recommended for practice.
{% endhint %}
