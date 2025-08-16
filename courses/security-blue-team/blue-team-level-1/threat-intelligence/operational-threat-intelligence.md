# Operational Threat Intelligence

## Section Introduction

Operational intelligence involves collecting and analyzing indicators, precursors, and attack frameworks to provide actionable insights that disrupt malicious actors at different levels of the Pyramid of Pain.

***

## Precursors Explained

Precursors, or threat precursors, are early indicators that reveal flaws or vulnerabilities in a system, giving organizations a chance to prevent cyber attacks before they occur.

***

### Issues with Precursors

Precursors are difficult to identify because most attacks leave no detectable traces beforehand. This lack of visibility delays detection and weakens security posture. If organizations could consistently recognize precursors, they could prevent incidents by adjusting defenses proactively.

***

### Types of Precursors

#### Port Scanning, Operating System and Application Fingerprinting

Attackers and researchers use tools such as Nmap, Netcat, or Nessus to scan systems, discovering services, operating systems, and application versions. Relevant precursors include:

* Firewall or WAF logs flagging multiple port connections from one IP in a short time.
* System logs showing scanning activity.

#### Social Engineering and Reconnaissance

Attackers gather intelligence through deception and physical methods, such as dumpster diving or eavesdropping. Relevant precursors include:

* Employee reports of suspicious activity.
* CCTV evidence of unknown individuals searching bins or loitering near offices.
* Calls from unknown or spoofed numbers.
* Missing documents or office equipment.

#### OSINT Sources and Bulletin Boards

Public and underground platforms reveal potential threats, including social media, forums, blogs, and government or vendor reports. Relevant precursors include:

* Online threats directed at the organization.
* Public CVEs affecting the organization’s systems.
* Chatter on underground forums about zero-days or new malware.
* Government or vendor advisories on exploitation activity.

***

## Indicators of Compromise Explained

Indicators of compromise (IOCs) are key elements of threat intelligence, enabling defenders to share and detect malicious activity. They fuel automated defenses such as intrusion detection, endpoint detection and response (EDR), and firewalls, while also supporting analysts in identifying early or late signs of attacks.

***

### Example of IOCs

* **Email Addresses** – Used for malicious activity such as phishing, delivering malware, or social engineering.
* **IP Addresses** – Linked to malicious actions like scanning, hosting malware, or serving as C2 infrastructure. WHOIS lookups provide ownership, location, and host details.
* **Domain Names/URLs** – Associated with phishing, malware hosting, or other malicious content.
* **File Hashes/File Names** – Unique identifiers for malware or other malicious files (MD5, SHA256, SHA1) used to blacklist and detect threats with EDR tools.

***

### IOC Formats

#### STIX (Structured Threat Information eXpression)

Developed by MITRE and OASIS, STIX is a standardized language for sharing threat data. It extends beyond IOCs to include:

* Motivations
* Abilities
* Capabilities
* Response

Examples and documentation are available at [OASIS STIX Introduction](https://oasis-open.github.io/cti-documentation/stix/intro.html) and [MITRE STIX Samples](https://stix.mitre.org/language/version1.0.1/samples.html).

#### TAXII (Trusted Automated eXchange of Intelligence Information)

TAXII defines protocols for exchanging cyber threat intelligence, typically in STIX format. It enables sharing within trusted groups or through public threat streams managed on TAXII servers.

Further details are available in [this overview of STIX and TAXII](https://medium.com/sekoia-io-blog/stix-and-taxii-c1f596866384).

***

## MITRE ATT\&CK Framework

The [**MITRE Adversarial Tactics, Techniques, and Common Knowledge (ATT\&CK)**](https://attack.mitre.org/) framework is a widely used model of adversary behavior, introduced in 2013. It maps attacker tactics, techniques, and procedures (TTPs) across the phases of an attack lifecycle, providing detailed insights into how adversaries compromise systems and networks. ATT\&CK is heavily used for analyzing and defending against Advanced Persistent Threats (APTs).

With over 250 documented techniques, ATT\&CK offers a comprehensive resource for security teams to understand adversary behavior across multiple platforms.

### ATT\&CK for Threat Intelligence

ATT\&CK provides a standardized language to structure, compare, and apply threat intelligence. Key resources include:

* **Getting Started with ATT\&CK (Blog Post):** Outlines how to adopt ATT\&CK for threat intelligence at different maturity levels.
* **ATT\&CKing Your Adversaries (Presentation):** Explains how to operationalize threat intelligence into ATT\&CK-based behaviors and detections.
* **ATT\&CK Navigator:** A visualization tool for mapping techniques and comparing adversary behaviors across groups.
* **Adversary Emulation Resources:** Presentations and tutorials on using ATT\&CK to replicate adversary behavior for testing defenses.

### ATT\&CK vs. Cyber Kill Chain

Both ATT\&CK and the **Lockheed Martin Cyber Kill Chain** describe attack phases but differ in focus:

* **Cyber Kill Chain:** Defines attacks as a fixed, sequential series of steps (reconnaissance through actions on objectives).
* **MITRE ATT\&CK:** Breaks attacks into individual techniques and behaviors, mapped case by case, allowing more granular analysis and attribution.

Because ATT\&CK offers more specificity, many professionals prefer it or use a hybrid model combining both approaches.

***

## Lockheed Martin Cyber Kill Chain

The [**Cyber Kill Chain (CKC)**](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html) was developed by Lockheed Martin in 2011 as a defense model to identify and prevent cyberattacks, especially Advanced Persistent Threats (APTs). It describes seven stages of an attack, allowing defenders to detect and contain intrusions at multiple points.

### Kill Chain Stages

#### \[1] Reconnaissance

* **Attackers:** Gather intelligence through domain lookups, port scans, vulnerability scanning, and employee research on social media.
* **Defenders:** Watch for suspicious scans, OSINT collection attempts, or unusual contact with employees.

#### \[2] Weaponization

* **Attackers:** Create custom malware and embed it in malicious documents that connect to attacker-owned domains.
* **Defenders:** Limited visibility, but can prepare with antivirus, email security, and hardening measures.

#### \[3] Delivery

* **Attackers:** Send spear-phishing emails with malicious attachments or links.
* **Defenders:** Use email defenses like sandboxing to detect and block suspicious attachments.

#### \[4] Exploitation

* **Attackers:** Exploit vulnerabilities for elevated privileges and deeper access.
* **Defenders:** Apply vulnerability management and patching to reduce exposure.

#### \[5] Installation

* **Attackers:** Deploy backdoors and persistence mechanisms to maintain access.
* **Defenders:** Use endpoint detection and response (EDR) tools to identify and remove implants.

#### \[6] Command and Control

* **Attackers:** Establish remote communication channels for issuing commands.
* **Defenders:** Block outbound malicious connections and monitor for unusual traffic.

#### \[7] Actions on Objectives

* **Attackers:** Achieve final goals such as data theft, disruption, or espionage.
* **Defenders:** Detect and respond quickly to minimize damage.

### Is it Outdated?

While still influential, the Cyber Kill Chain has limitations. It does not account well for insider threats and its first two phases occur outside the defender’s visibility. To address these gaps, MITRE combined ATT\&CK with CKC to create the **Unified Kill Chain (UKC)**, which expands to 18 phases covering both external and internal activities. The CKC remains useful, but hybrid or extended models may better reflect modern attack scenarios.

***

## Pyramid of Pain

The **Pyramid of Pain** illustrates how defenders can disrupt malicious actors by denying them indicators of compromise (IOCs). The higher on the pyramid, the more difficult and costly it becomes for attackers to adapt, forcing significant changes in their operations.

### Layers Explained

#### Hash Values

Easiest for attackers to change. A single modification in a file alters its hash, bypassing hash-based detection. Provides high confidence but minimal pain to adversaries.

#### IP Addresses

Attackers can quickly rotate IPs using VPNs, TOR, or proxies. Blocking IPs can be useful but offers only short-term disruption.

#### Domain Names

Harder to replace than IPs due to registration and hosting requirements. Still, attackers can switch domains with some delay and minimal added cost.

#### Network/Host Artifacts

Artifacts such as registry keys, file paths, or process behaviors are more difficult to modify. Malware families often retain the same artifacts across campaigns, making these valuable detection points.

#### Tools

Attackers rely on specific tools for years. Disrupting these forces retooling or replacement, requiring time and expertise. Blocking tools can cause significant setbacks.

#### TTPs

Tactics, techniques, and procedures are behavioral patterns—such as spear phishing with PDFs. Forcing adversaries to change their methodology is the most disruptive measure, requiring them to redesign their operations.

### Why Use It?

Targeting indicators higher up the pyramid causes greater disruption and raises the cost for attackers. By defending against tools and TTPs, organizations make it harder for adversaries to succeed, strengthening resilience against evolving threats.

***
