# Preparation Phase

## Section Introduction, Preparation

This section introduces how organizations prepare for incident response by building teams, establishing policies, and implementing preventive security controls.

***

## Preparation: Incident Response Plan

An incident response plan (IRP) ensures security incidents are handled efficiently and consistently. A well-documented plan reduces confusion, saves time, and supports clear decision-making. It must be continually updated and supported with regular training so staff can carry out their responsibilities effectively.

IRPs are usually divided into six stages: Preparation, Identification, Containment, Eradication, Recovery, and Lessons Learned.

***

### Preparation

This stage demands the greatest focus, both in planning and ongoing readiness. Key elements include:

* Creating incident-specific response plans and testing them through simulated scenarios to build team experience.
* Ensuring all resources are ready, such as laptops, forensic equipment, approved software, and staff availability to pause regular duties during incidents.
* Training and evaluating team members continuously. Security analysts may collect incident data, forensic analysts may preserve digital evidence, and communications staff may prepare stakeholder notifications.

***

### Identification

This stage defines how incidents are recognized and reported. Documentation should include:

* Time of occurrence.
* Who discovered the incident.
* Method of detection.
* Affected systems or business units.
* Impact on business operations.
* Scope of the incident, including entry points and damage.

To prioritize effectively, incidents may be categorized by:

* **Criticality level** – how urgently a response is required.
* **Impact level** – how long operations will be affected.

***

### Containment

Containment prevents further spread and disruption. Actions may include disconnecting affected devices from networks or substituting them with backups.

This phase must balance containment with evidence preservation, particularly from volatile memory. Clear guidelines should exist for both short-term and long-term containment actions. Reliable backups allow affected systems to be removed without halting business operations.

***

### Eradication

With the incident contained, responders investigate root causes using tools such as packet captures, SIEM logs, and the [MITRE ATT\&CK](https://attack.mitre.org/) framework.

Tasks include:

* Removing malware and malicious artifacts.
* Reversing unauthorized changes.
* Eliminating persistence mechanisms.
* Hardening systems and applying patches.
* Updating automated defenses such as NIPS and HIPS with new indicators of compromise.

Run-books should provide step-by-step actions for different incident types to accelerate remediation.

***

### Recovery

This stage focuses on restoring normal operations. Cleaned and hardened systems are safely returned to production after validation.

Temporary backups may host services to minimize downtime. For example, a compromised website server could be replaced with a backup until the original is secure and ready to resume operation.

***

### Lessons Learned

After response efforts conclude, stakeholders should hold a review meeting to assess the incident. Discussion should cover:

* What occurred.
* What was successful.
* What could be improved.

The findings guide updates to documentation, procedures, and resource allocation. Lessons drawn from real and simulated events strengthen readiness for future incidents.

***

## Preparation: Incident Response Teams

Incident response teams are responsible for managing security incidents effectively. They ensure continuity, reduce costs, and minimize business impact by bringing together the right skills and resources.

***

### Why do we Need Them?

A dedicated team allows organizations to respond quickly and limit damage. Larger companies often employ full-time staff focused on preparation, testing, and response, while smaller organizations may assign incident response duties to staff who also hold other roles.

***

### Incident Response Team Members

Incident response teams draw members from multiple disciplines, not just cybersecurity.

#### Incident Commander

The Incident Commander, typically an Incident Response Manager, leads and coordinates all efforts. They maintain communication with departments, update leadership, and act as the central point of contact.

#### Security Analysts

These analysts investigate alerts from systems such as IDPS and SIEM. They identify affected systems, analyze activity, and provide technical insight into ongoing incidents.

#### Forensic Analysts

Specialists in digital forensics and incident response (DFIR) collect and preserve digital evidence for investigations and potential legal proceedings.

#### Threat Intelligence Analysts

They provide context by identifying likely threat actors, using indicators of compromise to perform exposure checks, and sharing intelligence with external organizations to prepare against similar attacks.

***

#### Management / C-Suite

Executives such as the CISO, COO, and CTO ensure resources are available for effective prevention and response.

#### Human Resources (HR)

When employees are involved in incidents, HR manages disciplinary actions or legal proceedings.

#### Public Relations (PR)

PR handles external communications, including breach notifications and updates to customers, employees, or stakeholders, ensuring compliance with disclosure laws.

#### Legal

Legal staff ensure all actions comply with regulations. They support PR, HR, and forensic efforts, including requirements for notifying affected individuals and maintaining the integrity of digital evidence.

***

## Preparation: Asset Inventory and Risk Assessments

To defend systems effectively, organizations must maintain visibility of their assets and understand the risks associated with them. Asset inventories ensure no device is overlooked, while risk assessments determine which systems require the greatest protection and prioritization during incidents.

***

### Asset Inventory

“You can’t protect what you can’t see” highlights the importance of maintaining a centralized, updated record of all IT assets. This is often referred to as a Computer Management Database (CMDB). Typical entries include:

* Desktops and laptops
* Servers
* Printers
* Internet-of-Things (IoT) devices such as alarms, TVs, heaters, or vending machines
* Network devices such as firewalls, switches, routers, and load balancers
* Mobile devices including phones and tablets

Each entry should include details such as the system owner, operating system version, installed software, and assigned IP addresses. This enables IT teams to manage updates, monitor systems, and support troubleshooting.

For security operations, asset inventories support:

* Identifying outdated operating systems without requiring vulnerability scanners.
* Linking affected IP addresses to responsible owners during incidents.
* Understanding the purpose of suspicious systems, including whether they store confidential or non-confidential data.

***

### Risk Assessments

Risk assessments highlight the systems most critical to business operations, ensuring they receive appropriate protection and prioritization. If multiple incidents occur simultaneously, risk assessments provide clarity on where to focus resources.

Key considerations include balancing protection measures against actual risk. Overspending on non-critical or isolated systems wastes resources, while critical or exposed assets demand greater investment.

Risk can be addressed in four ways:

* **Transfer** – shift risk to a third party, such as by purchasing insurance.
* **Accept** – acknowledge the risk without action if the potential impact is minimal.
* **Mitigate** – apply security and operational controls to reduce exposure.
* **Avoid** – remove the risk entirely, such as by decommissioning a vulnerable system.

Business Impact Plans and Business Continuity Plans can guide risk assessments by identifying systems essential to operations. More detail on how cybersecurity risk assessments are conducted is available from [IT Governance UK](https://www.itgovernance.co.uk/cyber-security-risk-assessments).

***

## Prevention: DMZ

DMZs (demilitarized zones) are security controls that support the principle of defense-in-depth, adding multiple layers of protection to slow attackers and provide defenders with opportunities to detect and respond.

***

### What is a DMZ?

A DMZ is a physical or logical subnet separating an internal LAN from untrusted networks such as the internet. Systems in the DMZ are directly accessible from outside, but the LAN remains isolated. This segmentation limits an attacker’s ability to reach internal systems directly.

DMZs are commonly used to:

* Protect sensitive internal systems and resources.
* Isolate and separate potential targets from core networks.
* Control and restrict external access to organizational services.

***

### DMZ Systems

Public-facing services are placed in a DMZ to reduce exposure of internal networks. Common examples include:

* Web servers
* Proxy servers
* Email servers
* DNS servers
* FTP servers
* VoIP servers

***

### Architecture

There are two primary ways to design a DMZ: a single firewall or dual firewalls.

#### DMZ Architecture – Single Firewall

A single firewall with at least three interfaces can segment traffic:

* One interface connects to the external network (ISP).
* One connects to the internal private network.
* One connects to the DMZ hosting public-facing services.

#### DMZ Architecture – Dual Firewall

A more secure design uses two firewalls:

* The **frontend firewall** allows only traffic destined for the DMZ.
* The **backend firewall** controls traffic moving from the DMZ into the internal network.

Using firewalls from different vendors increases resilience by reducing the likelihood of shared vulnerabilities, though this approach adds cost and complexity.

***

### Benefits of a DMZ

DMZs provide security and operational benefits:

* **Access control** – External users can reach public-facing services without direct access to the private network. A proxy server in the DMZ may also centralize employee internet traffic for monitoring.
* **Prevention of reconnaissance** – Attackers who compromise a DMZ system cannot easily move into the internal network due to the firewall barrier, limiting both internal and external reconnaissance.
* **Protection against IP spoofing** – A DMZ can delay spoofed traffic while other systems validate IP legitimacy, reducing the risk of impersonation-based attacks.

***

## Prevention: Network Defenses

Network defenses add layers of protection to prevent incidents or detect them early. Key controls include intrusion detection and prevention, firewalls, event monitoring, network access control, and web proxies.

***

### Network Intrusion Detection

A **Network Intrusion Detection System (NIDS)** monitors traffic to detect suspicious activity and generate alerts. Deployment options include:

* **Inline** – positioned directly in the traffic path, acting as a NIPS with reactive blocking capabilities. Risk: if the device fails, all traffic is disrupted.
* **Network tap** – connected to a physical line, copying network traffic for analysis.
* **Passive (SPAN port)** – connected to a switch’s SPAN port to mirror all traffic for monitoring.

NIDS tools include:

* [Snort](https://www.snort.org/) – open-source, widely used, with strong community rule sets.
* [Suricata](https://suricata.io/) – open-source, with deep packet inspection at the application layer.
* [Zeek](https://zeek.org/) – formerly Bro, providing intrusion detection and advanced traffic analysis.

***

### Network Intrusion Prevention

A **Network Intrusion Prevention System (NIPS)** takes automatic action in response to detected threats. For example, it may block communications from a system performing internal scans.

Snort, Suricata, and Zeek all support NIDS and NIPS functionality.

***

### Firewalls

Firewalls restrict network traffic to create secure zones. Common types include:

#### Traditional Firewalls

Rule-based controls allow or block traffic by source/destination IP, port, or protocol. These can be built using dedicated hardware and open-source software such as [pfSense](https://www.pfsense.org/). pfSense is widely used for hands-on practice with firewall rule writing and configuration. More details on tuning rules are available from [eSecurity Planet](https://www.esecurityplanet.com/network-security/finetune-and-optimize-firewall-rules.html).

#### Next-Generation Firewalls (NGFWs)

NGFWs extend inspection to the application layer, enabling fine-grained control. For example, they can allow Skype VoIP calls while blocking file transfers. They are costlier but offer stronger protection.

#### Web Application Firewalls (WAFs)

WAFs act as proxy servers between users and applications, filtering requests before reaching the application server. They shield applications from reconnaissance, scanning, and direct attacks but may reduce performance or lack support for certain applications.

***

### Event Monitoring

Logs from network devices can be forwarded to a SIEM for centralized monitoring.

* **Web proxy logs** – record visited websites, enabling alerts for malicious or inappropriate domains.
* **Perimeter firewall logs** – capture scanning or DDoS attempts, which can trigger alerts for security analysts.

***

### Network Access Control

NAC ensures only compliant devices connect to the network.

* **Pre-admission** – enforces requirements such as patch levels and anti-virus before granting access. Commonly applied in BYOD or guest scenarios.
* **Post-admission** – controls access after connection, using role-based access control to limit resource availability.

***

### Web Proxy

A **web proxy** mediates requests between users and external resources, blocking or filtering traffic. Proxies can:

* Reject requests to malicious or unauthorized sites.
* Apply preemptive blocks against phishing campaigns by denying access to identified malicious URLs.

Example: If a user receives a phishing email with a malicious link to _BensGardeningSupplies.xyz_, the proxy can block the request before it reaches the site, protecting the user and the organization.

***

## Prevention: Email Defenses

Email defenses protect organizations against phishing, spoofing, malicious URLs, and attachments. Controls range from DNS-based authentication to spam filtering, sandboxing, and employee training.

***

### SPF, DKIM, DMARC

Email authentication records strengthen domain security:

* **Sender Policy Framework (SPF)** – DNS TXT record specifying which servers are authorized to send emails for a domain. Prevents attackers from spoofing the domain.
* **Domain Keys Identified Mail (DKIM)** – uses cryptographic signatures. The sending server signs emails with a private key, and recipients verify integrity with the public key in DNS. Ensures the email has not been altered in transit.
* **Domain-based Message Authentication, Reporting, and Conformance (DMARC)** – builds on SPF and DKIM. Domain owners define policies for failed checks:
  * **None** – take no action.
  * **Quarantine** – mark or hold the email.
  * **Reject** – block delivery.

***

### Marking External Emails

Marking external messages reduces the likelihood of employees mistaking them for internal communications. Systems like Microsoft Exchange or Office 365 can:

* Append subject lines with tags such as `[EXTERNAL]` or `[EXT]`.
* Add visible warnings in the email body (often in bright colors) to alert recipients that the message originated outside the organization.

***

### Spam Filters

Spam filters block phishing, malicious attachments, and unwanted content before reaching users. Three common types include:

* **Gateway spam filters** – deployed on-premises, e.g., Barracuda Email Security Gateway.
* **Hosted spam filters** – cloud-based, faster to update, e.g., SpamTitan.
* **Desktop spam filters** – installed on endpoints, often used in small office/home office setups, though less reliable and sometimes bundled with freeware.

***

### Data Loss Prevention (DLP)

DLP solutions monitor outgoing email to prevent sensitive data leakage. They can:

* Detect keywords such as “confidential” or “proprietary.”
* Flag, block, or alert on emails containing sensitive attachments or text.
* Provide visibility into both accidental and intentional data leaks.

***

### Sandboxing

Sandboxing executes email attachments in a controlled virtual environment. Behavior such as downloading files, modifying processes, or contacting malicious domains flags attachments as malicious. If unsafe, the email is blocked before reaching the user.

***

### Attachment Restrictions

Blocking certain file types reduces risk without preventing legitimate business operations. Common high-risk formats include:

* `.exe` – executable files
* `.vbs` – Visual Basic scripts
* `.js` – JavaScript files
* `.iso` – disk images
* `.bat` – batch files
* `.ps` / `.ps1` – PowerShell scripts
* `.htm` / `.html` – HTML documents

Organizations should balance security with usability, allowing necessary file types while restricting risky ones.

***

### Security Awareness Training

Employees play a crucial role in email defense. Training should:

* Reinforce company security policies.
* Teach how to recognize phishing attempts.
* Provide clear steps for reporting suspicious emails.

Regular phishing simulations measure effectiveness, tracking reported vs. clicked attempts. Employees who fall for simulations should receive additional targeted training.

***

## Prevention: Physical Defenses

Physical security is an essential complement to cybersecurity. If attackers gain physical access to systems, they can steal data, install malicious devices, or disable equipment. Physical defenses include deterrents, access controls, and monitoring systems.

***

### Deterrents

Deterrents discourage attackers from attempting entry by signaling risk or increasing perceived difficulty:

* **Warning signs** – Notices such as “DO NOT ENTER” or “You Are Trespassing” inform individuals that further actions may be illegal.
* **Fences** – Chain-link fences, often with barbed or razor wire, slow intruders and create barriers.
* **Guard dogs** – Trained dogs deter intruders and may help detain them until security personnel respond.
* **Security guards** – Human presence provides strong deterrence, particularly when personnel are armed.
* **Security lighting** – Eliminates dark areas where attackers might hide, improving visibility for guards and CCTV.

***

### Access Controls

Access controls restrict who can enter sensitive areas:

* **Mantraps** – Small rooms with two doors; individuals are verified before being granted access to the secure area.
* **Turnstiles/gates** – Require ID cards or passes to permit entry, commonly used in office buildings.
* **Electronic doors** – Role-based restrictions limit access to areas such as server rooms, reducing exposure and aiding accountability.
* **Security guards** – Can verify IDs and manually authorize entry when needed.

***

### Monitoring Controls

Monitoring controls provide visibility and detection of intrusions:

* **CCTV** – Closed-circuit systems enable live monitoring and recording across multiple locations.
* **Security guards** – Trained staff are required to operate, maintain, and respond to monitoring systems.
* **Intrusion detection systems** – Trigger alerts or alarms using thermal, sound, or motion detection sensors.

***

## Prevention: Human Defenses

Human behavior is often the weakest link in security. Controls such as training, policies, incentives, simulations, and anonymous reporting help employees stay vigilant without disrupting business operations.

***

### Security Awareness Training

Employees should receive mandatory training during onboarding and annually thereafter. Training covers:

* How to recognize phishing emails.
* Applicable security policies.
* Safe use of social media (e.g., never post work badges).

Annual refreshers reinforce the role employees play in protecting the organization. Many compliance frameworks mandate specific training intervals.

***

### Security Policies

Policies define acceptable behavior when using company resources. These are typically outlined in an **Acceptable Use Policy (AUP)**, which employees sign during onboarding.

Examples of AUP restrictions include:

* Blocking access to prohibited sites (adult content, gambling, illegal goods).
* Preventing downloads of unauthorized software.
* Restricting removal of company devices without approval.
* Prohibiting password sharing.

Policies should clearly state consequences for violations. Security teams often reference AUP sections when addressing breaches, such as sending template warnings to employees caught visiting restricted websites. Example AUP templates are available from [Get Safe Online](https://www.getsafeonline.org/).

***

### Incentives

Organizations may designate “security champions” — employees who identify risks such as phishing emails, suspicious activity, or unpatched systems. Rewards can include recognition, thank-you messages, vouchers, or small prizes. Positive reinforcement helps build a security-conscious culture.

***

### Phishing Simulations

Simulated phishing campaigns, run quarterly, test employee readiness. These exercises:

* Provide harmless phishing emails with non-malicious links.
* Measure who reports vs. who clicks links.
* Identify repeat offenders for additional training.
* Allow tailored campaigns by department, including C-suite targets.

Popular phishing simulation platforms include:

* [Sophos Phish Threat](https://www.sophos.com/en-us/products/phish-threat.aspx)
* [GoPhish](https://getgophish.com/) (open source)
* [Trend Micro Phish Insight](https://phishinsight.trendmicro.com/en/simulator)
* [PhishingBox](https://www.phishingbox.com/)

***

### Whistleblowing

Organizations should provide anonymous channels for employees to report suspicious or malicious behavior. Anonymity encourages reporting and helps security teams identify insider threats early, reducing risk before damage occurs.

***
