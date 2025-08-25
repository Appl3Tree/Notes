# Introduction to Incident Response

## Section Introduction

This section introduces incident response practices based on the [NIST SP 800-61r2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final) standard, with references to frameworks such as the Cyber Kill Chain and MITRE ATT\&CK.

***

## What is Incident Response?

Incident response is the structured methodology organizations use to manage and respond to cyberattacks. Security events are routine and handled by analysts in a Security Operations Center (SOC), while true security incidents require specialized responders. Once an attack succeeds, professionals must analyze, contain, and eradicate the threat to restore operations quickly and minimize business impact.

The incident response lifecycle also emphasizes preparation through the deployment of security controls to reduce the chance and severity of attacks. Incident response is reactive by nature and complements disaster recovery efforts. An organized, well-resourced response can significantly reduce downtime and costs, while documentation and updated run-books help strengthen defenses against future threats.

Large organizations often establish a Computer Security Incident Response Team (CSIRT). Beyond security experts, this team may include IT staff, HR, communications, legal representatives, and executive leadership to ensure a coordinated and effective response.

***

## Why is Incident Response Needed?

Incident response reduces the impact of successful attacks, ensuring business operations remain as uninterrupted as possible. Since no organization can fully prevent incidents, the focus shifts to minimizing consequences such as data breaches, malware infections, or credential leaks.

Cyberattacks can damage customer trust, cause financial losses, affect stock prices, and trigger legal or regulatory penalties. Fines under the [General Data Protection Regulation (GDPR)](https://gdpr-info.eu/) and similar legislation have reached millions, with notable cases including:

* Google – €50 million (France, 2019)
* H\&M – €35.3 million (Germany, 2020)
* TIM (Telecom Italia) – €27.8 million (Italy, 2020)
* Austrian Post – €18 million (Austria, 2019)
* Marriott International – £18.4 million (UK, 2020)
* British Airways – £20 million (UK, 2020)
* Deutsche Wohnen SE – €14.5 million (Germany, 2019)
* Eni Gas e Luce – €11.5 million (Italy, 2020)
* 1&1 Telecom GmbH – €9.55 million (Germany, 2019)
* Vodafone Spain – €8.15 million (Spain, 2021)

For smaller organizations, such penalties can be devastating, even forcing closure or restricting operations. Incident response goes beyond data breach handling, covering scenarios such as leaked employee credentials, database exfiltration, ransomware, stolen laptops, website defacement, or insider data theft.

Documented response plans enable rapid containment and recovery, lowering business risk. Ultimately, if maintaining an incident response team costs less than regulatory fines, the organization saves money.

***

## Security Events vs Security Incidents

Security events and security incidents differ in scale and consequence. All incidents originate as events, but not all events escalate into incidents. Events represent potential issues, while incidents are confirmed cases of harm or disruption.

***

### Security Events

A security event is any occurrence with possible security implications, even if no harm is confirmed. Common examples include:

* Spam emails that may contain links to malicious sites or malware.
* Vulnerability scans performed by attackers to identify weaknesses.
* Reconnaissance activity that maps organizational systems for later exploitation.
* Explained anomalies such as network disruptions caused by misconfigurations.
* Employees downloading software from the internet to company devices, which risks bundled malware.
* Brute-force attempts on login portals before access is gained.

Events occur constantly, often handled automatically by security controls or logged for monitoring.

***

### Security Incidents

A security incident is an event that results in actual harm to the organization. Examples include:

* A spam email leading to ransomware execution and encrypted files.
* A vulnerability scan followed by exploitation and data exfiltration.
* An unexplained anomaly where the cause is unknown and may indicate malicious activity.
* Downloaded software installing malware that sends files to attackers.
* A brute-force attack that successfully grants unauthorized access to a system or database.

Incidents cause disruption, data loss, or compromise, requiring focused investigation and response.

***

### Events vs Incidents

Security events are usually handled by SOC analysts, while incidents often demand incident responders with advanced expertise. If the threat level is high, an internal or external Computer Security Incident Response Team (CSIRT) may be engaged.

Not every alert from a SIEM or IDS signals an incident. Many are events, such as external scanning activity, or even false positives. Each alert must be evaluated with context and expertise to determine whether it represents an event or a true incident.

***

## Incident Response Lifecycle

An Incident Response Plan (IRP) defines how organizations handle security incidents, with the lifecycle commonly divided into four ongoing phases. Each phase strengthens defenses and helps prevent recurrence.

***

### Preparation

Preparation ensures that teams, resources, and documentation are ready before an incident occurs. Effective preparation both equips the organization to respond and actively reduces attack likelihood.

Activities supporting readiness include:

* Maintaining contact information for stakeholders.
* Establishing a central “war room” for coordination.
* Documenting procedures and system baselines.
* Equipping responders with forensic toolkits.

Prevention-focused activities include:

* Conducting regular risk assessments.
* Deploying secure client and server configurations.
* Running user awareness and training programs.

Though no preparation is perfect, it provides the first line of defense against potentially severe attacks.

***

### Detection and Analysis

This phase combines detection and analysis.

Detection relies on security tools such as intrusion detection/prevention systems, antivirus and antimalware software, and log monitoring. Alerts from these tools notify the Computer Security Incident Response Team (CSIRT) or internal security staff of potential issues.

Analysis is often complex and involves identifying the attack vector and tracking movement through the network. Useful resources include:

* Network baselines and profiles.
* Knowledge bases of past incidents.
* Policies for log retention and review.

During analysis, responders must:

* Document findings thoroughly.
* Prioritize actions for containment and response.
* Follow the organization’s communication plan, ensuring managers, HR, legal, and leadership are informed. External parties or the public may be notified depending on severity.

***

### Containment, Eradication, Recovery

This phase stabilizes the environment, removes threats, and restores normal operations.

**Containment** strategies vary depending on the incident type. Key criteria for choosing an approach include:

* Potential damage and theft of resources.
* Evidence preservation requirements.
* Service availability needs.
* Time, resources, and effectiveness of the solution.
* Duration of containment measures.

Detailed logs of evidence gathered during containment are critical for both future prevention and information sharing with the wider security community.

**Eradication and Recovery** actions include:

* Removing malware or compromised accounts.
* Rebuilding systems from trusted backups.
* Resetting credentials.
* Installing patches and strengthening network security.

The goal is to eliminate attacker footholds, restore systems to pre-attack conditions, and close exploited vulnerabilities.

***

## CSIRT and CERT Explained

Organizations and governments created specialized teams to handle the rising number of cyberattacks. These groups are called Cyber Emergency Response Teams (CERTs) or Cyber Security Incident Response Teams (CSIRTs). Their main role is to coordinate responses to security incidents and assess organizational impact. CSIRTs often include stakeholders from infrastructure, networking, legal, communications, public relations, and security, ensuring all critical areas are represented during an emergency.

***

### Why are they Important?

CSIRTs provide essential functions for modern organizations, including:

* Serving as a central communication point for incident information.
* Promoting security awareness and training, such as phishing simulations.
* Acting as the designated emergency contact group for cybersecurity matters.
* Investigating vulnerabilities and threats, then developing mitigation and response strategies.
* Determining metrics such as Mean Time to Recovery (MTTR) and Mean Downtime (MDT).
* Sharing insights and data with other CSIRTs and the wider security community.

***

### Public vs Private

The naming of CERTs and CSIRTs often causes confusion, as multiple variations exist: Security Incident Response Team (SIRT), Incident Response Team (IRT), or Computer Security Incident Response Centre (CSIRC).

* **CERTs** are typically nationally recognized response teams, such as AusCERT (Australia), CERT.br (Brazil), CERTNZ (New Zealand), KrCERT (South Korea), CERT-UK (United Kingdom), and US-CERT (United States).
* **CSIRTs** are more commonly used within businesses for internal incident response, focusing on breaches that affect company operations.

Despite the different names, the goal remains consistent: coordinating and improving responses to cybersecurity incidents.

***

## Further Reading Material, Incident Response

This section provides additional resources for exploring incident response, useful for strengthening understanding or expanding skills in preparation for practical assessments.

***

### Resources

* [**Incident Response Consortium**](https://www.incidentresponse.org/) – The first and only IR-focused community.
* [**Awesome Incident Response**](https://github.com/meirwah/awesome-incident-response) – Curated list of incident response tools.
* [**Incident Response Tools by AT\&T Cybersecurity**](https://cybersecurity.att.com/resource-center/ebook/insider-guide-to-incident-response/incident-response-tools) – Overview of tools to support incident handling.
* [**Proactive Incident Response by Secureworks**](https://www.secureworks.com/centers/proactive-incident-response) – Guidance on proactive response strategies.
* [**Incident Handler’s Handbook by SANS**](https://www.sans.org/reading-room/whitepapers/incident/paper/33901) – Comprehensive handbook for incident handlers.
* [**Ultimate Guide to Cybersecurity Incident Response by TechTarget**](https://searchsecurity.techtarget.com/Ultimate-guide-to-incident-response-and-management) – Practical guide for response and management.
* [**Beginner’s Guide to Open Source Incident Response Tools and Resources by Cybersecurity Insiders**](https://www.cybersecurity-insiders.com/beginners-guide-to-open-source-incident-response-tools-and-resources/) – Introduction to open-source IR tools and resources.

***

## Incident Response Glossary

A glossary of key acronyms and terms used in the Incident Response domain of the Blue Team Level 1 certification. This reference is marked TLP:White and may be shared freely.

***

* **CERT** – Computer Emergency Response Team. National or organizational teams responsible for handling security incidents and conducting defense research.
* **CSIRT** – Computer Security Incident Response Team. Organizational team responding to incidents, often including IT, legal, HR, communications, and security staff.
* **IRP** – Incident Response Plan. A set of instructions guiding detection, response, and recovery from security incidents such as cybercrime, data loss, or outages.
* **IOC** – Indicator of Compromise. Evidence from malicious activity, such as malware hashes or filenames, that can be shared to improve defenses.
* **TTP** – Tools, Techniques, and Procedures. Categories of adversary behavior documented by MITRE to describe attack methods and campaigns.
* **DMZ** – Demilitarized Zone. A subnetwork that exposes external-facing services to untrusted networks like the internet.
* **EDR** – Endpoint Detection and Response. Endpoint-based monitoring platforms that detect anomalies, generate alerts, and can automate containment actions.
* **AV** – Antivirus Solution. Software for detecting and removing malware using signatures or anomaly-based detection.
* **ISAC** – Information Sharing and Analysis Center. Industry groups that share intelligence about cyberattacks to strengthen collective defenses.
* **IDS/IPS/IDPS** – Intrusion Detection and Prevention System. Detects suspicious activity (IDS) or blocks malicious attempts (IPS).
* **HIDS** – Host Intrusion Detection System. Detects suspicious activity on individual endpoints.
* **HIPS** – Host Intrusion Prevention System. Prevents malicious activity on endpoints by taking automated actions.
* **NIDS** – Network Intrusion Detection System. Detects suspicious activity across network traffic.
* **NIPS** – Network Intrusion Prevention System. Actively blocks or resets malicious network traffic.
* **FW** – Firewall. A software or hardware system controlling traffic based on rules; includes Web Application Firewalls (WAFs).
* **NGFW** – Next-Generation Firewall. Traditional firewall combined with deep packet inspection and intrusion prevention functions.
* **SIEM** – Security Information and Event Management. Centralized logging and alert analysis platform for real-time monitoring.
* **GPO** – Group Policy Object. Collections of settings controlling user and system actions to reduce potential harm.
* **PCAP** – Packet Capture. File format storing recorded network traffic for later analysis.
* **Sysmon** – System Monitor. A Windows utility that generates detailed logs to support defenders and threat hunters.

***
