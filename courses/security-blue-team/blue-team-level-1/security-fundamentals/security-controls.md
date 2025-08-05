# Security Controls



## Section Introduction

This section provides a brief overview of security controls, grouped by deployment area. Controls are categorized into:

* **Physical Security Controls** – Deterrents, access control measures, and monitoring systems
* **Network Security Controls** – Firewalls, intrusion prevention/detection systems, SIEM, network access control
* **Endpoint Security Controls** – Host-based protections like HIPS, HIDS, EDR, and antivirus
* **Email Security Controls** – Spam filters, data loss prevention, and email scanning

## Physical Security

Physical security controls protect buildings and restricted areas from unauthorized access. These measures aim to make intrusion difficult through deterrents, access restrictions, and monitoring systems. While not usually managed by cybersecurity teams, understanding these controls can support investigations.

If attackers gain physical access, they can bypass most defenses. Physical access could allow direct system compromise, theft of sensitive materials, or even damage to critical equipment.

### Access Controls

Limit entry to secure areas and ensure only authorized individuals can pass:

* **Mantraps** – Two-stage entry system for secure inspection before granting access.
* **Turnstiles/Gates** – Require ID badge or access card for entry.
* **Electronic Doors** – Restrict access based on role, minimizing exposure to sensitive areas.

### Monitoring Controls

Provide real-time detection and evidence collection:

* **CCTV** – Continuous video monitoring for security teams.
* **Security Guards** – Trained staff to monitor and respond to incidents.
* **Intrusion Detection Systems** – Alerts triggered by motion, heat, or sound (e.g., breaking glass).

### Deterrents

Discourage attempts to gain entry:

* **Warning Signs** – Inform potential intruders of legal or policy violations.
* **Fences/Barbed Wire** – Physical barriers that slow or prevent entry.
* **Guard Dogs** – Visible, trained animals that discourage intrusion.
* **Security Lighting** – Eliminates dark areas that could conceal unauthorized activity.
* **Visible CCTV** – Cameras (operational or not) that signal surveillance is in place.

## Endpoint Security

Endpoint security focuses on protecting individual devices such as laptops, desktops, and servers from malicious activity. These defenses form a foundational layer of protection and are built upon in later parts of the course.

### Host Intrusion Detection (HIDS)

* Monitors endpoint activity for suspicious patterns.
* Generates alerts for analysts or pushes them to a SIEM for investigation.

### Host Intrusion Prevention (HIPS)

* Similar to HIDS but takes automated defensive actions.
* Can block connections, remove malicious files, or terminate harmful processes.

### Anti-Virus Solutions

* **Signature-based** – Detects malware by known patterns; limited against unknown threats.
* **Behavior-based** – Flags deviations from normal system behavior to identify new threats.

### Log Monitoring

* Endpoints send logs to a SIEM for centralized analysis.
* Unusual behavior triggers alerts for investigation.

### Endpoint Detection and Response (EDR)

* Combines logging, monitoring, and response capabilities.
* Enables analysts to investigate and respond to suspicious activity remotely.

### Vulnerability Scanning

* Identifies weaknesses and misconfigurations on endpoints.
* **External scans** simulate an attacker’s view.
* **Internal scans** assess internal systems for security gaps.
* Credentialed scans provide deeper insight into configurations; non-credentialed scans show attacker-visible risks.

### Compliance Scanning

* Ensures systems meet security standards required by compliance frameworks.
* Uses scanner profiles tailored to framework requirements.

## Email Security

Email remains the top attack vector for compromising organizations, often through phishing. Technical defenses are critical, but because email attacks target people rather than systems, employee training is equally important.

### Spam Filter

* Scans incoming messages for signs of spam or malicious content.
* Blocks suspicious messages before they reach employee inboxes, reducing exposure.

### Data Loss Prevention (DLP)

* Monitors outgoing emails to prevent unauthorized transmission of sensitive data.
* Can scan body text, headers, and attachments for keywords, patterns, or sensitive information.
* Blocks and alerts when policy violations are detected.

### Email Scanning

* Analyzes email content, URLs, and attachments for malicious indicators.
* Uses blacklists, signatures, and pattern analysis to detect threats.
* Quarantines suspicious emails and alerts the security team.

### Security Awareness Training

* Educates employees on recognizing and responding to phishing attempts.
* Reinforces proper reporting procedures for suspicious emails.
* Often paired with simulated phishing campaigns to measure and improve awareness.

## Network Security

Network security controls protect networks and connected systems from unauthorized access, malicious activity, and attacks. This section introduces foundational defenses that will be built on later in the course.

### Network Intrusion Detection (NIDS)

* Monitors network traffic for suspicious activity.
* Can be deployed inline, via network taps, or through SPAN ports.
* Generates alerts for analysts to investigate but does not take direct action.

### Network Intrusion Prevention (NIPS)

* Similar to NIDS but can automatically take defensive actions.
* Can block suspicious traffic, such as stopping a system from scanning other devices.

### Firewalls

* Restrict traffic between network segments, often separating internal networks from the internet.
* Types include:
  * **Standard firewalls** – Dedicated hardware at network boundaries.
  * **Local firewalls** – Software on endpoints (e.g., Windows Firewall).
  * **Web application firewalls** – Protect web servers and applications.

### Log Monitoring

* Network devices send logs to a SIEM for centralized analysis.
* Examples of valuable logs:
  * **Web proxy logs** – Track websites visited; can trigger alerts for malicious or restricted sites.
  * **Perimeter firewall logs** – Detect scanning activity, DDoS attempts, and other suspicious traffic.

### Network Access Control (NAC)

* Ensures only compliant devices can connect to the network.
* Can enforce security requirements like patches and antivirus.
* Common in BYOD and guest networks, as well as public Wi-Fi environments with access restrictions
