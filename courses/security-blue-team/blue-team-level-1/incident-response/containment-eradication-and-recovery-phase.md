# Containment, Eradication, and Recovery Phase

## Section Introduction

This section introduces methods for containing incidents, preserving digital evidence, eliminating malicious artifacts, addressing root causes, and restoring affected systems.

***

## Incident Containment

Incident containment limits the spread of an attack, prevents additional damage, and preserves forensic evidence that may be required for legal or investigative purposes.

### What is Containment?

Containment should be treated as a defined strategy rather than a single step in incident response. Strategies differ depending on the environment and may focus on the perimeter, demilitarized zone, internal networks, endpoints, or a combination. Each organization must tailor its approach based on its infrastructure and available tools.

### Short-Term Containment

Short-term containment involves immediate actions that prevent further harm, without resolving the root cause. Examples include:

* **Compromised AD account**: Disable the account in Active Directory to prevent continued unauthorized logins.
* **Malware on corporate laptop**: Use endpoint tools to isolate the device from the network to block attacker control or data exfiltration.
* **C2 traffic from internal servers**: Block the remote IP on perimeter firewalls to disrupt command-and-control communication.
* **Web attacks against company site**: Apply Web Application Firewall rules to block traffic matching specific attack signatures.

Short-term measures only stop active harm; they do not address underlying vulnerabilities or prevent recurrence.

### Long-Term Containment

Long-term containment applies broader organizational fixes after the root cause has been identified. These measures reduce the likelihood and impact of future incidents. Examples include:

* Restructuring internal networks for improved segmentation and isolation.
* Patching exploited vulnerabilities through software, firmware, or configuration updates.
* Deploying new security controls such as improved email gateways, antivirus, or intrusion detection systems.
* Reviewing accounts and enforcing the Principle of Least Privilege.

### Containment Measures

#### Perimeter Containment

* Block inbound and outbound traffic.
* Use IDS/IPS filters to detect and stop malicious connections.
* Apply Web Application Firewall policies against web-based threats.
* Implement DNS null routing to prevent domain resolution for attacker infrastructure.

#### Network Containment

* Isolate systems with switch-based VLANs or router segmentation.
* Block specific ports to prevent exploitation.
* Restrict access via IP or MAC filtering.
* Enforce Access Control Lists to limit network activity.

#### Endpoint Containment

* Disconnect compromised systems from networks (disable Wi-Fi or unplug cable).
* Power off infected devices.
* Apply host-based firewall rules.
* Use Host Intrusion Prevention Systems to isolate compromised endpoints.

### Has it Been Effective?

Effectiveness must be validated through monitoring. Indicators include attack vectors, targeted systems, and outbound traffic. For example, if a system was contained, a SIEM rule can check for prohibited outbound connections. Any alerts, such as “On-going Incident 5537, Containment Verification, Immediate Escalation,” should trigger immediate analyst review and escalation, since successful outbound traffic would indicate failed containment.

***

## Taking Forensic Images

Preserving evidence during incident response enables defenders to analyze attacker tactics, techniques, and procedures, as well as gather indicators of compromise to share with other organizations. Forensic imaging involves capturing hard drives and memory dumps from affected systems to ensure volatile and non-volatile data are retained.

Forensic images may be stored on external media, such as USB drives, to allow multiple analysts to examine the data and to maintain secure copies beyond the initial forensic workstation.

### FTK Imager and KAPE

Incident responders often use [FTK Imager](https://www.exterro.com/ftk-imager) and [KAPE](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape) for evidence collection:

* **KAPE** is used for rapid acquisition of volatile data, such as RAM.
* **FTK Imager** creates bit-for-bit disk copies while ensuring integrity.

The process includes:

1. Connect the suspect drive through a hardware write-blocker to a forensic workstation.
2. Take a full disk image without altering the original data.
3. Generate cryptographic hashes of both the original and the image for validation.
4. Store the original drive securely and investigate only the copy.

This ensures the chain of custody is preserved while still allowing analysts to perform deep forensic analysis.

### Virtual Desktops

In virtualized environments such as Citrix, the approach differs. Instead of imaging a physical drive:

1. Take a snapshot of the virtual system.
2. Mount the snapshot into a forensic virtual machine, such as [SIFT](https://digital-forensics.sans.org/community/downloads).
3. Create a disk image of the mounted snapshot for analysis.

This method preserves the state of the virtual environment while enabling forensic review without altering the original system.

***

## Identifying and Removing Malicious Artifacts

Malicious artifacts are any objects with harmful intent that persist on a system, such as malware, processes, scheduled tasks, registry entries, or files created by keyloggers. Removing all artifacts is critical; missing even one can allow attackers to retain access through mechanisms like backdoors, even if the system has otherwise been patched and hardened.

### Identifying Artifacts

Experience often plays a large role in recognizing suspicious items, but several indicators can guide the process:

* **Processes**: Look for unknown or suspicious processes. [Sysinternals Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer) can reveal processes attempting to masquerade as legitimate system activity.
* **Network connections**: Use `netstat` alongside [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) to trace malware attempting outbound communication or lateral movement.
* **Rootkits**: [Rootkit Revealer](https://learn.microsoft.com/en-us/sysinternals/downloads/rootkit-revealer) detects malware that hides using advanced evasion techniques.
* **Other checks**: Review scheduled tasks, user accounts, recent file downloads, and registry entries for unusual or unauthorized items.

### Removing Artifacts

#### Reimaging Affected Systems

Restoring from a clean backup is the most reliable way to remove all malicious artifacts. This guarantees system integrity but results in the loss of data created after the backup snapshot.

#### Anti-Malware Solutions

Scanning with updated antivirus or [Next-Generation Antivirus](https://www.crowdstrike.com/cybersecurity-101/next-gen-antivirus-ngav/) (NGAV) solutions can help detect and remove artifacts. NGAV tools use machine learning and behavioral analytics to detect threats beyond traditional signature-based methods, including fileless malware. In advanced infections, reimaging is often the safer approach.

#### Bootable Tools

Some vendors provide stand-alone, bootable solutions that bypass potentially compromised systems:

* [McAfee Stinger Malware Removal Tool](https://www.mcafee.com/en-us/consumer-corporate/mcafee-labs/free-tools/stinger.html)
* [Microsoft Malicious Software Removal Tool](https://www.microsoft.com/en-us/download/details.aspx?id=9905)
* [Avira Rescue System](https://www.avira.com/en/support-download-avira-rescue-system)

These tools can be run from CD or USB media, preventing interference from active malware.

#### Removing Malicious Files

Incident responders often delete discovered malicious executables, scripts, or offensive security tools that have no legitimate function on the system. This prevents future misuse by attackers or accidental execution by system users.

#### Deleting Persistence Mechanisms

Persistence mechanisms ensure attackers can return after an initial compromise. Removing them is essential:

* **Windows**: Delete malicious registry keys and scheduled tasks.
* **Linux/Unix**: Remove unauthorized cron jobs or startup scripts.

Eliminating persistence closes avenues for attackers to reestablish control.

***

## Identifying Root Cause and Recovery

After containment, evidence collection, and artifact removal, the next step is identifying the incident’s root cause and performing recovery so systems can safely return to production.

### Identifying the Root Cause

Some causes may be obvious, such as a user reporting they opened a suspicious email attachment before experiencing unusual behavior. Others require deeper investigation using structured frameworks like the [Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html) or [MITRE ATT\&CK](https://attack.mitre.org/). Mapping attacker activity across these stages helps analysts form hypotheses about the initial compromise.

Forensic images of affected systems allow detailed analysis of attacker actions and techniques. Identifying the true entry point is critical; skipping this step risks leaving open vulnerabilities that attackers could exploit again.

### Incident Recovery

Recovery focuses on strengthening affected systems and preventing recurrence. Common recovery measures include:

* **Patching**: Apply program, operating system, and security updates to close exploited vulnerabilities. Verify patches through manual testing.
* **Service hardening**: Disable unnecessary services to reduce the attack surface.
* **Security updates**: Update EDR, antivirus, intrusion detection and prevention systems, and SIEM rules to detect similar future activity.
* **Information sharing**: Share indicators of compromise and findings with peer organizations to improve collective defenses and enable exposure checks across other environments.

These actions ensure business operations can resume securely while addressing both technical and human factors behind the incident.

***
