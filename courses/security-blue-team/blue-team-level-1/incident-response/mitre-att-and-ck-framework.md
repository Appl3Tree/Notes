# MITRE ATT\&CK Framework

## Section Introduction

The [MITRE ATT\&CK](https://attack.mitre.org/) framework catalogs adversary tactics and techniques that can be applied for both defensive and offensive security purposes.

For **defensive roles**, security teams use the framework to identify visibility gaps, create detections, and improve monitoring. Threat hunters can proactively search for malicious activity by mapping it against known techniques, often aided by tools like the [ATT\&CK Navigator](https://mitre-attack.github.io/attack-navigator/).

For **offensive roles**, adversary emulation exercises replicate real-world threat actors’ behaviors, such as APT groups targeting specific industries. This allows red teams to test security controls while providing defenders with feedback on detection blind spots.

***

{% hint style="danger" %}
This course content does not cover the first two tactics of the MITRE ATT\&CK framework:

* [Reconnaissance (TA0043)](https://attack.mitre.org/tactics/TA0043/)
*   [Resource Development (TA0042)](https://attack.mitre.org/tactics/TA0042/)


{% endhint %}

## Initial Access

[Initial Access (TA0001)](https://attack.mitre.org/tactics/TA0001/) is the first stage of the MITRE ATT\&CK framework, where adversaries establish an entry point into a target network.&#x20;

{% hint style="warning" %}
At the time the course content was originally written, there were 9 high-level techniques in this category. As of **August 25, 2025**, the official MITRE ATT\&CK Enterprise matrix includes 11 **Initial Access techniques**.
{% endhint %}

### Phishing

[MITRE Technique T1566](https://attack.mitre.org/techniques/T1566/)

Phishing is the most common initial access vector and includes three sub-techniques covering different delivery approaches. Mitigations include training users, strengthening email filtering, and deploying anti-malware defenses. Detection recommendations focus on monitoring anomalous email patterns and suspicious message content.

### External Remote Services

[MITRE Technique T1133](https://attack.mitre.org/techniques/T1133/)

Attackers exploit services such as VPN, RDP, SSH, or Citrix to gain access, often paired with [Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/) obtained from phishing or breaches. Brute force attacks are possible but noisy, making them less common for advanced adversaries. Persistence can be maintained by keeping access to these services.

Mitigations include disabling unnecessary services and enforcing multi-factor authentication. Detection involves monitoring unusual authentication behavior, such as logins occurring far outside normal working hours.

### Removable Media

[MITRE Technique T1091](https://attack.mitre.org/techniques/T1091/)

Adversaries may use USB drives or similar devices to introduce malware, including in air-gapped environments. Devices like modified flash drives or “Rubber Ducky” tools may be used to deliver payloads.

Mitigations include disabling AutoRun, restricting USB device usage, enforcing strict policies, and deploying physical USB port blockers. Detection involves monitoring USB usage through Windows event logs, though this requires explicit configuration to enable.

***

## Execution

[Execution (TA0002)](https://attack.mitre.org/tactics/TA0002/) is the second stage of the MITRE ATT\&CK framework. It includes techniques adversaries use to run malicious code for objectives such as persistence, lateral movement, or discovery.&#x20;

{% hint style="warning" %}
At the time the course content was originally written, there were 10 high-level techniques in this category. As of **August 25, 2025**, the official MITRE ATT\&CK Enterprise matrix includes 16 **Execution techniques**.
{% endhint %}

### Windows Management Instrumentation

[MITRE Technique T1047](https://attack.mitre.org/techniques/T1047/)

Windows Management Instrumentation (WMI) is a Windows administration feature that provides system information and enables remote code execution across devices. WMI relies on the WMI service, SMB, and RPCS, and while often used legitimately, it is also abused for execution and lateral movement.

**Mitigations**:

* Limit privileged account usage by applying the principle of least privilege.
* Restrict which accounts are authorized to use WMI.

**Detection**:\
Monitor WMI activity with [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) using the following event IDs:

* Event ID 19 – WmiEventFilter activity
* Event ID 20 – WmiEventConsumer activity
* Event ID 21 – WmiEventConsumerToFilter activity

These logs can reveal suspicious or malicious WMI operations.

### User Execution

[MITRE Technique T1204](https://attack.mitre.org/techniques/T1204/)

User Execution involves tricking a user into running malicious content, either by clicking a harmful URL (sub-technique 1) or executing a malicious file (sub-technique 2). This often overlaps with [Phishing (T1566)](https://attack.mitre.org/techniques/T1566/). Adversaries may deliver payloads externally or use internal channels such as shared drives or email.

**Mitigations**:

* Application whitelisting to block unauthorized executables.
* Network intrusion prevention systems (NIPS) to block access to suspicious resources.
* Security awareness training to help users recognize phishing attempts.

**Detection**:

* Monitor commands executed in processes like `cmd.exe` or `powershell.exe`, as well as archive utilities (e.g., 7Zip, WinRAR).
* Use modern anti-virus and endpoint detection and response (EDR) tools to identify malicious activity, such as Microsoft Word spawning `cmd.exe`, which indicates malicious macro execution.

***

## Persistence

[Persistence (TA0003)](https://attack.mitre.org/tactics/TA0003/) is the third stage of the MITRE ATT\&CK framework. After gaining initial access, adversaries attempt to maintain their foothold on systems by disguising their activity and ensuring they can regain access if disrupted. This section focuses on **Boot or Logon Autostart Execution** and **External Remote Services**.

{% hint style="warning" %}
At the time the course content was originally written, there were 18 high-level techniques in this category. As of **August 25, 2025**, the official MITRE ATT\&CK Enterprise matrix includes **20 Persistence techniques**.
{% endhint %}

### Boot or Logon Autostart Execution

[MITRE Technique T1547](https://attack.mitre.org/techniques/T1547/)

Adversaries achieve persistence by configuring programs to automatically run at startup, often through Windows “run keys” in the Registry or by adding executables to startup folders. These programs will execute whenever a user logs into the host, and groups such as APT18, APT19, and APT29 have leveraged this method.

**Mitigation**: Hard to fully prevent, as legitimate programs also use startup configurations. Least privilege for user accounts helps reduce exposure.

**Detection**:

* Audit Windows Registry for unusual entries.
* Use [Sysinternals Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns) to identify and review autostart configurations.
* Monitor suspicious executables launched at system startup, especially those connecting to external command-and-control servers.

### External Remote Services

[MITRE Technique T1133](https://attack.mitre.org/techniques/T1133/)

Adversaries maintain persistence by using internet-facing services such as RDP, SSH, VPN, or Outlook Web Access with stolen valid credentials. This approach provides stealth, since activity can blend with legitimate remote connections unless login patterns appear unusual. Historical examples include APT18, APT41, Dragonfly 2.0, and FIN5.

**Mitigation**:

* Disable unnecessary internet-facing remote services.
* Restrict remote services to internal-only connections where possible.
* Enforce multi-factor authentication (MFA).
* Apply network segmentation with VLANs and firewalls to limit movement across systems.

**Detection**:

* Monitor authentication logs for login attempts, successes, and failures.
* Create alerts for access attempts outside of normal business hours or from unusual geographic regions.

***

## Privilege Escalation

[Privilege Escalation (TA0004)](https://attack.mitre.org/tactics/TA0004/) is the fourth stage of the MITRE ATT\&CK framework. These techniques describe how adversaries attempt to gain higher-level permissions, such as moving from a standard user to an administrator, or from an administrator to a domain administrator. At present, there are 12 top-level techniques in this category:

* [Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078/) (with four sub-techniques)
* [Exploitation for Privilege Escalation (T1068)](https://attack.mitre.org/techniques/T1068/)

{% hint style="warning" %}
At the time the course content was originally written, there were 12 high-level techniques in this category. As of August 25, 2025, the official MITRE ATT\&CK Enterprise matrix includes 14 Privilege Escalation techniques.
{% endhint %}

Below are details for selected techniques.

### Valid Accounts

[MITRE Technique T1078](https://attack.mitre.org/techniques/T1078/)

Adversaries may gain privileged accounts immediately if they can obtain valid credentials. This is often accomplished through phishing campaigns with credential-harvesting pages designed to mimic legitimate services such as Outlook Web Access. Attackers can then use these credentials to log into remote services like RDP.

Historical examples include APT28 campaigns where adversaries harvested credentials via spear phishing and exploited manufacturer default credentials on IoT devices to expand their foothold.

**Mitigations:**

* Avoid hardcoded credentials in applications or scripts that might be exposed publicly.
* Immediately change default credentials on routers, IoT devices, and other hardware.
* Conduct routine audits to identify over-privileged accounts and detect unauthorized privilege changes.

### Privilege Escalation Exploits

[MITRE Technique T1068](https://attack.mitre.org/techniques/T1068/)

Privilege escalation often relies on exploiting vulnerabilities in software or the operating system. Such flaws may allow execution of malicious code at higher privilege levels. For example, exploiting kernel-mode drivers in Windows can elevate an attacker’s privileges to SYSTEM, while similar exploits in Linux can grant ROOT access.

**Examples:**

* **APT28 – CVE-2017-0263**: A Windows kernel-mode vulnerability that mishandled objects in memory, allowing attackers to execute code in kernel mode, install programs, or create new administrator accounts.
* **APT32 – CVE-2016-7255**: Another kernel driver vulnerability enabling arbitrary code execution in the Windows kernel. Public exploit code exists and is integrated into frameworks like Metasploit.

**Mitigations:**

* Apply timely security patches to eliminate exploitable vulnerabilities.
* Build a threat intelligence capability to track active exploitation of CVEs.
* Enable Microsoft Exploit Guard to provide built-in protection against exploitation.

**Detection:**

* Enable detailed logging with [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) to track suspicious process creation and modification.
* Use endpoint detection and response (EDR) solutions to detect anomalous operating system changes.

***

## Defense Evasion

[Defense Evasion (TA0005)](https://attack.mitre.org/tactics/TA0005/) is the fifth stage of the MITRE ATT\&CK framework. These techniques describe how adversaries evade or disable defenses such as antivirus, endpoint detection and response, system logging, and even human analysts, allowing them to persist undetected within the network. At present, there are 38 top-level techniques in this category:

* [Impair Defenses (T1562)](https://attack.mitre.org/techniques/T1562/) (with six sub-techniques)
* [Indicator Removal on Host (T1070)](https://attack.mitre.org/techniques/T1070/) (with six sub-techniques)

{% hint style="warning" %}
At the time the course content was originally written, there were 38 high-level techniques in this category. As of August 25, 2025, the official MITRE ATT\&CK Enterprise matrix includes 45 Defense Evasion techniques.
{% endhint %}

### Impair Defenses

[MITRE Technique T1562](https://attack.mitre.org/techniques/T1562/)

Impair Defenses focuses on disrupting the normal function of security mechanisms, from antivirus and firewalls to monitoring tools and SIEM platforms. Sub-techniques include:

* **Disable or Modify Tools** – Adversaries may terminate or alter security software, logging processes, or scanning tools.
* **Disable Windows Event Logging** – Prevents defenders from using logs for detection and audit purposes.
* **HISTCONTROL** – On Linux, adversaries may configure this environment variable to avoid saving command history in `~/.bash_history`.
* **Disable or Modify System Firewall** – Attackers may alter or disable firewall rules to bypass network restrictions.
* **Indicator Blocking** – Attempts to block sensors or event collection by modifying system configurations or registry values.
* **Disable or Modify Cloud Firewall** – Disables or modifies firewall protections within cloud environments.

**Detection:**

* Adapt detections based on specific registry keys or configuration files altered by adversaries.
* Use [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) to log process activity and monitor command-line usage (CMD, PowerShell) for abnormal process termination or tampering.

### Indicator Removal on Host

[MITRE Technique T1070](https://attack.mitre.org/techniques/T1070/)

When adversaries interact with systems, they create artifacts such as log entries, file timestamps, and processes. Indicator Removal techniques erase or alter these traces to prolong undetected presence. Examples include:

* Deleting bash history or malicious files.
* Removing raw log files when SYSTEM or SUDO privileges are available.
* Timestomping files to obscure access or modification times.
* Self-deletion by malware to resist analysis (e.g., PoetRAT).
* Deleting C2-related artifacts, such as Goopy removing emails used for command-and-control.

**Mitigations:**

* Protect and restrict access to log files.
* Ensure minimal delay between log creation and forwarding to centralized SIEM storage. Once stored externally, adversaries face greater difficulty altering or deleting logs.

***

## Credential Access

[Credential Access (TA0006)](https://attack.mitre.org/tactics/TA0006/) is the sixth stage of the MITRE ATT\&CK framework. These techniques describe how adversaries attempt to obtain credentials such as usernames and passwords from compromised systems. Methods include credential dumping (retrieving credentials from memory) or deploying keyloggers to capture keystrokes. At present, there are 14 top-level techniques in this category:

* [OS Credential Dumping (T1003)](https://attack.mitre.org/techniques/T1003/)
* [Brute Force (T1110)](https://attack.mitre.org/techniques/T1110/)

{% hint style="warning" %}
At the time the course content was originally written, there were 14 high-level techniques in this category. As of August 25, 2025, the official MITRE ATT\&CK Enterprise matrix includes 17 Credential Access techniques.
{% endhint %}

### OS Credential Dumping

[MITRE Technique T1003](https://attack.mitre.org/techniques/T1003/)

Adversaries with local access may retrieve credentials stored by the operating system or applications. Among the eight sub-techniques, two common ones are:

* [**LSASS Memory (T1003.001)**](https://attack.mitre.org/techniques/T1003/001/)**:** In Windows environments, credentials are stored in the LSASS process. Attackers with admin or SYSTEM privileges can dump LSASS memory, extract password hashes, and perform offline brute force attacks to recover plaintext passwords. These credentials can then be reused across the network. Tools such as Mimikatz are often used for this purpose.
* [**/etc/passwd and /etc/shadow (T1003.008)**](https://attack.mitre.org/techniques/T1003/008/)**:** On Linux, adversaries may attempt to dump `/etc/passwd` (usernames) and `/etc/shadow` (password hashes). Access to `/etc/shadow` requires root privileges. Offline tools like John the Ripper or Hashcat can crack the hashes to reveal plaintext passwords.

**Mitigations:**

* Ensure unique, complex passwords for all local administrator accounts across systems.
* Implement Privileged Account Management (PAM) to secure and monitor privileged accounts.
* Train users on the importance of password hygiene and avoiding password reuse.

**Detection:**

* On Windows, monitor suspicious activity involving `lsass.exe`.
* On Linux, use [AuditD](https://linux.die.net/man/8/auditd) to detect processes accessing sensitive files like `/proc/*/maps` during credential dumping attempts.

### Brute Force

[MITRE Technique T1110](https://attack.mitre.org/techniques/T1110/)

Brute force involves systematically guessing or cracking passwords to gain access. Two common scenarios are:

1. Attempting to guess valid credentials without prior knowledge, often using username and password lists or iterating through possible password combinations.
2. Cracking dumped password hashes offline using tools such as Hashcat.

Adversaries like APT39 have used Ncrack to brute force network services, while groups such as Chaos and DarkVishnya have performed brute force against SSH and other services to gain access.

**Mitigations:**

* Configure account lockout policies to prevent repeated failed login attempts.
* Enforce multi-factor authentication (MFA) to add a barrier against compromised passwords.
* Follow [NIST password policy guidelines](https://pages.nist.gov/800-63-3/) to increase password strength.
* Monitor data breaches and proactively reset compromised credentials.

**Detection:**

* Monitor for failed login attempts at scale.
* In Windows, track Security Event ID **4625 (An account failed to logon)**, which includes error codes detailing failure reasons (e.g., 0xC000006A for bad password).
* Use SIEM or EDR solutions to alert on abnormal authentication patterns across multiple systems.

***

## Discovery

[Discovery (TA0007)](https://attack.mitre.org/tactics/TA0007/) is the seventh stage of the MITRE ATT\&CK framework. These techniques describe how adversaries collect information about the network, systems, and accounts to plan further actions while remaining stealthy and blending into normal activity. At present, there are 24 top-level techniques in this category:

* [Account Discovery (T1087)](https://attack.mitre.org/techniques/T1087/)
* [Network Service Scanning (T1046)](https://attack.mitre.org/techniques/T1046/)
* [File and Directory Discovery (T1083)](https://attack.mitre.org/techniques/T1083/)

{% hint style="warning" %}
At the time the course content was originally written, there were 24 high-level techniques in this category. As of August 25, 2025, the official MITRE ATT\&CK Enterprise matrix includes 33 Discovery techniques.
{% endhint %}

### Account Discovery

[MITRE Technique T1087](https://attack.mitre.org/techniques/T1087/)

Adversaries enumerate accounts to prepare for privilege escalation or lateral movement. Enumeration can include operating system accounts, domain accounts, email accounts, or even cached cloud credentials.

**Examples:**

* **Local Accounts:** Using commands like `net user` and `net localgroup` on Windows, or `id`, `groups`, and reading `/etc/passwd` on Linux/macOS.
* **Domain Accounts:** Using `net user /domain` or `net group /domain` on Windows, `dscacheutil -q group` on macOS, or `ldapsearch` on Linux.
* **Email Accounts:** Harvesting email addresses, such as Emotet scraping Exchange address lists for further phishing.
* **Cloud Accounts:** Browsing AWS or Azure consoles for cached credentials in user browsers.

**Mitigation:**

* Disable the Windows registry key that allows administrator account enumeration. Apply this setting broadly using Group Policy Objects (GPO).

### Network Service Scanning

[MITRE Technique T1046](https://attack.mitre.org/techniques/T1046/)

After gaining a foothold, adversaries often scan the network to identify active systems, services, and versions, which can be researched for exploitable vulnerabilities.

**Mitigation:**

* Disable unnecessary services that should not accept remote connections.
* Deploy intrusion detection/prevention systems (IDS/IPS) to monitor for suspicious scanning.
* Use network segmentation to restrict lateral reach, such as isolating sensitive database networks from employee laptops.

### File and Directory Discovery

[MITRE Technique T1083](https://attack.mitre.org/techniques/T1083/)

Attackers search a system’s filesystem for valuable data, such as credentials, network diagrams, emails, or sensitive documents.

**Mitigation:**

* None are listed, as filesystem browsing is normal user activity.

**Detection:**

* Monitor for unusual command-line usage of filesystem tools (`cd`, `dir`, `find`) on endpoints where users rarely interact with the filesystem via CLI.
* Monitor API calls or processes scanning large portions of the filesystem in a short timeframe.

***

## Lateral Movement

[Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008/) is the eighth stage of the MITRE ATT\&CK framework. Adversaries often need to compromise multiple hosts within a network to reach their primary objectives, and the process of moving between these systems is known as lateral movement. At present, there are 9 top-level techniques in this category:

* [Remote Services (T1021)](https://attack.mitre.org/techniques/T1021/) (with six sub-techniques)
* [Internal Spearphishing (T1534)](https://attack.mitre.org/techniques/T1534/)

{% hint style="warning" %}
At the time the course content was originally written, there were 9 high-level techniques in this category. As of August 25, 2025, the official MITRE ATT\&CK Enterprise matrix includes 9 Lateral Movement techniques.
{% endhint %}

### Remote Services

[MITRE Technique T1021](https://attack.mitre.org/techniques/T1021/)

Adversaries frequently exploit valid credentials to log into remote services such as RDP, SMB, DCOM, SSH, VNC, or WinRM. In large environments, IT administrators may reuse the same passwords across systems, making this technique highly effective and more difficult to detect.

**Mitigations:**

* Enforce multi-factor authentication (MFA) on remote services.
* Audit which accounts can access remote services and restrict unnecessary permissions.

**Detection:**

* Build activity timelines that correlate system enumeration, suspicious behavior, and logon events.
* Investigate unusual account usage by asking: Was the user expected to be working? Is the account new? What other events occurred around the same time?

### Internal Spearphishing

[MITRE Technique T1534](https://attack.mitre.org/techniques/T1534/)

After gaining email access, adversaries may send internal spearphishing emails containing links or attachments to compromise additional systems. These messages are highly effective because they come from trusted internal accounts, often leveraging existing email threads for added credibility.

**Example:** The Gamaredon Group has used malicious VBA modules to automatically send phishing emails from compromised mailboxes, spreading access across an organization.

**Detection:**

* Scan URLs and attachments passing through the organization’s mail server.
* If prevention fails, monitor at the Execution stage for suspicious payload activity triggered by recipients.

***

## Collection

[Collection (TA0009)](https://attack.mitre.org/tactics/TA0009/) is the ninth stage of the MITRE ATT\&CK framework. These techniques describe how adversaries gather information from compromised systems, identify valuable files or data, and prepare them for exfiltration. At present, there are 16 top-level techniques in this category:

* [Email Collection (T1114)](https://attack.mitre.org/techniques/T1114/)
* [Audio Capture (T1123)](https://attack.mitre.org/techniques/T1123/)
* [Screen Capture (T1113)](https://attack.mitre.org/techniques/T1113/)
* [Data from Local System (T1005)](https://attack.mitre.org/techniques/T1005/)

{% hint style="warning" %}
At the time the course content was originally written, there were 16 high-level techniques in this category. As of August 25, 2025, the official MITRE ATT\&CK Enterprise matrix includes 17 Collection techniques.
{% endhint %}

### Email Collection

[MITRE Technique T1114](https://attack.mitre.org/techniques/T1114/)

Adversaries collect emails to gain insight into business operations, harvest addresses for spear phishing, or steal attachments with sensitive data. Sub-techniques include:

* **Local Email Collection:** Accessing Outlook cache or storage files on the host.
* **Remote Email Collection:** Using valid credentials to retrieve mail directly from Exchange or Office 365, sometimes externally.
* **Email Forwarding Rule:** Creating auto-forwarding rules that silently leak emails to attacker-controlled accounts.

**Mitigations:**

* Enforce multi-factor authentication (MFA).
* Encrypt emails or sensitive attachments.
* Audit and alert on suspicious auto-forwarding rules.

**Detection:**

* Monitor unusual processes accessing mail applications or servers.
* Watch for anomalous login times, such as off-hours activity.
* Track suspicious PowerShell, WMI, or CMD commands executed under user accounts.

### Audio Capture

[MITRE Technique T1123](https://attack.mitre.org/techniques/T1123/)

Attackers may use connected microphones, headsets, or webcams to record conversations. They may also capture VOIP traffic from apps like Teams, Skype, or Webex.

**Examples:** APT37 has used SOUNDWAVE malware for microphone capture, while Bandook, Cobian RAT, Attor, and Cadelspy also include audio capture capabilities.

**Mitigations:**

* Cannot be fully prevented due to legitimate audio usage.

**Detection:**

* Monitor API calls associated with audio capture (noting high false positives).
* Track processes accessing microphones or generating audio files unexpectedly.

### Screen Capture

[MITRE Technique T1113](https://attack.mitre.org/techniques/T1113/)

Screenshots help adversaries observe user activity and collect data from documents, email, or browsing sessions.

**Examples:** Agent Tesla RAT takes scheduled screenshots. APT28, APT39, and Aria-body malware have also used this technique.

**Mitigations:**

* Not practical to block due to legitimate use.

**Detection:**

* Monitor for unusual API calls related to screenshot capture (`CopyFromScreen`, `xwd`, `screencapture`).
* Correlate screenshot behavior with other malicious activity to reduce false positives.

### Data From Local System

[MITRE Technique T1005](https://attack.mitre.org/techniques/T1005/)

Adversaries search local or network drives for valuable files, including documents, databases, projects, or configurations. Tools or interpreters (e.g., CMD with `find`, `tree`, `dir`) may be used to enumerate files, or malware may automate collection.

**Examples:** APT28 has exfiltrated internal documents. GravityRAT and Inception steal files with targeted extensions.

**Mitigations:**

* Differentiating legitimate user activity from malicious collection is challenging.

**Detection:**

* Monitor for excessive or unusual command usage in CMD or PowerShell.
* Watch for large-scale file access suggesting preparation for exfiltration.

***

## Command and Control

[Command and Control (TA0011)](https://attack.mitre.org/tactics/TA0011/) is the tenth stage of the MITRE ATT\&CK framework. These techniques describe how adversaries communicate with compromised systems inside a target network. Command and control (C2) often leverages common protocols and ports to blend in with normal traffic, making detection more difficult. At present, there are 16 top-level techniques in this category:

* [Application Layer Protocol (T1071)](https://attack.mitre.org/techniques/T1071/)
* [Web Service (T1102)](https://attack.mitre.org/techniques/T1102/)
* [Non-Standard Port (T1571)](https://attack.mitre.org/techniques/T1571/)

{% hint style="warning" %}
At the time the course content was originally written, there were 16 high-level techniques in this category. As of August 25, 2025, the official MITRE ATT\&CK Enterprise matrix includes 18 Command and Control techniques.
{% endhint %}

### Application Layer Protocol

[MITRE Technique T1071](https://attack.mitre.org/techniques/T1071/)

Adversaries use common application layer protocols such as HTTP, HTTPS, or DNS to disguise C2 traffic as normal web or email activity. Cobalt Strike, for example, can encapsulate C2 communication in SMB, while Dragonfly 2.0 and Duqu have hidden C2 traffic within HTTPS and DNS.

**Mitigations:**

* Deploy network intrusion detection and prevention systems (NIDS/NIPS) to alert or block suspicious traffic.

**Detection:**

* Use IDS solutions such as Suricata, Snort, or Zeek to analyze network data.
* Monitor SSL/TLS certificate usage with Zeek’s `x509.log` for default or reused C2 certificates.
* Investigate unusual data flows, such as large outbound transfers or unknown services listening on non-standard ports.

### Web Service

[MITRE Technique T1102](https://attack.mitre.org/techniques/T1102/)

Attackers may use legitimate external web services as C2 channels. Common platforms like Google, Twitter, GitHub, or Pastebin provide cover, as corporate users often already connect to these services. FIN6 has used Pastebin, Gamaredon Group has hosted payloads on GitHub, and Inception has relied on multiple cloud service providers for resilient C2.

**Mitigations:**

* Deploy NIDS/NIPS to detect and block suspicious connections.
* Use web proxies to filter inbound and outbound traffic, blacklist malicious domains, or block certain services altogether if business operations allow.

**Detection:**

* Monitor for abnormal upload activity, such as clients sending far more data than they receive.
* Investigate suspicious login times, such as employees connecting to GitHub outside normal hours.

### Non-Standard Port

[MITRE Technique T1571](https://attack.mitre.org/techniques/T1571/)

Adversaries may run standard protocols over uncommon ports to bypass security controls, such as HTTPS over port 8088 instead of 443. For example, APT33 has used HTTP over ports 808 and 880, while BADCALL malware communicates via FakeTLS over ports 443 and 8000.

**Mitigations:**

* Enforce firewall and proxy rules restricting outbound traffic to only expected ports (e.g., TCP 80 for HTTP, 443 for HTTPS).
* Implement strong network segmentation with firewalls and VLANs.

**Detection:**

* Use packet inspection with tools like Snort or Zeek to identify protocol-port mismatches and flag anomalies.

***

## Exfiltration

[Exfiltration (TA0010)](https://attack.mitre.org/tactics/TA0010/) is the eleventh stage of the MITRE ATT\&CK framework. These techniques describe how adversaries steal data from compromised networks and systems, often using compression, encryption, or encoding to avoid detection. Exfiltration typically occurs over existing command-and-control channels. At present, there are 9 top-level techniques in this category:

* [Exfiltration Over C2 Channel (T1041)](https://attack.mitre.org/techniques/T1041/)
* [Scheduled Transfer (T1029)](https://attack.mitre.org/techniques/T1029/)

{% hint style="warning" %}
At the time the course content was originally written, there were 9 high-level techniques in this category. As of August 25, 2025, the official MITRE ATT\&CK Enterprise matrix includes 9 Exfiltration techniques.
{% endhint %}

### Exfiltration Over C2 Channel

[MITRE Technique T1041](https://attack.mitre.org/techniques/T1041/)

Adversaries may repurpose established command-and-control channels to exfiltrate data from a network. Files can be extracted as part of beacon traffic sent to attacker-controlled C2 servers.

**Detection:**

* Monitor for clients sending large amounts of outbound data to external servers.
* Use network intrusion detection systems (NIDS) to create rules that detect specific file signatures (e.g., Microsoft Office “magic bytes”).
* Detect C2 servers by analyzing beaconing patterns such as regular intervals with jitter.

### Scheduled Transfer

[MITRE Technique T1029](https://attack.mitre.org/techniques/T1029/)

Adversaries may schedule exfiltration at specific times to avoid detection and maximize data stolen. Malware such as ADVSTORESHELL uploads data every 10 minutes, while Cobalt Strike can randomize beacon intervals and break files into smaller chunks. Other tools like ComRAT and Dipsind may only operate during business hours to blend in with normal traffic.

**Mitigations:**

* Deploy NIDS/NIPS (e.g., Snort, Zeek) to detect and disrupt abnormal outbound activity.

**Detection:**

* Monitor processes that simultaneously access files and initiate outbound network connections.
* Inspect traffic for large or irregularly sized packets that may indicate file uploads.

***

## Impact

[Impact (TA0040)](https://attack.mitre.org/tactics/TA0040/) is the twelfth stage of the MITRE ATT\&CK framework. These techniques describe how adversaries disrupt availability or compromise integrity by manipulating business and operational processes, such as destroying or encrypting data. At present, there are 13 top-level techniques in this category:

* [Account Access Removal (T1531)](https://attack.mitre.org/techniques/T1531/)
* [Defacement (T1491)](https://attack.mitre.org/techniques/T1491/) (with two sub-techniques)
* [Data Encrypted for Impact (T1486)](https://attack.mitre.org/techniques/T1486/)

{% hint style="warning" %}
At the time the course content was originally written, there were 13 high-level techniques in this category. As of August 25, 2025, the official MITRE ATT\&CK Enterprise matrix includes 15 Impact techniques.
{% endhint %}

### Account Access Removal

[MITRE Technique T1531](https://attack.mitre.org/techniques/T1531/)

Adversaries may delete, lock, or change passwords of user accounts to deny access, disrupt operations, or hinder forensic investigations. These activities are highly visible, so they typically occur after other objectives are completed. For example, the LockerGoga ransomware not only encrypted files but also changed account passwords, preventing recovery.

**Mitigations:**

* Administrative controls should limit the number of accounts with privileges to modify or delete user accounts.

**Detection:**

* Monitor relevant Windows Event IDs for account deletion, locking, and password changes.
* Analyze event volume and context to differentiate legitimate user activity (e.g., forgotten passwords) from malicious actions.

### Defacement

[MITRE Technique T1491](https://attack.mitre.org/techniques/T1491/)

Defacement occurs when adversaries alter content on systems or websites, often for hacktivism, intimidation, or to claim credit. Sub-techniques include internal system defacement (e.g., changing wallpapers) and external defacement (e.g., altering public websites).

**Mitigations:**

* Restore systems and websites from recent backups.
* Protect backups from tampering by adversaries.

**Detection:**

* Monitor for unauthorized file changes on web servers.
* Use web application firewalls (WAFs) to block injection and exploitation attacks.
* Detect abnormal direct access to web servers via RDP or SSH that bypasses the WAF.

### Data Encrypted for Impact

[MITRE Technique T1486](https://attack.mitre.org/techniques/T1486/)

Adversaries may encrypt files or systems to deny access, typically through ransomware attacks. In some cases, attackers demand payment for a decryption key; in others, encryption is used purely to destroy functionality. High-profile examples include Ryuk, Shamoon, and WannaCry.

**Mitigations:**

* Maintain frequent, secure backups and protect them against modification or deletion.

**Detection:**

* Monitor command-line activity for tools like `vssadmin`, `wbadmin`, and `bcdedit`, which adversaries use during encryption.
* Detect unusually high volumes of file modifications over short timeframes, a strong indicator of ransomware activity.

***
