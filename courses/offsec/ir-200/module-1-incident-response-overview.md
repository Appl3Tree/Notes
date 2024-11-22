# Module 1: Incident Response Overview

## What Is a Cyber Incident?

### Characteristics of a Cyber Incident

_The whos and hows to cyber incidents._

$$
Risk = Threat * Vulnerability * Impact
$$

### The Cyber Kill Chain

<figure><img src="../../../.gitbook/assets/image (10).png" alt=""><figcaption><p>Incidents and the Cyber Kill Chain</p></figcaption></figure>

## Cybersecurity Within an IT Incident

### Incident Management in the ITIL Framework

ITIL conists of five key stages:

* Service Strategy
* Service Design
* Service Transition
* Service Operation
* Continual Service Improvement

### The Incident Management Process in ITILv3

The Incident Management process starts whenever:

* A user, customer, or supplier reports an issue
* Technical staff notice a system failure
* An event monitoring system raises an alert

<figure><img src="../../../.gitbook/assets/image (1) (1) (1).png" alt=""><figcaption><p>ITIL Incident Response</p></figcaption></figure>

## Common Types of Incidents

### The European Union Incident Classification Taxonomy

| Classification        | Examples                                   |
| --------------------- | ------------------------------------------ |
| Abusive Content       | Spam, harmful speech, pornography          |
| Malicious code        | Viruses, worms, trojans, spyware, rootkits |
| Information Gathering | Scanning, sniffing social engineering      |
| Intrusion Attempts    | Exploit and login attempts                 |
| Intrusions            | Account and application compromise, bots   |
| Availability          | DDoS, sabotage                             |
| Information security  | Unauthorized data access or modification   |
| Fraud                 | Unauthorized use, phishing, copyright      |

### Understand the Open Threat Taxonomy

_Enclave Cybersecurity Threats_

| Code   | Description                        |
| ------ | ---------------------------------- |
| TEC003 | System fingerprinting via scanning |
| TEC004 | System fingerprinting via sniffing |
| TEC006 | Credential discovery via scanning  |

### The MITRE ATT\&CK Threat Taxonomy

_MITRE ATT\&CK Tactics and Techniques Example_

| Tactic               | Example Techniques                                        |
| -------------------- | --------------------------------------------------------- |
| Reconnaissance       | Active Scanning, Search open sources                      |
| Resource Development | Acquire infrastructure, Develop capabilities              |
| Initial Access       | Drive-by access, Phishing                                 |
| Execution            | Serverless execution, deploy container                    |
| Persistence          | Account manipulation, implant internal image              |
| Privilege Escalation | Abuse elevated control mechanism, process injection       |
| Defense Evasion      | Access token manipulation, Hide artifacts                 |
| Credential Access    | Adversary-in-the-middle, Brute force                      |
| Discovery            | Account discovery, Network sniffing                       |
| Lateral Movement     | Exploitation of remote services, Internal spearphishing   |
| Collection           | Archive collected data, Clipboard data                    |
| Command and Control  | Application layer protocol, Protocol tunneling            |
| Exfiltration         | Automated exfiltration, Exfiltration over physical medium |
| Impact               | Data encrypted, System shutdown                           |

## Case Studies

### The Colonial Pipeline Ransomware Attack

_Good password hygiene is important, and sharing password management improvements is a key part of the post-mortem stage of incident response._

### The Peloton Data Breach

_Check your API perms._
