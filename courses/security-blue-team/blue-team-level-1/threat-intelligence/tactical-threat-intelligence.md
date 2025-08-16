# Tactical Threat Intelligence

## Section Introduction

This section introduces tactical threat intelligence roles, focusing on daily analyst responsibilities like exposure checks, public assessments, and using actionable intelligence to strengthen defenses.

***

## Threat Exposure Checks Explained

A threat exposure check is the process of searching for indicators of compromise (IOCs) within an organization’s environment using tools such as SIEM or EDR. Analysts correlate intelligence from vendors, government alerts, partners, or OSINT sources to detect possible exposure. This tactical task requires technical expertise to interpret results and escalate findings for investigation.

***

## Watchlists/IOC Monitoring

IOC monitoring enables continuous detection of malicious activity by tracking indicators of compromise and precursors across an environment. Watchlists are commonly implemented within SIEM or EDR platforms, automating the process of searching for matches.

By creating watchlists, organizations ensure threat exposure checks run continuously without requiring analysts to perform manual searches. This automation alerts security teams in real time and allows threat intelligence analysts to focus on higher-value tasks.

***

## Public Exposure Checks Explained

Public exposure checks identify what information about an organization is publicly accessible online and assess how it could be exploited. This includes social media activity, exposed employee data, or leaked credentials. The goal is to reduce unintentional information disclosure that may assist attackers.

### Social Media Monitoring

#### Image Metadata

Photos taken in offices can expose sensitive details. Metadata may reveal device models, usernames, timestamps, and even GPS coordinates. Images may also unintentionally capture whiteboards, login details, or software in use, giving attackers valuable insight.

#### Leaked Information

Background details in photos or videos, such as documents, diagrams, or visible screens, can provide attackers with intelligence about systems, processes, or access credentials. Organizations often enforce social media policies to mitigate this risk.

#### Early Warning Signs of Insider Threats

Monitoring employee posts can provide indicators of potential insider threats. Negative or hostile statements online may warrant closer monitoring using forensic tools like DTEX to detect risks of sabotage, theft, or collusion with external actors.

#### Brand Abuse and Impersonation

Attackers can impersonate an organization online without needing to hijack accounts. Fake websites, apps, or social media profiles can damage reputation, defraud customers, and launch phishing campaigns. Such impersonation undermines customer trust and revenue.

### Data Breach Dumps

#### Employee Credentials

When company email addresses appear in breach dumps, attackers may attempt credential stuffing or phishing, especially if employees reuse passwords. Even unrelated breaches can put corporate accounts at risk.

#### Acquiring Data Breach Lists

Threat intelligence teams collect breach data from the clear web or infiltrate dark web marketplaces to identify exposed organizational accounts. Specialized vendors may purchase breach data and provide clients with only their relevant entries, reducing exposure.

***

## Threat Intelligence Platforms

Threat Intelligence Platforms (TIPs) centralize the collection, management, and use of cyber threat intelligence. They allow organizations to aggregate threat data, integrate it with defenses, and share intelligence across teams or with trusted partners.

### What are TIPs?

A TIP can be deployed as SaaS or on-premises to manage actors, campaigns, signatures, bulletins, and TTPs. Core functions include:

* Aggregating and normalizing intelligence from multiple sources.
* Integrating with firewalls, IPS, and other security tools.
* Enabling analysis and sharing of threat intelligence.

### Why Use a TIP?

TIPs provide a single repository for technical indicators and strategic intelligence. They benefit:

* **SOC Teams:** Automate routine tasks such as enrichment and scoring.
* **Threat Intelligence Teams:** Correlate actors, campaigns, and indicators for predictions.
* **Management:** Access centralized reporting at both technical and executive levels.

### Data Aggregation

TIPs reconcile and normalize threat data from multiple sources and formats.

* **Sources:** Open-source, paid vendors, government, ISACs, internal intelligence.
* **Formats:** STIX/TAXII, JSON, XML, email, .csv, .txt, PDF, Word.

### TIP Products

* [**MISP**](https://www.misp-project.org/)**:** Open-source, community-driven TIP with extensive sharing and automation features, used by thousands of organizations worldwide.
* [**ThreatConnect**](https://threatconnect.com/solution/threat-intelligence-platform/)**:** Automates collection from diverse sources and supports custom runbooks for analyst-driven response actions.
* [**Anomali**](https://www.anomali.com/)**:** Widely used by ISACs; allows organizations to build intelligence-sharing communities and extend functionality through an integration marketplace.
* [**ThreatQ**](https://www.threatq.com/threat-intelligence-platform/)**:** Threat-centric platform supporting prioritization, automation, and integration. Extends beyond a TIP into areas like vulnerability management, phishing defense, and threat hunting.

***

## Malware Information Sharing Platform (MISP)

The [**Malware Information Sharing Platform (MISP)**](https://www.misp-project.org/) is an open-source solution created by a volunteer community for collecting, storing, distributing, and sharing cybersecurity indicators. It supports incident analysts, security professionals, and malware researchers by enabling structured information sharing across organizations.

MISP fosters collaboration in the security and threat intelligence community by providing integrations with tools such as SIEMs, Network Intrusion Detection Systems (NIDS), and Host Intrusion Detection Systems (HIDS). Its open-source and free availability make it widely adopted for intelligence sharing.

### What Does MISP Do?

* Store technical and non-technical data about malware and incidents.
* Automatically build relationships between malware and attributes.
* Provide structured formats for automated use in security and forensic tools.
* Generate detection rules for NIDS (e.g., IPs, domains, hashes, memory patterns).
* Share malware and threat attributes with trusted groups and partners.
* Prevent duplicated work through shared detection and analysis.
* Build trust-based sharing communities with flexible distribution controls.
* Maintain local storage of external data for confidentiality.

### How Does MISP Work?

MISP can be accessed through a web interface for analysts or via a REST API for automated IOC exchange. Events and attributes can be shared at different levels:

* Private (organization only)
* Community only
* Connected communities
* Public (all communities)

Sector-specific sharing groups (e.g., financial industry) are also supported.

#### Core Functionalities

* **IOC Database:** Structured storage of malware samples, incidents, attackers, and intelligence.
* **Correlation Engine:** Identifies relationships between attributes, supporting fuzzy hashing (ssdeep), CIDR matching, and more. Correlation can be enabled or disabled per attribute.
* **Sharing:** Synchronizes data across MISP instances with flexible group-based or attribute-level distribution.
* **User Interface:** Allows analysts to create, update, and collaborate on events with graphical navigation, event graphs, advanced filters, and warning lists to reduce false positives.
* **Export Formats:** IDS rules, OpenIOC, CSV, JSON, STIX (v1 & v2), NIDS exports (Suricata, Snort, Zeek), RPZ zones, forensic cache formats, and more via misp-modules.
* **Import Formats:** Supports bulk or batch imports, OpenIOC, sandbox outputs, ThreatConnect CSV, MISP standard format, and STIX 1.1/2.0, extendable via misp-modules.

MISP’s extensive interoperability ensures that organizations can integrate shared intelligence into their detection, response, and forensic workflows.

***
