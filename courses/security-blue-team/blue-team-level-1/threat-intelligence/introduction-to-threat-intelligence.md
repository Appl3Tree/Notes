# Introduction to Threat Intelligence

## Section Introduction

Focuses on malicious actors, indicators of compromise, global malware campaigns, and intelligence sharing to support security operations and risk management.

***

## Threat Intelligence Explained

Threat intelligence is information organizations use to understand existing or potential threats, helping security teams strengthen defenses, reduce risk, and monitor networks for compromise. It addresses sophisticated threats like APTs, zero-day vulnerabilities, and global malware campaigns, providing insight into who may attack, their motives, and methods. Intelligence is often shared as indicators of compromise (IOCs) such as malicious email addresses, IPs, or file-based artifacts like malware names and hashes.

***

### Threat Intelligence Lifecycle

Threat intelligence transforms raw data into actionable insights through a structured lifecycle.

#### Planning & Direction

Define project scope, goals, and stakeholders to avoid wasted resources. Example: after intelligence reveals a foreign hacking group’s plans, teams may research the group, assess organizational attack surface, and determine defensive actions.

#### Collection

Gather relevant data such as underground forum posts, OSINT details, and other sources. Mature teams use centralized threat intelligence platforms like [MISP](https://www.misp-project.org/) to store IOCs from public and private feeds.

#### Processing

Convert raw data into usable formats, such as translating foreign-language posts, so analysts can accurately assess the information.

#### Analysis

Turn processed information into actionable intelligence. Recommendations vary depending on whether the audience is technical (security analysts) or strategic (executive leadership), requiring tailored presentation styles.

#### Dissemination

Deliver intelligence to the correct audience—SOC, analysts, or executives. Ensure it is understandable, actionable, and updated at appropriate intervals using the right communication channels.

#### Feedback

Continuous feedback ensures intelligence priorities align with consumer needs, guiding what data to collect, how to process and enrich it, how to analyze, and how quickly to disseminate.

***

### Threat Intelligence Analysts

Analysts specialize in critical thinking, evidence-based investigation, and creative problem-solving. They identify and track malicious actors, research tactics and techniques, and anticipate attacks. Their work maps adversary behavior to models such as the Cyber Kill Chain, MITRE ATT\&CK, and the Pyramid of Pain. Analysts often come from diverse backgrounds, including law enforcement and military roles, bringing investigative skills that enhance intelligence work.

***

## Types of Intelligence

Effective defense requires detailed knowledge of threats, refined into usable intelligence for continuous operations. The four primary types are SIGINT, OSINT, HUMINT, and GEOINT.

***

### SIGINT

Signal intelligence is gathered through intercepting radio signals and broadcasts, originating as early as World War I. Sources include communication systems, weapon systems, and radar.

* **COMINT**: Communications intelligence from conversations, messages, and voice traffic, often equated with SIGINT though it is a subset.
* **ELINT**: Electronic intelligence from non-communication systems like radar or missile guidance.

SIGINT is commonly used in electronic warfare, including surveillance drones, UAVs, and foreign government communications interception.

***

### OSINT

Open-source intelligence is collected from publicly available sources. Examples include driving records, phone numbers, addresses, social media, email addresses, and domain names. While defenders use OSINT to detect, track, or stop threats, adversaries also exploit it for planning attacks.

***

### HUMINT

Human intelligence is derived directly from people. It requires understanding human behavior and is obtained through meetings, debriefings, observation, document collection, espionage, or diplomatic communications.

***

### GEOINT

Geospatial intelligence relies on imagery and mapping to provide situational awareness. Satellite imaging identifies terrain, structures, and troop movements, supporting military planning, disaster response, and political crisis management by guiding deployments and aid.

***

## Types of Threat Intelligence

Threat intelligence is divided into three primary disciplines: strategic, operational, and tactical, each serving different audiences and purposes.

***

### Strategic Threat Intelligence

High-level, non-technical intelligence for executives and decision-makers. It informs budget allocation, policy development, and organizational strategy. Examples include linking global events to cyber activity, reporting attack patterns over time, or tracking industry-specific threats. Strategic analysts often focus on geopolitical and industry trends to anticipate risks.

***

### Operational Threat Intelligence

Focused on understanding threat actors, their motives, and their tactics, techniques, and procedures (TTPs). This intelligence is technical and analyst-driven, supporting defenses against specific adversaries and long-term campaigns. It requires ongoing human research and monitoring, rather than automation.

***

### Tactical Threat Intelligence

Technical intelligence of immediate value, usually in the form of indicators of compromise (IOCs) like URLs, IPs, file hashes, and domains. It enables detection and blocking of malicious activity, either manually by analysts or automatically through security tools and threat feeds. Examples include updated lists of phishing addresses, malicious IP feeds, or reports on zero-day exploitation activity.

***

## Why Threat Intelligence Can be Useful

Threat intelligence provides organizations with context, prioritization, enrichment, and collaboration opportunities that strengthen defenses and improve response decisions.

***

### Cyber Threat Context

A dedicated threat intelligence function enables in-depth research into adversaries, their history, and targeting patterns. This context helps vulnerability management teams prioritize patching and reduce the attack surface with proactive measures.

***

### Incident Prioritization

When multiple incidents occur, intelligence-driven context helps responders allocate resources to the incident with the highest potential impact. Knowledge of known threat actors and IOCs supports informed prioritization.

***

### Investigation Enrichment

Threat intelligence enhances investigations by providing background on suspicious activity. For example, scanning IPs may be routine, but if linked to a known APT group, the event demands deeper analysis and investigation.

***

### Information Sharing

Collaboration with analysts in other organizations strengthens defenses through shared knowledge, early warnings, and IOCs. This exchange supports proactive defense and helps prevent attacks before they begin.

***

## The Future of Threat Intelligence

Threat intelligence continues to evolve, with advances like predictive prioritization reshaping vulnerability management and risk-based decision making.

***

### CVEs and CVSS Scores

**CVEs (Common Vulnerabilities and Exposures):** Unique identifiers for publicly reported vulnerabilities. Each entry includes details about the issue, affected products, and remediation guidance. For example, CVE-2019-0708 was a critical RDP flaw in Windows. Databases such as the [National Vulnerability Database](https://nvd.nist.gov/) and [CVE Details](https://www.cvedetails.com/) provide searchable repositories of CVEs.

**CVSS (Common Vulnerability Scoring System):** A framework for rating vulnerability severity. Scores range from low to critical, offering a quick snapshot of risk. For example, a score of 8.8 HIGH indicates significant impact. However, scores are generalized and may not reflect real-world risk for a specific organization.

***

### Vulnerability Context

CVSS ratings alone may not represent true organizational risk. A critical score might not matter if the affected technology is unused. Conversely, a lower-rated issue could pose higher danger if it is widely exploited in the wild. Effective prioritization requires context, considering both the organization’s environment and active exploitation trends.

***

### Predictive Prioritization

Tenable’s predictive prioritization approach integrates vulnerability data with threat intelligence to rank issues by likelihood of exploitation. The system uses **Vulnerability Priority Rating (VPR)**, a dynamic score updated as threat intelligence evolves. If a vulnerability begins to see real-world exploitation, its VPR increases, signaling higher remediation urgency. This model enables teams to patch vulnerabilities with the most immediate defensive impact, shifting focus from theoretical severity to practical risk.

***
