# Strategic Threat Intelligence

## Section Introduction

This section introduces strategic threat intelligence roles, focusing on sharing actionable intelligence, monitoring geopolitical activity, and supporting defenders with global context on malicious actor campaigns.

***

## Intelligence Sharing and Partnerships

Organizations with established threat intelligence teams often participate in **Information Sharing and Analysis Centers (ISACs)**, which are typically industry-specific groups formed to share actionable intelligence such as IOCs, precursors, and threat reports.

For example, aviation companies can form a partnership through an Aviation ISAC, sharing intelligence about cyberattacks targeting their industry. If one member suffers an attack, it can share details so others can take preventive measures. The effectiveness of ISACs depends on active participation, regular intelligence sharing, and collaboration through meetings or reports.

Strategic intelligence analysts often manage these partnerships, building relationships not only with ISACs but also with government agencies and industry peers. This ensures organizations receive valuable intelligence that strengthens defenses and prepares teams for emerging campaigns.

Examples include:

* [**Aviation ISAC**](https://www.a-isac.com/)**:** Focused on threats to the aviation sector.
* [**National Council of ISACs**](https://www.nationalisacs.org/member-isacs)**:** A directory of ISACs across multiple industries.

***

## IOC/TTP Gathering and Distribution

Strategic threat intelligence analysts are well-positioned to collect and distribute indicators of compromise (IOCs) and tactics, techniques, and procedures (TTPs). Their frequent contact with information-sharing partners and government bodies such as NCCIC, US-CERT, and NCSC ensures they receive timely intelligence.

Collection efforts focus on relevant threats—analysts prioritize IOCs associated with actors likely to target their industry rather than gathering indiscriminately. This prevents overwhelming defenders with irrelevant alerts or false positives.

Once gathered, IOCs are passed to tactical threat intelligence analysts or the broader security team for operational use, enabling monitoring, exposure checks, and defensive action.

***

## OSINT vs Paid-for Sources

Organizations can acquire threat intelligence through **open-source intelligence (OSINT)** or **vendor-provided feeds**, each with strengths and limitations. The right choice depends on organizational needs, maturity, and budget.

### Open-Source Intelligence

OSINT offers free resources that provide useful indicators and context but require careful validation to ensure accuracy and relevance. It is ideal for smaller organizations or those starting to build a threat intelligence capability, as well as independent researchers.

Examples of free OSINT sources include:

* [Spamhaus](https://www.spamhaus.org/)
* [URLhaus](https://urlhaus.abuse.ch/)
* [AlienVault Open Threat Exchange](https://otx.alienvault.com/)
* [VirusShare](https://virusshare.com/)
* [ThreatFeeds.io](https://threatfeeds.io/)
* [Anomali Weekly Threat Briefing](https://www.anomali.com/resources/weekly-threat-briefing)
* [CISA Automated Indicator Sharing](https://www.cisa.gov/ais)
* [SANS Internet Storm Center](https://isc.sans.edu/)
* [Talos Intelligence (Free Version)](https://talosintelligence.com/)

### Paid-for Intelligence

Vendor-provided intelligence is often tailored, enriched, and delivered with higher confidence but can be costly. Typically, large enterprises with dedicated intelligence teams benefit most. Before purchasing, organizations should assess what type of intelligence is relevant to their sector to avoid overspending.

Notable paid vendors include:

* [FireEye](https://www.fireeye.com/)
* [Recorded Future](https://www.recordedfuture.com/)
* [CrowdStrike](https://www.crowdstrike.com/)
* [Flashpoint](https://www.flashpoint-intel.com/)
* [Intel471](https://intel471.com/)

***

## Traffic Light Protocol

The **Traffic Light Protocol (TLP)** is a system for classifying how sensitive information should be shared. Originally created in the early 2000s by the UK’s National Infrastructure Security Coordination Centre, it is now widely adopted in cybersecurity to regulate the distribution of threat intelligence and security reports. The system ensures that recipients respect the author’s intended level of information sharing, making trust essential.

### TLP Classifications

#### TLP Clear

Information can be freely shared with the public, though copyright rules still apply.\
**Example:** [CISA](https://www.cisa.gov/) publishes TLP:WHITE malware analysis reports and IOCs for open distribution.

#### TLP Green

Information may be shared within trusted communities such as ISACs, but not beyond them.\
**Example:** An aviation ISAC shares IOCs from an APT33 attack among member organizations, but the details remain internal to the ISAC.

#### TLP Amber

Information may only be shared internally on a need-to-know basis or with clients, as it contains sensitive details.\
**Example:** Penetration test reports or vulnerability scans are typically TLP:AMBER to prevent attackers from misusing them if leaked.

#### TLP Amber Strict

A stricter version of TLP:AMBER, limiting sharing strictly within the organization.\
**Example:** A security firm’s report on a newly discovered APT malware is restricted to internal staff only until defensive measures are prepared.

#### TLP Red

The most restrictive level. Information is only for those present in a meeting or listed as recipients in direct communication.\
**Example:** A meeting about an adversary with Domain Administrator privileges is marked TLP:RED to prevent tipping off the attacker.

***

## Permissible Action Protocol

The **Permissible Action Protocol (PAP)**, first introduced in 2016 under the guidance of the [MISP](https://www.misp-project.org/) project, classifies what defensive actions are permissible when handling threat intelligence. While **TLP** defines how information can be shared, PAP regulates the types of actions organizations may take, ensuring sensitive data handling does not expose defenses or alert adversaries. PAP uses a color-coded tier system similar to TLP.

### PAP Classifications

#### PAP Clear

Actions are unrestricted and can be carried out freely, provided they comply with legal and licensing requirements. Data may be handled and shared without significant constraints.

#### PAP Green

Permits controlled, non-intrusive defensive actions.\
**Example:** Blocking inbound threats at the firewall or stopping outbound malicious traffic via a proxy server, especially when linked to known malicious IPs or domains.

#### PAP Amber

Restricts activities to passive data handling, avoiding actions that could alert adversaries.\
**Example:** Using open-source repositories or online platforms to enrich IOCs during an investigation. Direct or indirect communication with threat actors is forbidden at this level.

#### PAP Red

Reserved for detection and investigation activities only, under strict “need-to-know” controls. Infrastructure is isolated from production systems to protect integrity. Actions must remain invisible to adversaries.\
**Example:** Threat hunting or incident response within segregated environments, using logged data to search for evidence of compromise without interacting with live adversary infrastructure.

***
