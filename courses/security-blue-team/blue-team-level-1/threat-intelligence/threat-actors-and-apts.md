# Threat Actors and APTs

## Section Introduction

Malicious actors are individuals or groups that conduct cyberattacks, driven by specific motivations, naming conventions, and chosen targets.

***

## Common Threat Agents

### What are Threats?

A threat is a danger that exploits a vulnerability, potentially causing a breach or impact. For example, a malicious user exploiting poor input validation with SQL injection can steal database credentials.

* Vulnerability: Lack of input validation
* Threat: Malicious SQL query
* Result: Data exfiltration

### What are Threat Actors?

A threat actor (or agent) is an individual or group that causes harm, intentionally or unintentionally. Cybercrime syndicates exploiting vulnerabilities for data theft represent intentional actors, while employees making mistakes without training can become unintentional actors.

* Threat Actor: Cybercrime syndicate or employee
* Threat Type: Intentional (malicious) or Unintentional (accidental)

### Actor Categorization

Threat actors are generally grouped into four categories:

#### Cyber Criminals

Motivated by financial gain, conducting attacks such as phishing, ransomware, or fraud. Includes both skilled hackers and inexperienced “script kiddies.”

#### Nation-States

Highly resourced adversaries backed by governments, often conducting covert, long-term operations. Known as Advanced Persistent Threats (APTs).

#### Hacktivists

Motivated by political or social causes, often using DDoS attacks or website defacements to spread messages.

#### Insider Threats

Individuals abusing insider knowledge, intentionally or accidentally. May involve disgruntled employees leaking data or mistakes like sending sensitive documents to the wrong recipient.

### Real-World Threat Actors

#### Nation-State – APT29 (Cozy Bear)

A Russian-linked group using advanced malware and spear-phishing campaigns. Known for the 2015 Pentagon spear-phishing incident and long-term targeting of diplomatic organizations.

#### Hacktivists – Anonymous

A well-known hacktivist collective conducting politically motivated attacks. In 2012, they launched “Operation Megaupload,” targeting U.S. government sites with DDoS attacks in protest of legislation and site shutdowns.

***

## Motivations

### Financial Motives

Money is a primary driver for many cyberattacks, affecting individuals, cybercrime groups, and even governments.

* **Individual motives:** Disgruntled employees may steal or sell company data for profit, engaging in corporate espionage.
* **Cybercrime motives:** Groups profit from ransomware, credential theft, banking trojans, and cryptocurrency mining. Ransomware alone caused billions in damages worldwide, with ransom demands and recovery costs steadily rising.
* **Government motives:** Nation-state groups such as Lazarus Group use financially focused teams like BlueNorOff to hack banks and convert stolen money into cryptocurrency to bypass economic sanctions.

### Political Motives

Nation-states and politically motivated groups often conduct cyberattacks for strategic or ideological purposes.

* Nation-state operations focus on espionage, disruption, and strategic advantage. Stuxnet, for example, targeted Iran’s nuclear program using multiple zero-day exploits.
* Hacktivists deface websites or launch DDoS attacks to make political statements or protest policies.
* Disinformation campaigns use fake accounts, bots, and targeted advertising to influence public opinion, especially around elections.

### Social Motives

Some attackers are motivated by reputation, recognition, or self-expression.

* **Script kiddies:** Often seek notoriety, using prebuilt tools or DDoS-as-a-service platforms to show off without technical expertise.
* **Reputation-driven hackers:** Groups like Lizard Squad gained attention by disrupting gaming networks and boasting on social media to grow their following.

### Unknown Motives

Not all cyberattacks reveal clear intent. When motives are unclear, attribution becomes difficult, and links to known groups may only emerge after further evidence and analysis.

***

## Actor Naming Conventions

Different security vendors use their own naming systems for tracking threat actors, which often leads to confusion. Groups may be known by multiple names depending on the vendor, and overlaps occur because actors share tools, copy tactics, and use foreign infrastructure to mislead researchers. Two major naming systems are used by CrowdStrike and FireEye/Mandiant.

### CrowdStrike

CrowdStrike categorizes nation-state actors by assigning animals linked to their country of origin. Non-nation-state groups are categorized by intent.

#### Nation-State-Based Adversaries

* **Bear = Russia** (e.g., Fancy Bear)
* **Buffalo = Vietnam**
* **Chollima = North Korea** (e.g., Stardust Chollima)
* **Crane = South Korea**
* **Kitten = Iran** (e.g., Refined Kitten)
* **Leopard = Pakistan** (e.g., Mythic Leopard)
* **Panda = China** (e.g., Goblin Panda)
* **Tiger = India** (e.g., Viceroy Tiger)

#### Non-Nation-State Adversaries

* **Jackal = Hacktivist groups** (e.g., Syrian Electronic Army)
* **Spider = Criminal groups** (e.g., Mummy Spider behind Emotet malware campaigns)

### FireEye/Mandiant

Mandiant uses a numbering system for clarity, with prefixes that indicate group type.

#### Nation-State-Based Adversaries

* **China:** APT1, APT2, APT3, APT10, APT19, APT20, APT30, APT40, APT41
* **Iran:** APT33, APT34, APT35, APT39
* **North Korea:** APT37, APT38
* **Russia:** APT28, APT29
* **Vietnam:** APT32

#### Financially-Motivated Cybercrime Groups

Use the prefix **FIN** to indicate financial motives.\
Examples: FIN4, FIN5, FIN6, FIN7, FIN8, FIN10.

* **FIN7** is notable for targeting U.S. retail, restaurant, and hospitality industries, using point-of-sale malware to steal funds.

#### Unclassified Groups

Labeled as **UNC** (Unclassified) when attribution, motives, or country of origin are unclear.

***

## What Are APTs?

Advanced Persistent Threats (APTs) are state-backed or highly resourced attacker groups known for long-term, targeted campaigns using advanced tools, exploits, and custom malware. They focus on espionage, disruption, or financial damage against governments, institutions, and large organizations.

### Real-World APTs

#### APT28 (Fancy Bear)

A Russian nation-state group specializing in politically motivated espionage. Targets include governments, militaries, and security organizations. Notable for interfering with the 2016 U.S. presidential election and campaigns in Eastern Europe.

#### Cobalt Group (Gold Kingswood)

A financially motivated group targeting banks, ATMs, and payment systems, primarily in Eastern Europe and Russia. Known for spear-phishing campaigns and the malware **SpicyOmelette**, enabling persistence, reconnaissance, and privilege escalation. Responsible for over €1 billion in losses across 40+ countries.

#### APT32

Believed to be Vietnam-based, active since 2014. Targets private sector industries, governments, journalists, and dissidents, with a focus on Southeast Asia. Known for using strategic web compromises to infect victims.

### What Makes APTs Special?

* **Resources:** Backed by nation-states, with vastly more funding and expertise than smaller groups.
* **Targets:** Focus on financial, political, or military organizations.
* **Tools:** Develop custom malware, frameworks, and zero-day exploits instead of relying on public tools.
* **Persistence:** Maintain long-term access to networks for surveillance, espionage, or disruption.

***

## Tools, Techniques, Procedures

Also referred to as **Tactics, Techniques, and Procedures (TTPs)**, these describe the methods threat actors use during cyberattacks. Defenders analyze TTPs to understand attacker behavior, track group activity, and design defensive measures.

The [MITRE ATT\&CK Framework](https://attack.mitre.org/) documents over 260 techniques across 12 categories:

* Initial Access
* Execution
* Persistence
* Privilege Escalation
* Defense Evasion
* Credential Access
* Discovery
* Lateral Movement
* Collection
* Command and Control
* Exfiltration
* Impact

### Proactive Defense

Security teams can strengthen defenses by proactively testing controls against known TTPs. This may include:

* Reviewing MITRE’s documented attack paths for relevant adversaries.
* Conducting penetration tests to simulate specific TTPs.
* Validating that security controls and monitoring systems detect or block these techniques.

For example, if an organization identifies APT30 as a likely threat, it can review APT30’s documented TTPs and ensure defenses cover those methods before an attack occurs.

***

