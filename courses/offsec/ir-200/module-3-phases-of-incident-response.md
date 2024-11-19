# Module 3: Phases of Incident Response

## The Preparation Stage

### Preparing for Incidents

_The CREST framework again, specifically the Preparation step._

### Preparation of Incident Response Plans

_Typical Incident Response Playbooks_

| Category                 | Playbook                                                                                                            |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------- |
| PB01 Scanning            | PB01.1 IP Address Scan, PB01.2 Port Scan                                                                            |
| PB02 Managed Threats     | PB02.1 Virus quarantine, PB02.2 Failed Login Attempts Detected, PB02.3 Known Exploit Detected                       |
| PB03 Intrusion           | PB03.1 Intrusion Indications Detected, PB03.2 Unprivileged Account Compromise, PB03.3 Unauthorized Privilege Escal$ |
| PB04 Availability        | PB04.1 Denial of Service (DOS/DDOS), PB04.2 Sabotage                                                                |
| PB05 Information         | PB05.1 Unauthorized Access to Information, PB05.2 Unauthorized Modification of Information, PB05.3 Data Breach $    |
| PB06 Fraud               | PB06.1 Unauthorized use of Resources, PB06.2 Copyright Infringement, PB06.3 Spoofing an Identity                    |
| PB07 Malicious Content   | PB07.1 Phishing Emails, PB07.2 Malicious Websites, PB07.3 Infected USB sticks                                       |
| PB08 Malware Detection   | PB08.1 Virus or Worm, PB08.2 Ransomware, PB08.3 APT                                                                 |
| PB09 Technical Integrity | PB09.1 Website defacement, PB09.2 DNS Redirection                                                                   |
| PB10 Theft               | PB10.1 Theft of Asset                                                                                               |

<figure><img src="../../../.gitbook/assets/image (8).png" alt=""><figcaption><p>Unauthorized Access (Detect) Playbook example</p></figcaption></figure>

A neat community development of Playbooks mapped to MTIRE techniques:

{% embed url="https://github.com/austinsonger/Incident-Playbook" %}

### Training Effective Incident Responders

* Formal/Tool-specific training.
* Active training with hands-on workshops and cyber drills
* Advanced training with red-blue cyber-range exercises
* Crisis exercises
* Cyber drills
* Cyber range exercises

## Managing an Incident Response

### Detect and Analyze Incidents

Signs of an incident fall into one of two categories: precursors and indicators.

* A _precursor_ is something that indicates an incident may happen in the future. An example would be logs showing that a port or web scanner has been used, which is a clear indicator that someone is seeking a vulnerability to exploit our systems. A new vulnerability in an established system is another example. We may also receive threat intelligence identifying a threat actor that is targeting our business sector.
* According to SP800-61, an Indicator of Compromise (IoC) is a sign that an incident may have occurred or is occurring now. We may also come across the term _Indicator of Attack_ (IoA), which indicates that an attack is taking place. We can use IoCs during incident response to determine the extent of an attack and to identify what data has been or is being breached. Examples include intrusion detection alerts, malware detection by antivirus software, unexpected changes to critical files, and multiple failed logins.

### Contain, Eradicate, and Recover from Incidents

_When an incident requires containment, it's important to do so before the attack becomes overwhelming. This may require making business impacting decisions, such as isolating a business system or terminating a customer connection._

## Post Response Activities

### Incident Post Mortem

<figure><img src="../../../.gitbook/assets/image (9).png" alt=""><figcaption><p>Security Incident Post Mortem Template</p></figcaption></figure>
