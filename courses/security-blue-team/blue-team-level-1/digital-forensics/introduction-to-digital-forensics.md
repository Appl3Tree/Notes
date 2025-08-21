# Introduction to Digital Forensics

## Section Introduction

This section introduces the fundamentals of digital forensics, including its definition, scope, and the structured process used to conduct forensic investigations.

***

## What is Digital Forensics?

Digital forensics involves collecting, analyzing, and preserving digital evidence, often for use in legal proceedings. While traditionally associated with law enforcement seizing computer equipment, it is also a critical skillset for security teams. When combined with incident response to investigate and preserve evidence during security incidents, the practice is referred to as DFIR. This domain explores forensic investigation processes, evidence sources from Windows and Linux systems, and hands-on use of real-world forensic tools in practical scenarios.

***

## Digital Forensics Process

The digital forensics process is a structured scientific approach used in investigations, primarily by law enforcement, but also applied in DFIR activities. It is widely used in computer and mobile device forensics and consists of five main stages: Identification, Preservation, Collection, Analysis, and Reporting. Digital media seized for examination is referred to as an “exhibit,” and investigators apply the scientific method to validate or refute a hypothesis in legal or civil proceedings.

### Process Steps

#### Identification

Potential sources of evidence are located, such as devices, data locations, or custodians, to determine what may be relevant to the investigation.

#### Preservation

Evidence is secured to prevent alteration or loss. This includes protecting the scene, capturing images, and documenting details of the evidence and acquisition methods.

#### Collection

Relevant digital information is gathered, often involving the removal of devices from the scene and imaging or copying their contents for examination.

#### Analysis

Collected data is systematically examined to identify evidence, such as system or user files. The goal is to establish conclusions based on the discovered evidence.

#### Reporting

Findings are presented using recognized forensic techniques, ensuring results are reproducible by other competent forensic examiners.

### Supporting Practices

Contemporaneous notetaking is essential throughout the first four stages, requiring immediate, detailed documentation of actions taken so another examiner could reproduce them. The chain of custody must also be maintained at all times to protect evidence integrity.

***

## Further Reading Material, Digital Forensics

This lesson provides additional resources to help strengthen understanding of digital forensics concepts and prepare for the BTL1 practical exam. Students are encouraged to revisit these materials after completing the domain.

### Resources

* [Digital Forensics Resources by Forensic Focus](https://www.forensicfocus.com/articles/digital-forensics-resources/)
* [Top Online Digital Computer Forensics Resources by InfoSec Institute](https://www.infosecinstitute.com/resources/digital-forensics/)
* [Digital Forensics: Tools & Resources by Study.com](https://study.com/academy/lesson/digital-forensics-tools-resources.html)
* [Digital Forensics Cheat Sheet by Tech Republic](https://www.techrepublic.com/article/digital-forensics-the-smart-persons-guide/)
* [A Guide to Digital Forensics and Cybersecurity Tools (2020) by Forensics Colleges](https://www.forensicscolleges.com/blog/resources/guide-digital-forensics-tools)
* [Free Course, Digital Forensics by OpenLearn](https://www.open.edu/openlearn/science-maths-technology/digital-forensics/content-section-0?active-tab=description-tab)

***

## Digital Forensics Glossary

This glossary covers key acronyms and terms used in the Digital Forensics domain of the Blue Team Level 1 course. It is TLP:White and may be freely shared.

### Key Terms

**IOC (Indicator of Compromise)** – Intelligence gathered from malicious activity, such as malware, with details like file hashes that can be shared for threat detection.

**TTP (Tools, Techniques, and Procedures)** – Standardized adversary tactics documented by [MITRE ATT\&CK](https://attack.mitre.org/), with over 240 unique techniques linked to known threat actors.

**PCAP (Packet Capture)** – A file containing captured network traffic, viewable in tools such as [Wireshark](https://www.wireshark.org/) or TCPDump for analysis.

**HDD (Hard Disk Drive)** – A storage device using rotating magnetic platters for data read/write operations.

**SSD (Solid State Disk Drive)** – A flash-memory–based storage device with faster performance compared to HDDs.

**USB Drive (Universal Serial Bus Drive)** – A portable flash storage device for transferring files between systems.

**ACPO (Association of Chief Police Officers)** – Provides guidelines for handling computer-based evidence to ensure admissibility in court.

**KAPE (Kroll Artifact Parser and Extractor)** – A tool for rapid acquisition of forensic evidence, allowing targeted collection of artifacts.

**FTK Imager (Forensic Tool Kit Imager)** – A free tool for creating bit-by-bit disk images, mounting them read-only, and performing analysis.

**Write-Blocker** – A hardware or software device that prevents writes to evidence media, ensuring data integrity during forensic imaging.

**BHC (Browser History Capturer)** – A tool for collecting web browser data files for manual review or analysis in Browser History Viewer.

**BHV (Browser History Viewer)** – A tool for analyzing collected browser data, including history, cached images, and web content.

**/etc/passwd (Linux Passwd File)** – Stores user account information on Linux systems, including service and user-created accounts.

**/etc/shadow (Linux Shadow File)** – Stores encrypted passwords for accounts on a Linux system, used alongside `/etc/passwd` for password cracking.

***
