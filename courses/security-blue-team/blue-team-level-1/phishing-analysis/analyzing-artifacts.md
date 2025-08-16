# Analyzing Artifacts

## Section Introduction

Section covers analyzing email, web, and file artifacts to confirm if emails are malicious and extract useful defensive information.

***

## Visualization Tools

Covers tools that let analysts view malicious URLs safely without visiting them directly. Focus is on URL2PNG and URLScan for generating webpage screenshots.

### URL2PNG

Simple tool: input a URL, receive a screenshot of the page. Useful for quickly checking phishing sites like credential harvesters.

### URLScan

Provides rich URL analysis including a screenshot of the destination page. Helps identify phishing pages, such as fake Outlook Web Apps.

***

## URL Reputation Tools

Focuses on checking potentially malicious URLs using reputation services and threat feeds. Main tools: VirusTotal, URLScan.io, URLhaus, and PhishTank. Key reminder: absence of detections does not mean safe; assume malicious until proven safe.

### VirusTotal

Web-based service for URL scanning.

* Use **URL tab** to submit a link.
* Returns detection results from multiple vendors (e.g., Kaspersky, ESET, Fortinet).

### URLScan

Provides extensive URL intelligence:

* Reputation score, screenshot, web technologies, domain & IP data.
* Useful for in-depth investigation; for quick checks, visualization with URL2PNG may suffice.

### Threat Feeds

Public intelligence sources for phishing/malware URLs:

* **URLhaus**: Database of reported malicious URLs, tags for malware families, availability status, reporter info. Feeds can power blacklists for email security.
* **PhishTank**: Community-driven repository of phishing URLs, verified by users, similar interface to URLhaus.

***

## File Reputation Tools

Covers online services to check reputation of suspicious attachments or their hashes. Tools highlighted: [VirusTotal](https://www.virustotal.com/) and [Cisco Talos File Reputation](https://www.talosintelligence.com/talos_file_reputation). Key reminder: absence of detections ≠ safe — always assume malicious until proven otherwise.

### VirusTotal

* Upload files, URLs, IPs, or domains for vendor-based detection results
* File upload shows details such as detection ratio, file size, and type
* Even if not flagged, files can still be malicious; further analysis is required

### Talos File Reputation

* Cisco service to check SHA256 hashes against its database (AMP, FirePower, ClamAV, Snort)
* Supports searching by hash to determine malicious classification
* Provides file size, type, detection names, and aliases

***

## Malware Sandboxing

Sandboxing executes malware in a controlled environment to observe behavior and gather indicators of compromise (IOCs). This helps detect actions like C2 communication, module downloads, or persistence mechanisms, enabling defenders to build detection strategies. While enterprises use advanced sandboxing tools, this lesson focuses on using the free [Hybrid Analysis](https://www.hybrid-analysis.com/) platform.

### Hybrid Analysis

* Online service for malware analysis with instant cloud-based reports
* Supports file upload via drag-and-drop or browsing
* Allows selection of target operating system for detonation (default: Windows VM)
* Generates public reports showing observed activity and file behavior

### Analysis Results

* Provides detailed reports on malware activity, reputation, and indicators
* Example analysis available through Hybrid Analysis public report link

***

## Automated Artifact Analysis

[PhishTool](https://phishtool.com/) provides an analysis console that streamlines investigations by integrating checks for file and web artifacts, including WHOIS lookups, [VirusTotal](https://www.virustotal.com/) queries, and URL visualization with [URL2PNG](https://www.url2png.com/). This centralizes tasks, saving time during phishing analysis.

### File Artifact Analysis

* Automatically extracts filenames and MD5 hashes from attachments
* One-click option to submit hashes to VirusTotal for reputation checking
* Opens results in a new browser tab for quick review

### Web Artifact Analysis

* Generates live screenshots of URLs
* Displays HTTP requests and headers associated with the site
* Provides integrated WHOIS lookups showing domain age, registrar, hosting, and contact details

***
