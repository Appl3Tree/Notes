# Correlation

## Introduction

Introduces SIEM correlation, normalization, and rulesets for detecting anomalies and generating alerts for analyst investigation.

***

## Normalization and Processing

Normalization reduces diverse log formats into common attributes like time, IP address, and operation. Categorization adds context by mapping events to system activity, authentication, or remote/local operations.

***

### Log Enrichment

Enrichment adds contextual data to logs, such as mapping an IP to a geographic location. This helps analysts investigate alerts, assess unusual activity, and build metrics more effectively.

***

### Log Indexing

Indexing shared attributes across large datasets enables faster searches. Instead of scanning all logs, indexed attributes make queries more efficient, especially over long time ranges.

***

### Log Storage

SIEM storage demands are large for enterprises. Options include on-premises servers or cloud solutions like AWS S3 or Hadoop. Teams must balance cost, scalability, and ease of use.

***

### Normalization

Vendors produce logs in unique formats. Normalization aligns attributes (e.g., mapping Cisco `src_ip` and Juniper `source_address` to `source_ip`) so SIEMs can process data consistently. This improves searches and cross-platform analysis.

***

## SIEM Rules

SIEM rules can be provider-supplied for generic detection or custom-built by defenders who understand normal activity. These rules are search queries against incoming or stored data. When a query matches, actions can be triggered, such as alerts, emails, or event recording. Queries can run continuously for real-time detection or on scheduled intervals.

***

### Examples of SIEM Rule Functionality

#### Authentication/Account Activity

* Failed logon attempts
* Login attempts to disabled accounts
* Use of privileged accounts (local/administrator/domain admin)
* Account SID changes (possible privilege escalation)

#### Process Execution

* Executions from unusual locations (temporary folders, browser caches)
* Suspicious process relationships (e.g., Word spawning CMD or PowerShell)
* Detection of known malicious file hashes (MD5, SHA1, SHA256)

#### Network Activity

* Port scans
* Service enumeration
* Host discovery

***

### False Positive Reduction and Tuning

False positives are non-malicious events that trigger alerts. For example, monitoring Windows Event ID 4625 (“account failed to log on”) will generate noise from simple mistyped passwords. Thresholds reduce noise by only alerting after multiple failures in a short timeframe (e.g., 10 failed logins within 10 minutes).

Exclusions also reduce false positives. For instance, a firewall scanning rule may detect legitimate vulnerability scanning as malicious. Excluding the scanner’s IP allows normal scans without alerting, while still monitoring the activity.

***

### Writing Search Queries and Alerts

In the next section, you will configure a local Splunk SIEM and practice writing search queries to analyze large datasets. These queries can then be converted into alerts. For additional insight, review [Elastic’s guide on detection rules](https://www.elastic.co/guide/en/security/current/rules-ui-create.html), which demonstrates similar rule logic for the ELK stack.

***

## Sigma

Sharing SIEM rules is valuable, but each platform uses its own format. Sigma provides a universal rule format, allowing teams to share detection logic across SIEMs.

***

### What is Sigma?

Sigma is an open, generic signature format for describing log events. Its rules are flexible, human-readable, and applicable to any log type. Using converters like **Sigmac**, rules can be translated into formats for different SIEMs, or reversed back to Sigma for sharing.

***

### Which Platforms Support Sigma?

* Splunk
* QRadar
* ArcSight
* Elasticsearch (Elastalert, Query strings, DSL, Watcher, Kibana)
* Logpoint

***

### Benefits of Using Sigma

* Share detection methods in a common format
* Avoid vendor lock-in by writing portable rules
* Publish Sigma signatures with research, IOCs, or YARA rules
* Share rules in threat intel communities (e.g., ISACs via MISP)

***

### SIGMA Rule Example

Below is a Sigma rule designed to detect web shells on compromised web servers:

```yaml
title: Webshell Detection  
id: b1234567-89ab-cdef-0123-456789abcdef  
status: experimental  
description: Detects suspicious web shell execution via unusual URL patterns  
logsource:  
    category: webserver  
detection:  
    keywords:  
        - '=whoami'  
        - '=net user'  
        - '=ipconfig'  
    condition: keywords  
falsepositives:  
    - Testing or administrative requests including these strings  
level: high  
```

If a web shell is hosted on `https://example.com/.../shell.php?` and a request includes `=whoami`, the SIEM generates an alert. Normal users rarely include OS commands in GET requests, so false positives are low, though some exceptions are documented.

***

### Further Resources

Explore real-world Sigma rules on [Florian Roth’s repository](https://github.com/Neo23x0/sigma) and the [official SigmaHQ rules library](https://github.com/SigmaHQ/sigma/tree/master/rules).

***
