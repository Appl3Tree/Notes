# Lessons Learned and Reporting

## Section Introduction

This section reviews completed incidents to identify strengths, weaknesses, and improvements for security controls and response processes.

***

## What Went Well?

Reflection should include recognition of successful actions taken during the incident. Acknowledging team performance helps reinforce effective practices, prevents burnout, and supports morale.

After recovery, stakeholders should meet to review the incident comprehensively. Key discussion points include:

* Which individuals or teams performed well.
* Whether new tools or processes proved beneficial.
* Metrics collected during the incident.
* Effectiveness of communication between departments.

Documenting these strengths in run-books ensures successful approaches can be reused in future incidents.

***

## What Could be Improved?

Analyzing weaknesses in incident response helps organizations prepare more effectively, reduce potential damage, and minimize business disruption in future incidents.

During the post-incident meeting, stakeholders should carefully evaluate shortcomings. Examples include mishandled evidence collection, insufficient resources such as laptops or storage media, or delays caused by unclear responsibilities. Key questions to guide reflection are:

* What limitations existed with tooling?
* What limitations existed with procedures and guidelines?
* Did any individuals or departments hinder the response, and how?
* How was each stage of the NIST Incident Response Lifecycle impacted by weaknesses in resources, personnel, or documentation?

Once weaknesses are identified, corrective actions must be taken. Issues should be addressed through:

* Increased budget for security staff such as forensic analysts, incident responders, and incident commanders.
* Additional personnel in supporting departments including legal, public relations, communications, and human resources.
* Investment in improved tools to support response activities.
* Review and update of documentation, run-books, policies, and procedures.

These measures ensure that weaknesses are resolved rather than repeatedly noted without action.

***

## Importance of Documentation

Accurate and detailed documentation ensures future incidents can be managed more efficiently by providing reference material, structured guidance, and lessons learned. After an incident, the following records should be updated as appropriate:

**Incident Response Case Notes**\
Investigation notes within platforms such as ServiceNow or IBM Resilient should be fully completed. This includes artifacts (file names, hashes, IP addresses, domain names), attachments (emails, malicious files, log files), and records from all stages of the incident response lifecycle.

**Incident Response Plan (IRP)**\
The IRP should be revised if improvements to the overall process are identified. Updates may include changes in team composition, secure communication methods, or contact information for stakeholders.

**Incident Run-Books**\
Run-books for the relevant incident type should be reviewed and expanded. Detailed step-by-step instructions help ensure structured and consistent responses in the future. A useful [collection of example incident response playbooks](https://medium.com/@inginformatico/compilation-of-web-page-links-that-show-lists-of-incident-response-playbooks-eng-c66714602222) can serve as reference material.

**Organization Policies**\
Weaknesses in policy should be corrected to prevent repeat incidents. For example, restricting unauthorized software downloads, requiring patch management for internet-facing systems, or enforcing vulnerability management responsibilities. Policy updates establish accountability and strengthen prevention measures.

***

## Incident Response Metrics

Metrics provide quantitative measurements that allow teams to assess efficiency, identify weaknesses, and track incident trends. They also support business cases for additional budget, staffing, or improved tooling. Different organizations may prioritize different metrics, but common categories include:

### **Impact Metrics**

* **Service Level Agreement (SLA):** Formal agreement defining expectations such as uptime or responsiveness, typically measured in percentages (e.g., 99%, 99.9%).
* **Service Level Objective (SLO):** Specific targets within the SLA, such as uptime for a critical system, which hold both parties accountable if not met.
* **Escalation Rate:** Frequency of correct alert assignment within the SIEM. High escalation accuracy ensures complex cases reach experienced analysts quickly.

### **Time-Based Metrics**

* **Mean Time to Detect (MTTD) / Mean Time to Acknowledge (MTTA):** Average time to notice and confirm an incident. Tracking helps validate SIEM alert effectiveness.
* **Mean Time to Response (MTTR):** Time between detection and initiating corrective action. A core measure of response efficiency.
* **Incidents Over Time:** Tracks whether incident volume is rising or falling across periods, highlighting effectiveness of preventive measures.
* **Remediation Time:** Duration required to fully recover affected systems and restore business operations.

### **Incident Type Metrics**

* **Cumulative Number of Incidents per Type:** Categorizes incidents to identify recurring problem areas (e.g., vulnerabilities in internet-facing systems).
* **Alerts Created per Incident:** Evaluates how many alerts were generated and which detection layers triggered them, revealing coverage gaps in the defensive stack.
* **Cost per Incident (CPI):** Calculates financial impact, factoring in staff time, lost productivity, revenue loss, or damage. More accurate when paired with a business impact analysis (BIA).

***

## Reporting Format

There is no universal template for incident reports, as requirements differ across organizations. However, four sections are commonly included:

### Executive Summary

A high-level overview written in non-technical terms for business leaders. It should fit on one page, highlight financial costs, risks, and damages prevented, and emphasize how the security team’s actions reduced impact. This section demonstrates the value of maintaining or expanding the security program.

### Incident Timeline

A chronological list of events with dates, times, and concise descriptions. It may be ordered by discovery or by actual sequence of events. Teams often use local time for single-location incidents, or Universal Time Coordinated (UTC) for incidents spanning multiple regions, ensuring consistency and clarity.

### Incident Investigation

The main body of the report, documenting step-by-step actions and findings throughout the incident response lifecycle (excluding preparation).

* **Detection and Analysis:** How was the incident identified (SIEM alert, user report, threat hunt)? How was it confirmed as a true incident? Were systems analyzed or network traffic captured? Screenshots can demonstrate the investigative process.
* **Containment, Eradication, and Recovery:** How was the incident scoped to ensure all affected systems were identified? How was the threat actor removed? Were backups restored, antivirus scans performed, or systems decommissioned? What was the root cause?
* **Post-Incident Activity:** What improvements are needed (staffing, tools, network visibility)? Major findings should also be reflected in the executive summary to ensure executive visibility.

### Report Appendix

A repository for supplementary material such as figures, graphs, tables, and long lists (e.g., IP addresses checked for malicious indicators). Storing these here keeps the main report concise and readable.

### Report Templates

No single template fits every organization. The structure varies depending on priorities, but the sections above are the most commonly included.

***

## Reporting Considerations

When drafting incident documentation, several factors must be considered to ensure clarity, accuracy, and usefulness. Key considerations include audience, investigation detail, and supporting evidence.

### Report Audience

Incident reports often serve multiple audiences, such as executive board members, IT staff, and the security team. Each section should match the needs of its readers:

* **Executive Summary:** Concise, non-technical, and framed around business risk. It should explain how the incident was discovered, resolved, and its potential business impact (e.g., lost sales, reputation damage, loss of trust). Executives rarely read beyond this section, so it must be impactful.
* **Rest of the Report:** Aimed at technical staff, this should include detailed explanations, annotated screenshots, and technical language where appropriate.

### Incident Investigation

This section must be evidence-driven. Unsupported speculation reduces credibility. Every claim should follow the principle: **Make a Point → Provide Evidence.**

For example, in a phishing attack involving a malicious Microsoft Word macro:

* State that phishing was the initial access vector.
* Provide supporting evidence such as screenshots of the email, macro code, and SIEM logs showing malware download and beaconing activity.

Mapping findings to [MITRE ATT\&CK](https://attack.mitre.org/matrices/enterprise/) tactics strengthens the investigation by showing how adversary behaviors align with known techniques.

### Screenshots and Captions

Screenshots provide strong visual evidence of findings, such as filtered PCAPs in Wireshark showing port scans, or SIEM logs confirming credential re-use. Every screenshot should include a clear caption summarizing its relevance. This helps readers quickly interpret the evidence, even if they are unfamiliar with the tools used.

***
