# Report Writing

## Section Introduction

Writing effective phishing reports requires balancing detail with conciseness, ensuring future analysts can quickly understand the case without re-investigating. This section covers structuring a report with key elements: email header details, collected artifacts, body content, affected users and notifications, analysis steps and results, defensive measures, and lessons learned.

***

## Email Header, Artifacts, and Body Content

Artifacts (Indicators of Compromise, IOCs) are the first data collected from phishing emails. They help link attacks into campaigns, identify threat actors, build metrics, and support trend analysis. Reports should present these clearly and concisely so analysts can copy and paste them into tools or reputation services without delay.

### Email Header and Artifacts

Key artifacts to extract and record:

* **Email Header**
  * Sending Email Address (e.g., `emma.watson@mailops.net`)
  * Reply-to Address (e.g., `michael.jones77@securemail.net`)
  * Date Sent (e.g., 20th October 2019, 9:34 AM)
  * Sending Server IP (e.g., `40.92.10.10`)
  * Reverse DNS of Sending Server IP (e.g., `mail-oln040092010100.outbound.protection.acmecorp.local`)
  * Recipient(s) (e.g., `sarah.green@acmecorp.local`)
  * Subject Line (e.g., `Payroll Notice – URGENT!`)
* **Email with URLs**
  * Sanitized URLs (e.g., `hxxps://malicious-site[.]mailops.net/path/lure.php`)
* **Emails with Attachments**
  * File Name + Extension (e.g., `Payroll_Acme_Update.exe`)
  * File Hashes (MD5/SHA256)

### Email Body Content

Best practice:

* Attach the raw email file (`.eml` or `.msg`) to the case.
* Provide a **brief description** (1–2 sentences) of how the email looks and what action it tries to prompt.
* Add a screenshot for reference.

This makes it easier to identify social engineering trends and reduces the need for others to re-open the original email.

### Example One

**Artifacts Retrieved**

* Sender: `michael.jones77@mailops.net`
* Reply-to: None
* Date: Monday 16th September 2019 17:33
* Sending Server IP: `209.85.167.42`
* Reverse DNS: `mail-lf1-f42.google.com`
* Recipients: `info@acmecorp.local`
* Subject: `General Inquiry`
* URL: None
* Attachments: None

**Email Description**\
Plain text message with no links or attachments. Attempts to prompt a reply or confirm the mailbox is active. Classified as **Recon**.

### Example Two

**Artifacts Retrieved**

* Sender: `support.team@securemail.net`
* Reply-to: `no-reply@mailops.net`
* Date: Monday 16th September 2019 19:25
* Sending Server IP: `209.85.167.91`
* Reverse DNS: `mail-lf1-f91.google.com`
* Recipients: `emma.watson@acmecorp.local`
* Subject: `Suspicious Account Alert`
* URL: `hxxp://phishyexample[.]mailops.net/`
* Attachments: None

**Email Description**\
Formatted to resemble a legitimate service, urging the recipient to click a malicious link. Classified as **Credential Harvester**.

***

## Analysis Process, Tools, and Results

This section is the most detailed part of the report. It outlines the analysis process used to determine the risk of malicious artifacts such as attachments or URLs. Analysts should include the tools utilized, the results obtained, and any manual investigation methods performed (e.g., detonating malware in a sandbox).

The goal is to provide enough detail for other analysts or senior staff to replicate the investigation and reach the same conclusion. This section ultimately justifies any defensive measures that follow.

### Example One

**Malicious Artifact Analysis (URL)**

* **URL:** `hxxps://malicious-site[.]mailops.net/index/login.aspx`

**WHOIS Analysis**

* The domain was registered within the last few days using a registrar that allows anonymous registration.
* No identifying information about the registrant is available.

**VirusTotal Reputation**

* The URL and root domain were not flagged at the time of analysis, likely due to the domain being newly registered and not yet crawled.

**URL Visualization**

* A screenshot service (e.g., [URL2PNG](https://url2png.com/)) showed the link resolves to a fake login page designed to harvest credentials.
* The root domain has no legitimate homepage, a common indicator of domains set up solely for malicious use.

### Example Two

**Malicious Artifact Analysis (Attachment)**

* **Attachment Name:** `Wallpaper_Acme_Update.exe`
* **Attachment MD5 Hash:** `0c4374d72e166f15acdfe44e9398d026`
* **Attachment SHA256 Hash:** `240387329dee4f03f98a89a2feff9bf30dcba61fcf614cdac24129da54442762`

**VirusTotal Upload**

* Uploading the file showed high malicious detection, flagged by the majority of antivirus engines.
* Direct link to the [VirusTotal report](https://www.virustotal.com/gui/file/240387329dee4f03f98a89a2feff9bf30dcba61fcf614cdac24129da54442762/detection).

**Talos File Reputation**

* Submitting the SHA256 hash to Cisco Talos confirmed the file’s malicious reputation.

### Conclusion

This section must answer questions such as:

* Is the URL or file malicious?
* What impact could it have on the organization?

Detailed notes on the methods, tools, and findings provide the justification for any defensive measures. Senior analysts should be able to review this section and independently arrive at the same conclusions.

***

## Defensive Measures Taken

This section records the defensive actions implemented, or those requested, to protect the organization after a phishing attack. Defensive measures target artifacts observed in malicious emails to prevent similar attacks from succeeding in the future.

#### Types of Defensive Measures

* **Email artifact blocking:** subject lines, sending addresses, sending server IPs
* **Web artifact blocking:** URLs, domains, IPs
* **File artifact blocking:** filenames, hashes

Depending on the organization, analysts may:

1. Apply blocks directly, or
2. Request senior analysts or other departments to apply them, providing justification.

In both cases, the report must clearly document the actions taken, including justification, timing, and accountability.

### Example One

**Scenario:** A credential-harvesting email was received by 23 employees.

**Artifacts Retrieved**

* Sender: `contact@delivery-service.net`
* Sending Server IP: `209.85.167.42`
* Reverse DNS: `mail-lf1-f42.google.com`
* Subject: `Failed Delivery Notice – URGENT!!`
* URL: `hxxps://faileddelivery[.]mailops.net/login`

**Report Section Example**

1. The sending address was spoofed, but the IP belongs to Gmail and cannot be blocked without major business impact.
2. Blocking the spoofed sender is also inappropriate, as the legitimate address may be used.
3. The subject line was blocked on the email gateway since it is unlikely to appear in legitimate business traffic.
4. This block prevents future delivery of similar phishing emails without affecting legitimate mail.
5. The malicious domain was created solely for phishing and has no business justification, so it was blocked at the proxy.

**Defensive Measures Applied**

* Subject Line Block (Email Gateway): `Failed Delivery Notice – URGENT!!` on 22nd December at 12:03 PM by Jane Smith
* Domain Block (Web Proxy): `faileddelivery[.]mailops.net` on 22nd December at 12:07 PM by Jane Smith

***

### Example Two

**Scenario:** A malicious email was reported with an attachment delivering malware. Two machines were infected before incident response contained the spread.

**Artifacts Retrieved**

* Sender: `official.notice@securemail.net`
* Sending Server IP: `129.33.19.188`
* Reverse DNS: `mail-securemail.net`
* Subject: `Tax Document Announcement`
* URL: `hxxp://tax-docs[.]mailops.net/download.php`
* Attachment: `Tax_Update_AcmeCorp.pdf.exe`
* File MD5 Hash: `0a52730597fb4ffa01fc117d9e71e3a9`

**Report Section Example**

1. The sending address originates from a malicious domain. Blocking the whole domain may be excessive at this stage, but blocking the specific sender prevents further emails.
2. This block has no negative business impact.
3. The embedded URL downloads the same malware as the attachment. The domain is malicious and has no legitimate purpose, so it was blocked at the proxy.

**Defensive Measures Applied**

* Sending Address Block (Email Gateway): `official.notice@securemail.net` on 1st March at 3:37 PM by Chris C.
* Domain Block (Web Proxy): `tax-docs[.]mailops.net` on 1st March at 3:41 PM by Chris C.

***

## Artifact Sanitization

When writing reports, all URLs and IP addresses must be sanitized (defanged) to prevent accidental execution or access. This ensures that analysts reviewing the report cannot inadvertently trigger malicious content by clicking on a link.

### Why Defang?

If a report contains an unsanitized URL or IP, a colleague could accidentally open it. For example, a URL found in a malicious PowerShell script might automatically download and execute a payload if clicked. Defanging removes this risk.

### Defanging Rules

* Replace each “.” with “\[.]” in URLs and IPs.
* Replace “http” with “hxxp” to make it non-clickable.

**Examples:**

* `8.8.8.8` → `8[.]8[.]8[.]8`
* `https://hello.example.com` → `hxxp://hello[.]example[.]com`

### Automation

Batch defanging can be tedious. Tools like [CyberChef](https://gchq.github.io/CyberChef/) include built-in **Defang IP Addresses** and **Defang URL** operations to quickly sanitize artifacts.

***
