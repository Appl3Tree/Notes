# Taking Defensive Actions

## Section Introduction

Covers preventative and reactive security measures against phishing, including both technical and administrative controls at the technological and human levels.

***

## Preventative: Marking External Emails

Most phishing emails come from outside the organization, making it critical for employees to recognize them. Email platforms such as Microsoft Exchange and Office 365 can automatically tag incoming external messages to warn recipients that they are not internal communications.

A common method is to prepend the subject line with a short marker such as **\[EXTERNAL]** or **\[EXT]**. This helps employees pause before clicking links or opening attachments.

### Example Walkthrough

In Office 365 Exchange Admin Center:

* Go to **Mail flow** and create a new rule.
* Condition: sender is outside the organization and recipient is internal.
* Action: prepend the subject with “\[EXTERNAL]”.

The same approach can insert warnings into the body of the email, with styling such as bold or red text to ensure visibility and encourage caution.

***

## Preventative: Email Security Technology

Organizations can use email security technologies to detect spoofing attempts and verify whether emails truly originate from the domains they claim. The main protective measures are SPF, DKIM, and DMARC.

### Anti-Spoofing Records

DNS records can strengthen email security by preventing attackers from forging addresses from an organization’s domain. SPF, DKIM, and DMARC work together to protect against spoofing and phishing.

### SPF Records

* **Purpose:** Defines which IPs or domains can send mail for a domain.
* **Format:** `v=spf1 <IP/host> <enforcement rule>`
* **Enforcement rules:**
  * `-all` → **hard fail** (unauthorized senders are rejected)
  * `~all` → **soft fail** (unauthorized senders are accepted but marked as suspicious)
*   **Example:**

    ```
    v=spf1 a: include:mailgun.org protection.outlook.com -all
    ```

    * Declares SPF record
    * Authorizes Mailgun and Outlook
    * `-all` enforces hard fail if spoofed

### DKIM Records

* **Purpose:** Ensures message integrity and authenticity using cryptographic signatures.
* **Process:**
  * Sending server generates a hash with its private key → attaches as DKIM signature
  * Receiving server retrieves public key from DNS, verifies signature, and ensures the content hasn’t been altered
* **Format:** `V=DKIM1 <key type> <public key>`

### DMARC Records

* **Purpose:** Builds on SPF and DKIM, adding policy and reporting.
* **Actions:** `none`, `quarantine`, or `reject` if checks fail.
* **Format:** `v=DMARC1 <action> <report address>`
*   **Example:**

    ```
    v=DMARC1; p=quarantine; rua=mailto:contact@AcmeCorp.local
    ```

    * Sets policy to quarantine
    * Sends aggregate reports to [contact@AcmeCorp.local](mailto:contact@AcmeCorp.local)

***

## Preventative: Spam Filter

Spam filters prevent unwanted or malicious emails from reaching inboxes, reducing risks such as lost time, phishing, social engineering, and malware. They are built into many email services (e.g., Gmail, Outlook) or deployed as standalone solutions, using techniques like rulesets, algorithms, blacklists, machine learning, and community feedback.

### Why is it Important?

Spam filters protect end-users by catching threats before they reach mailboxes. Since email is a common vector for cyber-attacks, properly configured spam filtering helps block phishing attempts, malicious payloads, and scams.

Types of deployment:

* **Gateway Spam Filters** – Deployed behind an on-premises firewall; common in enterprises (e.g., Barracuda Email Security Gateway).
* **Hosted Spam Filters** – Cloud-based, quick to update, similar in function to gateway filters (e.g., SpamTitan).
* **Desktop Spam Filters** – Installed by individual users; common in SOHO setups but can be risky if bundled with unwanted software.

### Types of Spam Filters

* **Content Filters** – Analyze headers and body text; check against blacklists and detect keywords or suspicious content.
* **Rule-Based Filters** – Follow predefined criteria, e.g., flagging “FREE OFFER” emails from external senders in Exchange Mail Flow rules.
* **Bayesian Filters** – Use machine learning to adapt based on user input; improve over time but require sufficient spam samples and proper user handling.

Correct configuration and user training are essential; mislabeling legitimate email as spam can degrade filter performance.

***

## Preventative: Attachment Filtering

Attachment filtering reduces the risk of malware delivery by restricting or controlling the types of files allowed through email. Instead of blocking all attachments, organizations tailor rules to focus on file types most often abused by attackers, while allowing those needed for business use.

### Filtering

Risky file types commonly blocked include:

* **.exe** (Executables)
* **.vbs** (Visual Basic Scripts)
* **.js** (JavaScript)
* **.iso** (Disk Images)
* **.bat** (Batch Files)
* **.ps/.ps1** (PowerShell Scripts)
* **.htm/.html** (Web Pages)

Business-relevant but also potentially risky file types include:

* **.zip** (Archives)
* **.doc/.docx/.docm** (Word Documents)
* **.pdf** (Portable Document Format)
* **.xls/.xlsx/.xlsm** (Excel Spreadsheets)

Actions available in email gateways or security tools once flagged include:

* Scanning attachments for malicious indicators
* Blocking delivery
* Quarantining the email
* Stripping the attachment
* Alerting administrators or security teams
* Generating logs for SIEM ingestion and alerting analysts

***

## Preventative: Attachment Sandboxing

Attachment sandboxing addresses the risk of malicious files bypassing traditional attachment filtering. Instead of only checking file type or name, the attachment is detonated in a controlled virtual environment where its behavior is observed. If actions such as downloading from malicious domains or altering processes are detected, the file is flagged as malicious and the email is blocked.

### Advanced Features

* **Machine Learning** – Continuously refines detection by analyzing behavior from millions of malicious samples.
* **Scalable Virtual Environments** – Expands resources dynamically to handle large volumes of incoming email attachments.
* **Detailed Reports** – Provide insights into attempted malicious actions, allowing security teams to improve defenses and share intelligence with peers.

***

## Preventative: Security Awareness Training

Phishing targets human weaknesses by tricking users into opening malicious attachments, submitting credentials, or giving away sensitive information. Because technical defenses cannot stop every phishing email, organizations must train employees to recognize and report suspicious activity.

### Awareness Training

* Should be part of onboarding and ongoing education.
* Delivered in-person or online.
* Covers key phishing indicators:
  * Unknown sender address
  * Grammar/spelling errors
  * Poor formatting or styling
  * Urgent requests or suspicious actions
  * Unfamiliar URLs or attachments

Well-trained employees reduce the chance of creating incidents by avoiding malicious links and attachments.

### Simulated Phishing Attacks

Organizations often test awareness with controlled phishing campaigns to measure training effectiveness. Employees who click links are redirected to a safe page that explains the test, while security teams track reports to gauge responsiveness. Regular simulations highlight who needs additional training.

Common platforms include:

* [Sophos Phish Threat](https://www.sophos.com/en-us/products/phish-threat.aspx)
* [GoPhish Open-Source](https://getgophish.com/)
* [Trend Micro’s Phish Insight](https://phishinsight.trendmicro.com/en/simulator)
* [PhishingBox](https://www.phishingbox.com/)

***

## Reactive: Immediate Response Process

The immediate response process defines the steps analysts follow after identifying a phishing email, ensuring the threat is contained, investigated, and documented.

### Steps in the Process

1. **Retrieve an Original Copy**
   * Obtain from the email gateway, Exchange server, or by having the employee forward it to a security mailbox.
2. **Gather Artifacts**
   * Collect key artifacts (headers, URLs, attachments, domains) for later analysis and defensive actions.
3. **Inform Recipients**
   * Notify all recipients who received the phishing email.
   * Use a standardized template with:
     * Date and time the phishing email was sent
     * Subject line of the phishing email
     * Clear instructions (delete or forward to security mailbox)
     * Contact information for security team support
4. **Artifact Analysis and Investigation**
   * Examine collected artifacts to confirm malicious activity.
   * Use tools such as enterprise sandboxing, [URL2PNG](https://www.url2png.com/), [VirusTotal](https://www.virustotal.com/), [IPVoid](https://www.ipvoid.com/), WannaBrowser, or a virtual machine.
5. **Take Defensive Measures**
   * Block identified malicious artifacts:
     * Emails at the gateway
     * URLs/domains via proxy or firewall
     * File hashes or executables via endpoint protection
   * Example: blocking a phishing credential-harvesting URL on the web proxy prevents employee access.
6. **Complete Investigation Report**
   * Document all steps taken: retrieval, analysis, notifications, defensive measures.
   * Provides an audit trail and ensures lessons learned are captured.

***

## Reactive: Blocking Email Artifacts

After analyzing phishing emails, defensive measures can be applied at the gateway to block malicious senders, domains, IPs, or subject lines, preventing delivery to employee mailboxes.

### Key Email Artifacts to Block

* **Email Sender (mailbox@domain)**
  * Primary method for blocking phishing campaigns.
  * Typically configured to block incoming emails from that address.
  * Can also be bi-directional to stop employees from replying to the malicious sender.
* **Sender Domain (@domain)**
  * Broader block than a single address.
  * Only used when the domain is entirely malicious.
  * Risky for common domains (e.g., @Gmail, @Outlook) since it could block legitimate communication.
* **Sending Server IP**
  * High-severity block; used only when absolutely necessary.
  * Drops any emails originating from that IP.
  * Effective if the IP is known to be compromised or dedicated to malicious activity.
* **Subject Line**
  * Useful when multiple senders reuse the same phishing subject line.
  * Blocking by subject line allows one rule to capture many variants of the same campaign.

***

## Reactive: Blocking Web Artifacts

Malicious websites linked in phishing emails must be blocked quickly to protect employees even if they click a link. Controls are usually applied through web proxies, DNS, or firewalls.

### Web Proxy

* **URL Blocks**
  * Block a specific malicious URL observed in phishing emails.
  * Effective if the URL is static.
  * Can also block at a suspicious directory level to catch multiple variations (e.g., block `secure-mail.net/index/2019/hgasdf` instead of just one full URL).
  * Less effective if URLs are dynamically generated for each recipient.
* **Domain Blocks**
  * Blocks all traffic to a domain, including subdomains and new URLs.
  * Used when the domain is confirmed to be malicious or compromised with no business use.
  * Example: blocking `secure-mail.net` stops all traffic regardless of the URL path.

### DNS Blackholing

* Redirects a malicious domain to a safe site instead of the intended target.
* Useful during large phishing campaigns to educate employees.
* Can trigger SIEM or EDR alerts when users attempt to connect, identifying who clicked and may need additional training.

### Firewall

* Blocks traffic to a malicious IP hosting multiple bad sites.
* Considered an extreme measure and less effective for phishing because attackers can easily switch IPs.
* More commonly used against scanning or direct attacks.

### Making the Decision

* **Purely malicious domain:** Block the entire domain at the proxy.
* **Compromised domain (no business need):** Block the domain.
* **Compromised domain (possible business need):** Use a URL block at the appropriate directory level.
* Use WHOIS, [URL2PNG](https://www.url2png.com/), and background checks to assess legitimacy and age of the domain before deciding.

***

## Reactive: Blocking File Artifacts

Malicious attachments can deliver severe threats like ransomware, keyloggers, or backdoors. Defensive measures typically focus on blocking file hashes or, in rare cases, filenames.

### Blocking Hashes

* Block MD5, SHA1, or SHA256 hashes in an Endpoint Detection and Response (EDR) tool.
* When the file appears, the endpoint agent detects and removes it before execution.
* If an AV product misses detection, hashes can often be submitted to the vendor for signature updates.
* **Limitations:**
  * Polymorphic malware can alter itself, generating new hashes.
  * MD5 and SHA1 are deprecated due to collisions; **SHA256 is the current standard.**

### Blocking Names

* Rarely recommended unless filenames are highly unique and unlikely to be legitimate.
  * Risky example: `Budget FINAL March 2019.xls` (may be legitimate).
  * Safer example: `INVOICE #8491 READ NOW URGENT` (clearly suspicious).
* More commonly used to create watchlists of suspicious filenames, triggering alerts rather than automatic blocking.
* In most cases, hash-based blocking is the preferred method.

***
