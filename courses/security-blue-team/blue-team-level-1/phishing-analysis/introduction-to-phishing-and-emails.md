# Introduction to Phishing and Emails

### Section Introduction

Overview of email structure, protocols, and phishing as a primary cyber threat.

***

### How Electronic Mail Works

Covers email protocols (SMTP, POP3, IMAP), address structure, infrastructure, and access methods to support phishing defense.

#### Email Addresses

* Format: **mailbox/local part** + **domain** (e.g., `user@domain.com`)
* Mailbox identifies recipient; domain identifies mail server
* Example: `jane.doe@AcmeCorp.local` → mailbox = jane.doe, domain = AcmeCorp.local
* Lookup mail server for a domain with MX record query:

```bash
dig MX AcmeCorp.local
```

#### Email Protocols

**SMTP**

* Default port: TCP 25 (moving to TCP 587 with TLS)
* Sends email from client to recipient’s mail server
* Uses DNS to resolve recipient domain’s IP
* Test SMTP connection with `openssl`:

```bash
openssl s_client -starttls smtp -connect mail.AcmeCorp.local:587
```

**POP3**

* Retrieves email from server, then deletes it from server
* Emails stored locally; inaccessible from other devices afterward
* Manual POP3 login example:

```bash
openssl s_client -connect mail.AcmeCorp.local:995
USER jane.doe@AcmeCorp.local
PASS MySecurePass123
LIST
QUIT
```

**IMAP**

* Emails remain on server; accessible from multiple devices
* Allows optional download for offline storage
* Manual IMAP login example:

```bash
openssl s_client -connect mail.AcmeCorp.local:993
a LOGIN jane.doe@AcmeCorp.local MySecurePass123
a LIST "" "*"
a LOGOUT
```

**Email Delivery Flow Example:**

1. Client sends message to outbound SMTP server
2. SMTP queries DNS for recipient domain IP
3. Message routed via internet and other SMTP servers
4. Delivered to recipient domain SMTP server
5. Moved to POP3 or IMAP server for client access

#### Webmail

* Browser-based access (e.g., WebMail.AcmeCorp.local)
* Accessible from any internet-connected device
* Requires internet connection; some offer limited offline mode
* Differs from clients, which store emails locally for full offline use

***

### Anatomy of an Email

Covers the two main parts of an email — header and body — for use in artifact retrieval and analysis.

#### Email Header

* Contains transport and routing info (sender, recipient, timestamps)
* Modified by each intermediary mail server (MTA)
* Allows tracing the path and timing of delivery

**Header Fields**

* **Mandatory:**
  * From – sender’s email address
  * To – recipient’s email address
  * Date – when email was sent
* **Optional:**
  * Received – intermediary server info and timestamps
  * Reply-To – alternate reply address
  * Subject – message subject line
  * Message-ID – unique identifier
  * Message body – separated from header by a line break

**Custom X-Headers**

* Begin with `X-` (e.g., `X-Spam-Status: YES`)
* Can be set by software or users
* Not reliable proof of sender or send time — values can be forged

#### Email Body

* Contains sender’s written content (text, links, images, HTML)
* Often branded to appear legitimate in phishing attempts
* Can be plain text or encoded (e.g., Base64 for HTML-heavy messages)
* Encoded content can be decoded with tools like CyberChef or CLI:

```bash
echo 'SGVsbG8gV29ybGQhCg==' | base64 -d
Hello World!
```

***

### What is Phishing?

Phishing is an email-based attack using social engineering to trick recipients into disclosing information, downloading malware, or performing actions they normally wouldn’t. Variants include **Vishing** (voice calls) and **SMiShing**(SMS/text).

***

### The Impact of Phishing

* 90% of data breaches in 2019 linked to phishing (Retruster)
* Average breach cost: $3.86M (IBM, 2019)
* 65% increase in phishing attempts from 2018 to 2019 (Retruster)
* \~1.5M new phishing sites monthly (Webroot, 2019)
* Advanced malware campaigns (e.g., 1M Emotet trojan emails in one day – Proofpoint)
* Cheap, effective, and requires only one successful target to compromise systems

***

### Domain Glossary

#### IOC – Indicator of Compromise

* Intelligence from malicious activity, intrusions, or incidents
* Example: malware file hashes and names shared for blocklists or exposure checks

#### Artifact

* Data element retrieved from an email, website, or file
* Examples: email addresses, sending server IPs, file hashes, domain names

#### File Hash

* Unique string from hashing a file (MD5, SHA1, SHA256)
* SHA256 preferred due to resistance to collisions

#### Recon – Reconnaissance Phishing Email

* Email sent to prompt replies or confirm active mailboxes
* Identifies potential targets for future phishing

#### Cred Harvester – Credential Harvester Phishing Email

* Email with link to fake login page imitating trusted brands
* Goal: capture user credentials

#### Vishing – Voice Phishing

* Voice calls + social engineering to elicit sensitive actions or site visits

#### Smishing – SMS Phishing

* Text messages + social engineering to elicit sensitive actions or site visits

#### BEC – Business Email Compromise

* Compromised organization mailbox used for phishing or data theft
* Can also mean any phishing targeting an organization

#### SPF – Sender Policy Framework

* DNS TXT record validating allowed sending servers for a domain
* Helps prevent spoofing

#### DMARC – Domain-based Message Authentication, Reporting and Conformance

* Email authentication + policy/reporting protocol
* Dictates action when SPF/DKIM checks fail (quarantine, reject, allow)

#### DKIM – DomainKeys Identified Mail

* Cryptographic email authentication verifying sender server and message integrity

***

### Further Reading Material

Additional resources for exploring phishing analysis concepts, tools, and training.

#### Resources

* **The Weakest Link – User Security Awareness Game**\
  [https://www.isdecisions.com/user-security-awareness-game/](https://www.isdecisions.com/user-security-awareness-game/)
* **Online Phishing Quiz**\
  [https://phishingquiz.withgoogle.com/](https://phishingquiz.withgoogle.com/)
* **Awesome Social Engineering – Curated Resource List**\
  [https://github.com/v2-dev/awesome-social-engineering](https://github.com/v2-dev/awesome-social-engineering)
* **YouTube – Social Engineer CTF Winning Voice Phishing Call**\
  [https://www.youtube.com/watch?v=yhE372sqURU](https://www.youtube.com/watch?v=yhE372sqURU)
* **Anti-Phishing Working Group (APWG) – Resources**\
  [https://apwg.org/resources/](https://apwg.org/resources/)
* **Phishing.org – Phishing Resources (Tools, Webinars, Whitepapers)**\
  [https://www.phishing.org/phishing-resources](https://www.phishing.org/phishing-resources)
* **GoPhish – Simulated Phishing Exercise Toolkit**\
  [https://getgophish.com/](https://getgophish.com/)
* **SpearPhisher by TrustedSec – Simulated Phishing Exercise Toolkit**\
  [https://github.com/kevthehermit/SpearPhisher](https://github.com/kevthehermit/SpearPhisher)
* **Cofense Blog – Phishing Defenses and Awareness**\
  [https://cofense.com/blog/](https://cofense.com/blog/)
* **Report Phishing Pages to Google**\
  [https://safebrowsing.google.com/safebrowsing/report\_phish/?rd=1\&hl=en](https://safebrowsing.google.com/safebrowsing/report_phish/?rd=1\&hl=en)

***
