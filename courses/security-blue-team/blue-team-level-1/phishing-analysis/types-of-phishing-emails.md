# Types of Phishing Emails

## Section Introduction

Overview of common phishing email types, related social engineering techniques, and false positives.

***

## Recon

Reconnaissance emails are used to determine if a mailbox is active so it can be targeted in future phishing attacks. They may be spam-only, socially engineered, or use tracking pixels to gather engagement data.

#### Recon Emails Explained

* Purpose: confirm active mailboxes for future targeting
* Types:
  1. **Spam Recon** – random body text, checks for “undeliverable” bounce messages
  2. **Social Engineering Recon** – impersonates known contacts, creates urgency, or uses authority to elicit a reply
  3. **Tracking Pixel Recon** – embeds an invisible HTML pixel to confirm opens and collect activity data

#### Tactics Used

**Spam Recon Emails**

* No malicious payload; checks mailbox validity via bounce message behavior

**Social Engineering Recon Emails**

* Uses familiarity, urgency, or authority to encourage response
* Can overlap with **BEC (Business Email Compromise)**

**Tracking Pixels**

* HTML code with external link to pixel server
* Triggered when email is opened, sending back:
  * Operating system
  * Email access method (mobile/desktop, webmail/client)
  * Client software
  * Screen resolution
  * Date/time opened
  * IP address (ISP and location)

**Example of pixel HTML snippet:**

```html
<img src="http://tracker.CyberMetrics.local/pixel.png" width="1" height="1" />
```

#### Recon Email Examples

**Example 1 – Spam Recon**

* Sender: `mark.wilson@MailOps.net`
* Subject: “asdkf”
* Body: random text; no request for action; goal = detect mailbox validity via bounce handling

**Example 2 – Social Engineering Recon**

* Sender: `bob.thomas@SecureMail.net`
* Recipient: `contact@AcmeCorp.local`
* Subject: “Hello”
* Body: vague “hi there” greeting; generic message sent to group mailbox; unlikely from a legitimate known contact

***

## Credential Harvester

Phishing emails designed to trick recipients into entering credentials into a fake login page, often styled to imitate trusted brands or the target organization. Collected credentials may be used for **credential stuffing** or other attacks.

#### How They Work

* Email contains a lure (e.g., fake alert or notice) styled to mimic a legitimate company
* Links lead to a replica login portal
* Entered credentials are stored in hidden directories or sent to attacker-controlled accounts
* Attackers often use free email services (e.g., `MailOps.net`, `SecureMail.net`) for harvesting

#### Targeting

* Commonly imitate popular services (Outlook, Amazon, DHL, FedEx, HMRC, etc.)
* May be customized to match the branding of the victim organization
* Logos and assets easily copied from public websites

#### Examples

**Amazon-Themed Harvester**

* Real-world example: `hxxps://amazonupdates.securetrack[.]net/ap/signin?`
* URL uses **subdomain impersonation** to appear legitimate
* Visual styling closely matches the real Amazon login

**Microsoft-Themed Harvester**

* Real-world example: `hxxps://12.158.186[.]80/owa/auth/logon.aspx`
* Mimics Outlook Web Access
* Uses an **IP address instead of a domain** — a strong red flag

#### Key Points

* Mimics widely used websites/services
* Uses urgency or false authority to encourage action
* URLs may be random, impersonated, or misleading
* Small spelling or styling errors may be present — uncommon in genuine corporate emails

**Example CLI Check for Final Redirect Location:**

```bash
# Safely check where a suspicious link redirects without opening it in a browser
curl -I "http://short.url/abc123"
```

***

## Social Engineering

The exploitation of human behavior through psychological manipulation to make targets perform actions they normally wouldn’t — such as disclosing confidential information, granting unauthorized access, or transferring funds. Phishing is a form of social engineering attack.

#### Common Tactics in Phishing Emails

* Prompting replies to attacker’s initial email (**e.g., recon emails**)
* Posing as executives (CEO, CTO, CFO) to request money transfers
* Impersonating a data subject or higher-level employee to obtain confidential information

#### Key Points

* Targets the person, not the technical system
* Leverages authority, urgency, trust, and familiarity to influence behavior
* Used in nearly all phishing attacks to bypass technical defenses

***

## Vishing and Smishing

Two phone-based phishing attack types that rely on social engineering via voice calls (vishing) or text messages (smishing) instead of email. These methods often bypass traditional email security controls.

#### Smishing

* **Vector:** SMS/text messages, often sent in bulk to many recipients
* **Common Targets:** PII (names, DOBs, SSNs) and PCI (credit card/banking info)
* **Key Identifiers:**
  * Links that do not match the legitimate company’s domain
  * Unusual senders, including short or impossible numbers (e.g., 4291)
  * Unexpected requests for login, payment, or personal details
  * Spelling or grammar errors uncommon in legitimate corporate communications
* **Example:** Fake PayPal text with link `hxxps://paypal.account-verify.SecureMail[.]net` (real registered domain is `SecureMail[.]net`, not PayPal)

#### Vishing

* **Vector:** Phone calls leveraging direct voice contact
* **Likely Victims:** Staff 1–2 levels below executives with access to sensitive info
* **Key Identifiers:**
  * Caller pressures you to act quickly
  * Requests sensitive details (passwords, financial info) without standard verification
  * Caller ID spoofing (appears as internal number or trusted entity)
  * Language implying authority (CEO, bank security officer, government agent)
* **Defenses:**
  * Follow standard verification procedures
  * Refuse to share sensitive details over the phone without authentication
  * Report all suspicious calls to the security team

***

## Whaling

A highly targeted phishing attack aimed at senior executives (e.g., CEO, COO, CFO) to exploit their access to sensitive information and decision-making authority.

#### Characteristics

* Targets often less familiar with phishing and cybersecurity
* Uses **open-source intelligence** (OSINT) to craft realistic, personalized emails
* Methods may include:
  * Malicious attachments that install malware
  * Links to credential harvesters
  * Social engineering to obtain confidential data
* Low-volume, tailored messages designed to evade detection

#### Mitigation

* Provide phishing awareness training to executives and their assistants
* Mark external emails in subject or body to highlight potential risk
* Implement **data loss prevention (DLP)** policies to block sensitive data exfiltration
* Ensure assistants who manage executive inboxes are trained to spot and report suspicious messages

***

## Malicious File

Phishing emails designed to convince recipients to open malware-laden files. Delivered either as attachments or as hyperlinks to maliciously hosted files.

#### Malicious Attachments

* Directly attached to phishing emails
* High-risk file types often blocked (.exe, .vbs, etc.)
* Attackers prefer common formats (Word, Excel) to appear legitimate

**Microsoft Office Macros**

* Word/Excel documents can contain macros (scripts)
* Macros now disabled by default; attackers prompt users to “Enable Content” via fake warnings
* Once enabled, macros can:
  * Download malware (viruses, trojans, ransomware, rootkits)
  * Connect to malicious domains
* **Defenses:**
  * Keep macros disabled by default
  * Train users to spot suspicious prompts
  * Delete unsolicited attachments
  * Use Attack Surface Reduction (ASR) rules to block execution

#### Hosted Malware

* Malware stored on external websites; phishing email contains download link
* User must visit the link, download the file, and run it

**Malicious Domains**

* Easy and cheap to register
* Many newly registered domains used for malicious purposes
* Attacker hosts malware on these domains and distributes links via phishing emails

**Compromised Domains**

* Legitimate sites hacked and used to host malware
* Site’s normal content left intact to avoid detection
* Hyperlinks in phishing emails direct victims to these infected sites

***

## Spam

Unsolicited, unwanted, or unexpected emails that are not inherently malicious. Common sources include marketing, newsletters, or updates from registered services.

#### Characteristics

* Sent in bulk, not targeted
* Can include:
  * Newsletters
  * Product/service promotions
  * Update announcements from companies
* May originate from shared/sold mailing lists without user consent
* Not to be confused with **malspam** (malicious spam) — large-scale malicious email campaigns

#### Common Topics (Honeypot Observations)

* Cryptocurrency promotions and schemes
* PPE sales (notable during COVID-19)
* Sexual performance products
* Non-crypto financial schemes
* Adult dating
* Restaurant marketing
* Diet/weight-loss products

#### Examples

**Example 1 – Marketing Email**

* Sender: WordPress plugin vendor
* Legitimate service, but unwanted content
* Includes unsubscribe link as required by terms of service

**Example 2 – Cryptocurrency Promotion**

* Sender: promoting crypto platform, encouraging account creation and deposit

#### Key Points

* While often harmless, spam can be used for reconnaissance
* Clicking unsubscribe links can confirm mailbox is active or trigger fingerprinting
* Best practice: delete or forward to security team, avoid interacting with links or attachments

***

## False Positive

A legitimate email incorrectly reported as malicious.

#### Common Causes

* User suspects the email is malicious or potentially harmful
* Poor formatting (often in internal emails) makes the message look suspicious
* Email is unexpected and requests an action (e.g., click link, contact immediately, transfer funds)
* Lack of phishing awareness training leads to over-caution

#### Key Points

* Reporting false positives is preferable to missing genuine threats
* Indicates users are engaged and actively scanning for suspicious activity
* Helps maintain a security-focused culture even if it adds investigative workload

***
