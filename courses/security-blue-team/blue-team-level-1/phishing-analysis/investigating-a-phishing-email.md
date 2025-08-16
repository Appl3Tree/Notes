# Investigating a Phishing Email

## Section IntroductionX

Investigations begin once a phishing email is reported, focusing on collecting email, file, and web artifacts for analysis.

***

## Artifacts to Collect

Artifacts are key data from emails that support searches, threat intelligence sharing, and defensive actions.

***

### Email Artifacts

#### Sending Email Address

* Record the apparent sender, even if spoofed
* Use as a search term in email gateways to find related traffic

#### Subject Line

* Useful for searches and blocking rules
* Can link emails from the same campaign

#### Recipient Email Addresses

* Identify all mailboxes that received the phishing email
* Often hidden via BCC; cross-check with gateway logs

#### Sending Server IP & Reverse DNS

* Collect sending IP to check for spoofing
* Perform reverse DNS lookup for more context

#### Reply-To Address

* May differ from sending address
* Often points to attacker-controlled accounts

#### Date & Time

* Record when the email was sent
* Helps identify campaign activity within similar timeframes

***

### File Artifacts

#### Attachment Name

* Filename + extension can serve as an indicator of compromise
* May be blockable in EDR platforms

#### SHA256 Hash Value

* Unique identifier for file reputation checks (VirusTotal, Talos, etc.)
* SHA256 is standard; MD5/SHA1 deprecated due to collisions

***

### Web Artifacts

#### Full URLs

* Copy directly, never type manually
* Required for accurate analysis

#### Root Domain

* Helps assess whether a domain is malicious or a compromised legitimate site

***

***

## Manual Collection - Email Artifacts

Retrieve email, web, and file-based artifacts using clients, text editors, and terminals; always perform analysis in isolated or disposable environments.

***

### Email Artifact List

Easiest artifacts to collect directly from an email client:

* Sending Address
* Subject Line
* Recipients (unless BCC)
* Date & Time

***

### Email Client Extraction

Quickly gather visible indicators in a client like Outlook or Thunderbird. Example:

* Subject Line = Hello
* Sending Address = [mark.thomas92@SecureMail.net](mailto:mark.thomas92@SecureMail.net)
* Date & Time = Monday 16th September 2019 at 17:33
* Recipient(s) = [contact@AcmeCorp.local](mailto:contact@AcmeCorp.local)

***

### Text Editor Extraction

Open the email in `.eml` or `.msg` format with a text editor (e.g., Sublime Text).

* Use **Find (CTRL+F)** to locate:
  * **X-Sender-IP** → convert via reverse DNS lookup (e.g., `209.85.167.42` → `mail-if1-f42.MailOps.net`)
  * **Reply-To Address** → search for “reply” to locate alternate addresses (e.g., `flamingo91591@SecureMail.net`)

If sending domain and sending IP don’t match, the sender address has likely been spoofed.

***

***

## Manual Collection - Web Artifacts

Hyperlinks in phishing emails may lead to fake login portals or malware downloads. Collect the **full URL** and the **root domain**.

***

### Email Client Extraction

* Hover over hyperlinked text to reveal the destination URL
* Right-click → **Copy Hyperlink** to copy it to the clipboard
* Faster than a text editor, but risk of accidentally clicking the link
* Always analyze inside a virtual machine or dirty system

***

### Text Editor Extraction

Use a text editor and **CTRL+F** to find URLs safely:

* Search for `http` to locate http/https links
* Search for `<a>` HTML anchor tags
* Search for the visible hyperlink text (e.g., “you can cancel it”)

Copy the URL directly from the HTML without risk of visiting it.

***

***

## Manual Collection - File Artifacts

Collect file hashes of malicious attachments to run reputation checks and strengthen defenses. Even a single character change alters the hash completely.

***

### Hashes via PowerShell

* Use `Get-FileHash` in Windows PowerShell (defaults to SHA256)
* Specify algorithm with `-Algorithm` (MD5, SHA1)
* Chain commands with `;` to retrieve multiple hashes at once

**Example:**

```powershell
Get-FileHash sample.docx
Get-FileHash sample.docx -Algorithm MD5
Get-FileHash sample.docx -Algorithm SHA1
Get-FileHash sample.docx -Algorithm SHA256
```

***

### Hashes via Linux CLI

* `sha256sum <file>`
* `sha1sum <file>`
* `md5sum <file>`

***

***

## Automated Collection With PhishTool

[PhishTool](https://app.phishtool.com/) is a forensic analysis console that automates artifact retrieval, tagging, and reporting from phishing emails.

***

### Example One

* Upload an email by drag-and-drop or using the **Browse** button
* Once analyzed, artifacts appear in sections of the console
* Copy artifacts using the clipboard icon

**Artifacts retrieved:**

* Sending Address
* Subject Line
* Recipients
* Date & Time
* Sending Server IP
* Reverse DNS
* URLs (if applicable)
* File Name (not applicable)
* File Hash (not applicable)

**Locations in console:**

* **Basic Header** → Sending Address, Subject, Recipients, Date & Time
* **Detailed Header** → X-Originating-IP and Reverse DNS
* **URLs Section** → Hyperlinks included in the email

***

### Example Two

* Submit an email with an attachment
* Under **Attachments** in the Basic Header section:
  * File Name
  * MD5 Hash
  * VirusTotal link to check hash reputation

***
