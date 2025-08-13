# Tactics and Techniques Used

## Section Introduction

Overview of tactics and techniques used to make phishing emails appear legitimate, increase engagement, and evade detection by security tools.

***

\#Spear Phishing

A targeted phishing attack that uses **reconnaissance and OSINT** to craft highly convincing, personalized emails for a specific individual or group.

#### Characteristics

* Tailored content based on target’s personal/professional information
* Increases likelihood of clicking links or opening attachments
* May use additional techniques such as **typosquatting** or **sender spoofing** to appear legitimate

#### Example Scenario

* Attacker targets employee at `AcmeCorp.local`
* Finds target’s LinkedIn profile → identifies colleagues
* Reverse-image search reveals Facebook account with public friends and interests
* Crafts email referencing real hobbies/interests to increase trust
* Includes malicious attachment to install a backdoor for remote access
* Uses social engineering (e.g., impersonating a known contact) to boost credibility

***

## Impersonation

A phishing tactic where the attacker pretends to be a trusted person — such as a friend, colleague, or senior leader — to increase the likelihood of the target acting on the request.

#### Characteristics

* Exploits authority bias — employees may comply faster when requests come from higher-ranking individuals
* Can be combined with **spear phishing** for higher success rates
* Common impersonation targets: CEO, CFO, managers, directors

#### Example Scenario (as shown in diagram)

1. Malicious actor sends email posing as company CEO (“James”) to Finance employee (“Robert”)
2. Email requests urgent transfer of £5000 to “secure a deal”
3. Robert, believing request is legitimate, transfers funds to attacker-controlled account
4. Attacker receives payment, bypassing normal approval or verification

#### Key Points

* Often time-sensitive or urgent to discourage verification
* May use spoofed email addresses or lookalike domains
* Best defenses:
  * Verification via a separate communication channel
  * Policies for confirming financial transactions
  * Training staff to recognize authority-based phishing tactics

***

## Typosquatting and Homographs

Two domain-based phishing tactics that visually imitate legitimate domains or email addresses to deceive recipients.

#### Typo Squatting

* Registers domains with **minor spelling variations** of a legitimate domain
* Examples (based on legitimate `SecureOps.local`):
  * `SecurltyOps.local` (lowercase “L” replacing “I”)
  * `SecureOpps.local` (extra “P” in “Ops”)
  * `SecurOps.local` (missing “e” in “Secure”)
* Can be used for:
  * Hosting phishing sites
  * Creating convincing phishing email addresses
* Defense:
  * Monitor or register common misspellings of company domain
  * Train staff to scrutinize sender addresses

**Example Scenario:**

* Legitimate domain: `AcmeCorp.local`
* Attacker registers: `AcmeCorpp.local`
* Creates address `chloe.wood@AcmeCorpp.local`
* Sends email to new HR employee impersonating senior HR manager, requesting sensitive employee information about another staff member

#### Homoglyphs

* Exploits **Unicode characters** that look visually identical but have different underlying code points
* Examples:
  * `AсmeCorp.local` — first “c” is Cyrillic “с” instead of Latin “c\`
  * `PayPaⅼ.SecureMail.net` — last “l” is a lowercase L from a different script
* Enables creation of lookalike domains that are **impossible to distinguish by sight**

**Safe Detection Methods:**

```bash
# Display Unicode code points for each character in the domain
echo "AсmeCorp.local" | hexdump -C
00000000  41 d1 81 6d 65 43 6f 72  70 2e 6c 6f 63 61 6c 0a  |A..meCorp.local.|
00000010

# (d1 81 = Cyrillic “с”, different from Latin “c”)

# Use 'idn2' to reveal the punycode representation of an IDN
idn2 "AсmeCorp.local"
xn--meCorp-iva.local
```

* In browsers, hover over the link and inspect the **status bar** or right-click → “Copy Link” → paste into a plain text editor to reveal the true domain.
* Security gateways can block IDNs from untrusted sources or convert them to punycode for inspection.

***

## Sender Spoofing

A phishing tactic where the **From** address is forged to appear as if the email is coming from a trusted sender, increasing the likelihood that the recipient will interact with the message. Commonly paired with credential harvester campaigns.

#### How It Works

* SMTP allows the **From** field to be set to any value — no verification at sending
* Attacker forges a trusted sender’s address to bypass recipient suspicion

#### Example 1 – FROM Address

* Target: `james.smith@AcmeCorp.local`
* Attacker forges From address as `ServiceDesk@AcmeCorp.local`
* Includes link to an Office365 credential harvester
* Victim believes the email is from IT and enters their credentials

**Detection:**

* Check the sending server IP (e.g., `X-Originating-IP` header)
* Perform WHOIS/IP lookup to confirm if server belongs to the claimed organization

#### Example 2 – FROM Address with Reply-To

* Attacker sets From address as `contact@MailOps.net` to impersonate a trusted sender
* Sets Reply-To address as `helpdesk.support@SecureMail.net` (attacker-controlled)
* Victim replies → response goes to attacker’s mailbox

**Detection:**

* Compare **From** and **Reply-To** headers
* Block attacker-controlled Reply-To addresses at the email gateway

***

## HTML Styling

How phishers use branded HTML (logos, colors, buttons, layout) to make emails look legitimate and increase clicks on malicious links or attachments.

#### Why Attackers Use Styling

* Mimics trusted brands and internal templates to lower suspicion
* Hides malicious links behind buttons and styled anchors
* Uses layout tricks (tables, divs) to place urgent warnings/promos prominently

#### Common Elements You’ll See

* Logos and header banners sourced from attacker-controlled CDNs
* Buttons using `<a>` tags styled as CTAs (“Update Payment”, “Verify Account”)
* Tables for precise layout (common in marketing templates)
* Inline CSS to control fonts, colors, spacing and to bypass some scanners

#### Quick Tag Reference

* `<a>…</a>`: hyperlink text or buttons to an external URL
* `<table>…</table>`: structure and spacing of content blocks
* `<b>…</b>`, `<i>…</i>`, `<u>…</u>`: emphasis (bold/italic/underline)
* `<img src="…">`: logos/tracking pixels (sometimes 1×1 invisible)

#### Example: Decode HTML from a Base64 Email Section

```bash
# Decode a base64-encoded HTML snippet from an email
echo 'UEhUTUwgc25pcHBldCBleGFtcGxlOiA8aHRtbD48Ym9keT48aDE+QWNtZUNvcnAgQWNjb3VudCBOb3RpY2U8L2gxPjwvYm9keT48L2h0bWw+' | base64 -d
<html><body><h1>AcmeCorp Account Notice</h1></body></html>
```

* Shows how to safely view encoded HTML content without opening it in a browser.

***

## Attachments

Phishing campaigns often use attachments to deliver malware, trick users into revealing information, or direct them to malicious websites. Common categories include:

1. **Non-malicious files for social engineering** — e.g., fake invoices, letters, images
2. **Non-malicious files with malicious hyperlinks** — e.g., PDFs linking to phishing sites
3. **Malicious files** — e.g., Office documents with macro-based malware

#### Social Engineering Files

* Appear legitimate and request information under false pretenses
* Example: Posing as HR with a “payroll change form” attachment, using urgency to rush the recipient
* Can be paired with sender spoofing for credibility
* Data gathered can enable fraud, blackmail, or further impersonation attacks

#### Lure Documents

* Contain embedded hyperlinks to malicious sites instead of malicious code
* Example: PDF “invoice” directing user to “view online” via a phishing domain
* Bypasses some email scanners since the file itself is clean, but the link is dangerous

#### Malicious Files

* Inherently harmful, typically Office docs with macros that execute malware
* Can download additional payloads from attacker-controlled domains
* Require convincing the user to click “Enable Content” for macros to run
* Best defense: keep macros disabled, train users to avoid unsolicited attachments, and use sandboxing where possible

***

## Hyperlinks

Clickable elements in emails — text, buttons, or images — that open a browser and navigate to a specified URL. Attackers use them to lead targets to:

* Malicious file downloads
* Fake login portals (credential harvesters)
* Redirect chains ending at phishing or malware sites

#### Why They Work

* Most emails contain links, so recipients are accustomed to clicking them
* Appear less suspicious than attachments
* Can be disguised with:
  * **Typosquatted domains**
  * **URL shorteners** to hide the true destination

#### Safe Analysis

* Hover over the link to preview the destination without clicking
* If hidden, open the email in a **text editor** or safe analysis environment (VM, “dirty” system) and look for `<a>`anchor tags
* Never open suspicious links on a production system

#### HTML Anchor Tag Example

```html
<p>Need to access Google? 
<a href="https://www.google.com">Just click this text!</a></p>
```

* `<p>` … `</p>`: paragraph block
* `Need to access Google?`: normal, non-linked text
* `<a href="…">`: opening anchor tag, defines link destination
* `Just click this text!`: clickable link text
* `</a>`: closes the link

#### Key Takeaways

* Hyperlinks can appear safe but lead elsewhere — always verify the actual domain
* HTML inspection reveals the real link even when disguised behind styled text or buttons

***

## URL-Shortening Services

Services like Bitly or Short URL replace long URLs with short versions that redirect to the original destination. Attackers use them to:

* Hide the true destination of a malicious link
* Bypass some automated link analysis tools
* Make links look cleaner and more enticing to click

#### How They Work

* Shortener stores the full URL and issues a short link (e.g., `bit.ly/abc123`)
* Clicking the short link redirects the browser to the stored destination
* Back-half of the short link can often be customized to make it more believable

#### Example (Legitimate Use)

* Original URL: `https://training.AcmeCorp.local/courses/introduction-to-OSINT`
* Shortened (default): `bit.ly/4hT92xQ`
* Shortened (custom): `bit.ly/OSINTCourse`

#### Why This Is Dangerous in Phishing

* Destination URL may lead to:
  * Credential harvesters
  * Malware downloads
  * Typosquatted or homoglyph domains
* Masks the mismatch between brand in email and real domain

#### Analyzing Shortened URLs Safely

* Use an **unshortening service** (e.g., [WannaBrowser](https://wannabrowser.net/)) to preview the resolved URL without visiting it directly
* Look for:
  * Final destination URL
  * Number of redirects
  * HTTP status codes and “Location” headers

**Example CLI Method:**

```bash
# Resolve a Bitly link without opening it in a browser
curl -I "https://bit.ly/4hT92xQ"
HTTP/2 301
location: https://training.AcmeCorp.local/courses/introduction-to-OSINT
```

* `301` = permanent redirect
* `location` shows the final destination

***

## Use of Legitimate Services

Attackers leverage well-known, trusted platforms to send phishing emails or host malicious content, making detection and blocking more difficult for defenders.

#### Email Delivery

* **Tactic:** Use free webmail providers (e.g., `@MailOps.net`, `@SecureMail.net`) to send phishing messages
* **Why Effective:**
  * Organizations rarely block common domains used for legitimate communication (HR queries, customer contact, etc.)
  * Can also use reputable email marketing services (e.g., MailGun, MailChimp) whose IPs are typically whitelisted
* **Impact:** Emails from these services are less likely to be flagged or blocked by security filters

#### File Hosting

* **Tactic:** Host malicious documents on trusted platforms such as Dropbox, OneDrive, or Google Drive
* **Why Effective:**
  * Recognizable domains increase user trust
  * Free and fast account creation
* **Example:**
  * Attacker uploads a Microsoft Word document with malicious macros to `drive.google.com`
  * Sends phishing email containing link to the hosted file
  * Alternatively, uses Google Docs to create a clean-looking document containing a hyperlink to a malicious page, bypassing link inspection in the email body

***

## Business Email Compromise (BEC)

A high-impact phishing attack targeting organizations that regularly transfer large sums of money. BEC can lead to significant financial loss or private information disclosure by leveraging compromised or spoofed email accounts and social engineering.

#### How It Works

* Targets organizations with predictable payment relationships (vendors, suppliers)
* Attacker compromises or spoofs an executive or key employee’s email account
* Uses trust and authority to redirect payments or request sensitive data
* Often involves a **monitoring phase** to study payment patterns before acting
* Highly effective — the FBI reported $1.77B in U.S. losses from BEC in 2019

#### Common Scenarios

**1. Email Compromise & Vendor Attack**

* Compromised payment-handling employee account used to send fake invoices to vendors
* Vendors unknowingly pay into attacker-controlled accounts

**2. Email Spoofing & Alternative Payment Attack**

* Spoofed address sends new payment instructions to vendors
* Future payments redirected to attacker accounts

**3. Email Spoofing & CEO Fraud**

* Attacker impersonates C-suite executive (CEO, CFO, CTO)
* Urgent request to finance staff or bank to transfer funds immediately

**4. Email Spoofing & Data Theft**

* Spoofed employee requests personal or financial data (e.g., tax forms)
* Data used for spear phishing, blackmail, or resale to other attackers

**5. Email Compromise & Zombie Phishing**

* Compromised account replies to existing email threads with malicious links
* High trust factor increases likelihood of clicks

***
