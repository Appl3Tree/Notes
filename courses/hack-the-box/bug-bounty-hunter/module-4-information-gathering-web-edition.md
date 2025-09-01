# Module 4: Information Gathering - Web Edition

## Introduction

### Introduction

Web reconnaissance is the first step in the information gathering phase of penetration testing. Objective: enumerate assets, identify exposures, map the attack surface, and collect intelligence for later use.

***

#### Active Reconnaissance

Direct interaction with the target. Produces detailed results but carries higher detection risk.

***

**Port Scanning**\
Command:

```bash
user01@AcmeCorp:~$ nmap -p- -T4 target.AcmeCorp.local
```

Output:

```
PORT     STATE SERVICE
80/tcp   open  http
443/tcp  open  https
8080/tcp open  http-proxy
```

* `-p-` → scan all 65,535 TCP ports
* `-T4` → faster/aggressive timing (less stealthy)

Purpose: Identify open ports and services. High detection risk.\
Tools: Nmap, Masscan, Unicornscan

***

**Vulnerability Scanning**\
Command:

```bash
user01@AcmeCorp:~$ nikto -h http://target.AcmeCorp.local
```

Output:

```
+ Server: Apache/2.4.50 (Unix)
+ /admin/: Admin login page found
+ /phpinfo.php: Output from phpinfo() found
+ X-Frame-Options header: not present
```

* `-h` → specify target host

Purpose: Probe for misconfigurations and known CVEs. Very noisy; often logged.\
Tools: Nessus, OpenVAS, Nikto

***

**Network Mapping**\
Command:

```bash
user01@AcmeCorp:~$ traceroute target.AcmeCorp.local
```

Output:

```
 1  gw.AcmeCorp.local (10.0.0.1)     1.123 ms
 2  isp-edge.MailOps.net (192.0.2.1) 8.532 ms
 3  target.AcmeCorp.local (203.0.113.10) 18.241 ms
```

Purpose: Show the path packets take across hops to reach the target. Medium–high detection risk.\
Tools: Traceroute, Nmap

***

**Banner Grabbing**\
Command:

```bash
user01@AcmeCorp:~$ nc target.AcmeCorp.local 80
GET / HTTP/1.0

```

Output:

```
HTTP/1.1 200 OK
Server: Apache/2.4.50 (Unix)
Content-Type: text/html; charset=UTF-8
```

Purpose: Retrieve service banners to reveal software and version. Low interaction, but often logged.\
Tools: Netcat, curl

***

**OS Fingerprinting**\
Command:

```bash
user01@AcmeCorp:~$ nmap -O target.AcmeCorp.local
```

Output:

```
OS details: Linux 5.4 - 5.10
Network Distance: 3 hops
```

* `-O` → enable OS detection

Purpose: Identify operating system via TCP/IP fingerprinting. Low detection risk.\
Tools: Nmap, Xprobe2

***

**Service Enumeration**\
Command:

```bash
user01@AcmeCorp:~$ nmap -sV -p80,443,8080 target.AcmeCorp.local
```

Output:

```
80/tcp   open  http    Apache httpd 2.4.50
443/tcp  open  https   nginx 1.18.0
8080/tcp open  http    Jetty 9.4.z-SNAPSHOT
```

* `-sV` → probe open ports to determine service version
* `-p` → specify which ports to scan

Purpose: Gather service versions for vulnerability matching.\
Tools: Nmap

***

**Web Spidering (mapping mode)**\
Command:

```bash
user01@AcmeCorp:~$ wget --spider -r -l 2 -e robots=off -O /dev/null \
    --no-parent --domains=target.AcmeCorp.local -nv -o spider.log http://target.AcmeCorp.local/
```

* `--spider` → spider mode; check links without downloading
* `-r` → recursive crawling
* `-l 2` → recursion depth of 2
* `-e robots=off` → ignore robots.txt rules
* `-O /dev/null` → discard any file output
* `--no-parent` → don’t crawl above start directory
* `--domains=…` → restrict crawl to this domain
* `-nv` + `-o` → quiet output, log results

Purpose: Build a map of site endpoints without saving files.\
Tools: Burp Suite Spider, OWASP ZAP Spider, Scrapy

***

#### Passive Reconnaissance

No direct interaction with target infrastructure. Stealthier, less complete.

***

**Search Engine Queries**\
Command:

```
site:AcmeCorp.local filetype:pdf "confidential"
```

Purpose: Use search operators to locate public documents and leaks. Very low detection risk.\
Tools: Google, DuckDuckGo, Bing, Shodan

***

**WHOIS Lookup**\
Command:

```bash
user01@AcmeCorp:~$ whois AcmeCorp.local
```

Output:

```
Domain Name: ACMECORP.LOCAL
Registrant: Operations Team
Name Server: ns1.AcmeCorp.local
Name Server: ns2.AcmeCorp.local
Updated Date: 2025-07-12
```

Purpose: Retrieve domain ownership, contacts, and nameservers. Very low detection.\
Tools: whois command-line, online WHOIS services

***

**DNS Enumeration**\
Command:

```bash
user01@AcmeCorp:~$ dig axfr @ns1.AcmeCorp.local AcmeCorp.local
```

Output:

```
; Transfer of 'AcmeCorp.local' from ns1.AcmeCorp.local
www     A   203.0.113.10
mail    A   203.0.113.20
dev     A   203.0.113.30
_stage  A   203.0.113.40
; Transfer completed.
```

* `axfr` → request full zone transfer
* `@ns1` → query specific nameserver

Purpose: Collect all DNS records if zone transfer is misconfigured. Very low detection.\
Tools: dig, nslookup, host, dnsenum, fierce, dnsrecon

***

**Web Archive Analysis**\
Command:

```
AcmeCorp.local in Wayback Machine
```

Purpose: Review historical versions of the website for deprecated endpoints and leaks. Very low detection.\
Tools: Wayback Machine

***

**Social Media Analysis**\
Command:

```
site:linkedin.com "AcmeCorp" ("engineer" OR "devops")
```

Purpose: Identify employees, roles, and technologies for pivoting or social engineering. Very low detection.\
Tools: LinkedIn, Twitter, Facebook, specialised OSINT tools

***

**Code Repositories**\
Command:

```
"AcmeCorp" "AWS_SECRET_ACCESS_KEY" site:github.com
```

Purpose: Search public repos for credentials, tokens, or config leaks. Very low detection.\
Tools: GitHub, GitLab

***

## WHOIS

### WHOIS

WHOIS is a query and response protocol for retrieving registration data about internet resources. Primarily used for domains, but also supports IP address ranges and autonomous systems. Think of it as a phonebook for the internet: it shows who owns or manages online assets.

***

**Example Command**

```bash
user01@AcmeCorp:~$ whois AcmeCorp.local
```

Output:

```
Domain Name: AcmeCorp.local
Registry Domain ID: 5420012345_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.registrar.AcmeCorpReg.net
Registrar URL: https://registrar.AcmeCorpReg.net
Updated Date: 2025-07-03T01:11:15Z
Creation Date: 2020-08-05T22:43:09Z
Registrant Contact: Operations Team, AcmeCorp
Administrative Contact: Admin Dept, AcmeCorp
Technical Contact: IT Support, AcmeCorp
Name Server: ns1.AcmeCorp.local
Name Server: ns2.AcmeCorp.local
```

***

#### Typical WHOIS Record Fields

* **Domain Name** → e.g., `example.com`
* **Registrar** → company managing the registration (GoDaddy, Namecheap, etc.)
* **Registrant Contact** → individual/organization who owns the domain
* **Administrative Contact** → responsible for domain management
* **Technical Contact** → handles domain technical issues
* **Creation/Expiration Dates** → when domain was registered, when it expires
* **Name Servers** → servers resolving the domain into IP addresses

***

#### History of WHOIS

Elizabeth Feinler and her team at the Stanford Research Institute’s NIC created the first WHOIS directory in the 1970s for ARPANET resource management. It stored hostnames, users, and domains. This groundwork evolved into the modern WHOIS protocol.

***

#### Why WHOIS Matters for Web Recon

WHOIS records provide valuable intel during reconnaissance:

* **Identifying Key Personnel**\
  Contact details (names, emails, phone numbers) can highlight potential phishing or social engineering targets.
* **Discovering Network Infrastructure**\
  Name servers and IP address data reveal parts of the network footprint, useful for finding entry points or misconfigurations.
* **Historical Data Analysis**\
  Services like [WhoisFreaks](https://whoisfreaks.com/) show how ownership, contacts, or infrastructure changed over time, helping track target evolution.

***

### Utilising WHOIS

WHOIS provides valuable intelligence across multiple scenarios and is a key recon tool for analysts, researchers, and threat hunters.

***

#### Scenario 1: Phishing Investigation

* **Trigger:** Suspicious email flagged by gateway
* **Look for:**
  * Domain registered only days ago
  * Registrant hidden by privacy service
  * Nameservers tied to bulletproof hosting
* **Interpretation:** Strong phishing indicators → block domain, alert employees, investigate hosting/IP for related domains.

***

#### Scenario 2: Malware Analysis

* **Trigger:** Malware communicating with C2 server
* **Look for:**
  * Free/anonymous registrant email
  * Registrant address in high-risk cybercrime country
  * Registrar with lax abuse history
* **Interpretation:** C2 likely on bulletproof/compromised infra → pivot to hosting provider, expand infra hunting.

***

#### Scenario 3: Threat Intelligence Report

* **Trigger:** Tracking activity of a threat actor group
* **Look for:**
  * Clusters of registrations before attacks
  * Fake or alias registrants
  * Shared name servers across campaigns
  * Past takedowns of similar domains
* **Interpretation:** Identify attacker TTPs, generate IOCs, feed into threat intel reporting and detections.

***

#### Using WHOIS

**Install WHOIS on Linux**

```bash
user01@AcmeCorp:~$ sudo apt update
user01@AcmeCorp:~$ sudo apt install whois -y
```

**Perform WHOIS Lookup**

```bash
user01@AcmeCorp:~$ whois AcmeCorp.local
```

Output:

```
Domain Name: AcmeCorp.local
Registry Domain ID: 5420012345_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.registrar.AcmeCorpReg.net
Registrar URL: https://registrar.AcmeCorpReg.net
Updated Date: 2025-04-24T19:06:12Z
Creation Date: 2010-03-29T05:00:00Z
Registry Expiry Date: 2035-03-30T04:00:00Z
Registrar: AcmeCorpReg, LLC
Registrar IANA ID: 4321
Registrar Abuse Contact Email: abuse@AcmeCorpReg.net
Registrar Abuse Contact Phone: +1-555-555-1234
Domain Status: clientDeleteProhibited
Domain Status: clientTransferProhibited
Domain Status: clientUpdateProhibited
Domain Status: serverDeleteProhibited
Domain Status: serverTransferProhibited
Domain Status: serverUpdateProhibited
Name Server: ns1.AcmeCorp.local
Name Server: ns2.AcmeCorp.local
DNSSEC: unsigned
```

***

## DNS & Subdomains

### DNS

The Domain Name System (DNS) translates human-readable domain names into machine-usable IP addresses. It functions like an online GPS, ensuring users don’t need to remember raw IPs when navigating the web. Without DNS, browsing would be like navigating without a map.

***

#### How DNS Works

1. **Local Cache Check** – Computer first checks memory for stored IP mappings.
2. **DNS Resolver Query** – If not cached, query sent to resolver (usually ISP’s).
3. **Root Name Server** – Root directs query to appropriate TLD server.
4. **TLD Name Server** – TLD server points to the authoritative server for the requested domain.
5. **Authoritative Name Server** – Provides the correct IP address.
6. **Resolver Returns Answer** – Resolver gives IP back to computer and caches it.
7. **Client Connects** – Browser connects to the web server using the IP.

Think of DNS as a relay race: request passes from resolver → root → TLD → authoritative → back to resolver → to client.

***

#### Hosts File

A local file that maps hostnames to IP addresses, bypassing DNS. Useful for testing, overrides, or blocking.

* **Windows:** `C:\Windows\System32\drivers\etc\hosts`
* **Linux/macOS:** `/etc/hosts`

Format:

```txt
<IP Address>    <Hostname> [<Alias> ...]
```

Examples:

```txt
127.0.0.1       localhost
192.168.1.10    devserver.local
127.0.0.1       myapp.local        # Redirect for development
192.168.1.20    testserver.local   # Force connection for testing
0.0.0.0         unwanted-site.com  # Block site
```

***

#### Key DNS Concepts

* **Zone** – Portion of namespace managed by an entity. Example: `example.com` and its subdomains.
* **Zone File** – Text file defining resource records. Example:

```zone
$TTL 3600
@   IN SOA  ns1.example.com. admin.example.com. (
            2024060401 ; Serial
            3600       ; Refresh
            900        ; Retry
            604800     ; Expire
            86400 )    ; Minimum TTL
@   IN NS   ns1.example.com.
@   IN NS   ns2.example.com.
@   IN MX 10 mail.example.com.
www IN A    192.0.2.1
mail IN A   198.51.100.1
ftp  IN CNAME www.example.com.
```

***

#### Common DNS Concepts

* **Domain Name** – Human-readable identifier (e.g., `www.example.com`).
* **IP Address** – Numeric identifier (e.g., `192.0.2.1`).
* **DNS Resolver** – Translates names to IPs (ISP resolver, Google DNS 8.8.8.8).
* **Root Name Server** – Top-level servers that direct queries to TLD servers.
* **TLD Name Server** – Responsible for domains like `.com` or `.org`.
* **Authoritative Name Server** – Holds actual IPs for a domain.
* **DNS Record Types** – Store specific info (A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, PTR).

***

#### Common DNS Record Types

*   **A (Address Record)** – Maps hostname to IPv4.

    ```zone
    www.example.com. IN A 192.0.2.1
    ```
*   **AAAA (IPv6 Address Record)** – Maps hostname to IPv6.

    ```zone
    www.example.com. IN AAAA 2001:db8:85a3::8a2e:370:7334
    ```
*   **CNAME (Canonical Name Record)** – Alias to another hostname.

    ```zone
    blog.example.com. IN CNAME webserver.example.net.
    ```
*   **MX (Mail Exchange Record)** – Mail servers for domain.

    ```zone
    example.com. IN MX 10 mail.example.com.
    ```
*   **NS (Name Server Record)** – Delegates a DNS zone.

    ```zone
    example.com. IN NS ns1.example.com.
    ```
*   **TXT (Text Record)** – Arbitrary data, often for verification/security.

    ```zone
    example.com. IN TXT "v=spf1 mx -all"
    ```
*   **SOA (Start of Authority Record)** – Zone administration info.

    ```zone
    example.com. IN SOA ns1.example.com. admin.example.com. 2024060301 10800 3600 604800 86400
    ```
*   **SRV (Service Record)** – Defines hostname/port for services.

    ```zone
    _sip._udp.example.com. IN SRV 10 5 5060 sipserver.example.com.
    ```
*   **PTR (Pointer Record)** – Reverse DNS (IP → hostname).

    ```zone
    1.2.0.192.in-addr.arpa. IN PTR www.example.com.
    ```

{% hint style="info" %}
Note: `IN` = Internet protocol class, almost always used. Other classes (CH, HS) exist but rarely used.
{% endhint %}

***

#### Why DNS Matters for Web Recon

* **Uncovering Assets** – Records may expose subdomains, MX servers, name servers, or outdated CNAMEs (e.g., `dev.example.com → oldserver.example.net`).
* **Mapping Infrastructure** – A/NS/MX records reveal providers, load balancers, and interconnections. Useful for network mapping and identifying choke points.
* **Monitoring for Changes** – New records (e.g., `vpn.example.com`) may indicate new entry points. TXT records may reveal tools in use (`_1password=`), enabling social engineering.

***

### Digging DNS

After reviewing DNS fundamentals and record types, reconnaissance moves into practical tooling. These utilities query DNS servers to extract records, uncover infrastructure, and identify potential entry points.

***

#### DNS Tools

* **dig** – Flexible DNS lookup; supports many record types (A, MX, NS, TXT, etc.), zone transfers, troubleshooting.
* **nslookup** – Simpler DNS lookup; mainly for A, AAAA, MX queries.
* **host** – Streamlined DNS lookups with concise output.
* **dnsenum** – Automates enumeration; brute-forces subdomains, attempts zone transfers.
* **fierce** – Recon and subdomain discovery; recursive search and wildcard detection.
* **dnsrecon** – Combines multiple techniques; outputs in various formats.
* **theHarvester** – OSINT tool; collects DNS records, email addresses, and related data.
* **Online DNS Lookup Services** – Web-based interfaces for quick lookups when CLI tools aren’t available.

***

#### The Domain Information Groper

The `dig` command (Domain Information Groper) is a versatile and powerful utility for querying DNS servers and retrieving various types of DNS records. Its flexibility and detailed output make it a go-to choice for DNS recon.

**Common dig Commands**

* `dig AcmeCorp.local` → Default A record lookup
* `dig AcmeCorp.local A` → IPv4 address
* `dig AcmeCorp.local AAAA` → IPv6 address
* `dig AcmeCorp.local MX` → Mail servers
* `dig AcmeCorp.local NS` → Authoritative name servers
* `dig AcmeCorp.local TXT` → TXT records
* `dig AcmeCorp.local CNAME` → Canonical name record
* `dig AcmeCorp.local SOA` → Start of authority record
* `dig @1.1.1.1 AcmeCorp.local` → Query a specific resolver (Cloudflare in this case)
* `dig +trace AcmeCorp.local` → Show full DNS resolution path
* `dig -x 203.0.113.10` → Reverse lookup for an IP address
* `dig +short AcmeCorp.local` → Short answer only
* `dig +noall +answer AcmeCorp.local` → Display only the answer section
* `dig AcmeCorp.local ANY` → Request all record types (often ignored per RFC 8482)

{% hint style="danger" %}
Note: Some DNS servers may detect or block excessive queries. Always respect rate limits and get permission before performing extensive DNS reconnaissance.
{% endhint %}

***

#### Groping DNS

```bash
user01@AcmeCorp:~$ dig AcmeCorp.local
```

Output:

```
; <<>> DiG 9.18.24-0ubuntu0.22.04.1-Ubuntu <<>> AcmeCorp.local
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 5421
;; flags: qr rd ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;AcmeCorp.local.        IN  A

;; ANSWER SECTION:
AcmeCorp.local.   3600  IN  A   203.0.113.10

;; Query time: 12 msec
;; SERVER: 192.0.2.53#53(192.0.2.53) (UDP)
;; WHEN: Mon Aug 26 14:42:10 UTC 2025
;; MSG SIZE  rcvd: 54
```

**Breakdown**

* **Header:** Type = QUERY, status = NOERROR, transaction ID = 5421
* **Flags:** `qr` (response), `rd` (recursion desired), `ad` (authentic data)
* **Question Section:** Requested A record for AcmeCorp.local
* **Answer Section:** Returned IP 203.0.113.10 with TTL of 3600s
* **Footer:** Response time, responding server, timestamp, message size

**Short Answer Example**

```bash
user01@AcmeCorp:~$ dig +short AcmeCorp.local
```

Output:

```
203.0.113.10
```

***

### Subdomains

Subdomains extend a main domain into functional segments (e.g., `blog.AcmeCorp.local`, `shop.AcmeCorp.local`, `mail.AcmeCorp.local`). They often host resources and services not visible on the main site.

***

#### Why Subdomains Matter in Web Recon

* **Development/Staging Environments** – May be less secure, exposing features or sensitive data.
* **Hidden Login Portals** – Admin panels or internal logins not intended for public access.
* **Legacy Applications** – Old apps may remain online with unpatched vulnerabilities.
* **Sensitive Information** – Configs, docs, or internal data might be exposed.

***

#### Subdomain Enumeration

Process of identifying subdomains, typically via A/AAAA records (direct mappings) or CNAME records (aliases).

**Active Enumeration**

Direct interaction with DNS servers or brute-force guessing.

**Zone Transfer Attempt**

```bash
user01@AcmeCorp:~$ dig axfr @ns1.AcmeCorp.local AcmeCorp.local
```

Output:

```
; Transfer failed.
```

{% hint style="info" %}
Note: Rarely successful due to tightened DNS security.
{% endhint %}

**Brute Force Enumeration with dnsenum**

```bash
user01@AcmeCorp:~$ dnsenum AcmeCorp.local
```

Output:

```
dnsenum.pl VERSION: 1.2.6
Host's addresses:
AcmeCorp.local.   203.0.113.10

Subdomains found:
dev.AcmeCorp.local   203.0.113.20
mail.AcmeCorp.local  203.0.113.30
vpn.AcmeCorp.local   203.0.113.40
```

**Fuzzing Subdomains with ffuf**

```bash
user01@AcmeCorp:~$ ffuf -u http://FUZZ.AcmeCorp.local -w /usr/share/wordlists/subdomains.txt
```

Output:

```
[Status: 200, Size: 1345, Words: 300, Lines: 22]   blog
[Status: 200, Size: 842,  Words: 110, Lines: 18]   shop
[Status: 302, Size: 0,    Words: 1,   Lines: 1]    admin
```

**Brute Force with gobuster**

```bash
user01@AcmeCorp:~$ gobuster dns -d AcmeCorp.local -w /usr/share/wordlists/subdomains.txt
```

Output:

```
Found: api.AcmeCorp.local
Found: staging.AcmeCorp.local
Found: legacy.AcmeCorp.local
```

***

**Passive Enumeration**

No direct interaction with the target. Uses public data.

**Certificate Transparency Logs**

* Example tool: [crt.sh](https://crt.sh/)
* Query: `%.AcmeCorp.local` → returns certificates listing subdomains in SAN fields.

**Search Engine Operators**

* `site:AcmeCorp.local` → reveals indexed subdomains (e.g., `vpn.AcmeCorp.local`, `blog.AcmeCorp.local`).

**Aggregated DNS Databases**

* Public repositories collect DNS records and expose subdomain lists without querying target servers.

***

#### Strategy Note

* **Active Enumeration** – More comprehensive but noisy and detectable.
* **Passive Enumeration** – Stealthier but may miss subdomains.
* **Best Practice** – Combine both for stronger coverage.

***

### Subdomain Bruteforcing

Subdomain brute-force enumeration is an active discovery technique that tests lists of possible names against a target domain to identify valid subdomains. Wordlists are critical:

* **General-purpose** → common names (dev, staging, blog, mail, admin, test).
* **Targeted** → industry- or technology-specific patterns.
* **Custom** → created from intel or observed naming conventions.

***

#### Process

1. **Wordlist Selection** – Choose appropriate wordlist (broad, targeted, or custom).
2. **Iteration and Querying** – Tool appends each word to the domain (e.g., `dev.AcmeCorp.local`).
3. **DNS Lookup** – Query each candidate with A/AAAA lookups.
4. **Filtering/Validation** – Keep resolving subdomains, validate by further checks.

***

#### Tools for Subdomain Brute-Forcing

**DNSEnum**

Perl-based toolkit for DNS recon.

* **Record Enumeration** – A, AAAA, NS, MX, TXT.
* **Zone Transfer Attempts** – Attempts AXFR on name servers.
* **Subdomain Brute-Forcing** – Uses wordlists.
* **Google Scraping** – Finds subdomains via search results.
* **Reverse Lookups** – Maps IPs back to domains.
* **WHOIS Queries** – Gathers registration info.

**Example Command**

```bash
user01@AcmeCorp:~$ dnsenum --enum AcmeCorp.local -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -r
```

* `--enum` → shortcut enabling multiple options (record lookups, transfers, brute force).
* `-f` → specify wordlist.
* `-r` → recursive brute force on discovered subdomains.

**Example Output**

```
-----   AcmeCorp.local   -----

Host's addresses:
AcmeCorp.local.         300 IN A 203.0.113.10

Brute forcing with subdomains-top1million-20000.txt:
www.AcmeCorp.local.     300 IN A 203.0.113.10
support.AcmeCorp.local. 300 IN A 203.0.113.20
dev.AcmeCorp.local.     300 IN A 203.0.113.30
```

***

**Fierce**

Python-based tool for recursive DNS recon.

* Supports **recursive search** (find sub-subdomains).
* Handles **wildcard detection** to reduce false positives.

**Example Command**

```bash
user01@AcmeCorp:~$ fierce --domain AcmeCorp.local --wordlist /usr/share/wordlists/subdomains.txt
```

* `--domain` → target domain.
* `--wordlist` → specify subdomain list.

**Example Output**

```
Found: api.AcmeCorp.local
Found: staging.AcmeCorp.local
Found: vpn.AcmeCorp.local
```

***

**DNSRecon**

Comprehensive enumeration framework.

* Supports **standard record enumeration**, **brute force**, **zone transfers**.
* Can export results in **multiple formats** (JSON, XML, CSV).

**Example Command**

```bash
user01@AcmeCorp:~$ dnsrecon -d AcmeCorp.local -D /usr/share/wordlists/subdomains.txt -t brt
```

* `-d` → target domain.
* `-D` → wordlist file.
* `-t brt` → brute force mode.

**Example Output**

```
[*] Performing standard enumeration...
[+] Found A record: AcmeCorp.local → 203.0.113.10
[+] Found A record: dev.AcmeCorp.local → 203.0.113.30
[+] Found A record: hr.AcmeCorp.local → 203.0.113.50
```

***

**Amass**

Popular subdomain enumeration tool with extensive integrations.

* Supports **brute force**, **API integrations**, and **OSINT sources**.
* Maintains updated databases of discovered assets.

**Example Command**

```bash
user01@AcmeCorp:~$ amass enum -brute -d AcmeCorp.local -w /usr/share/wordlists/subdomains.txt
```

* `enum` → enumeration mode.
* `-brute` → enable brute force.
* `-d` → target domain.
* `-w` → wordlist.

**Example Output**

```
www.AcmeCorp.local
mail.AcmeCorp.local
intranet.AcmeCorp.local
vpn.AcmeCorp.local
```

***

**Assetfinder**

Lightweight tool focused on discovering subdomains.

* Uses OSINT sources and APIs.
* Designed for quick checks.

**Example Command**

```bash
user01@AcmeCorp:~$ assetfinder AcmeCorp.local
```

**Example Output**

```
dev.AcmeCorp.local
support.AcmeCorp.local
legacy.AcmeCorp.local
```

***

**PureDNS**

Efficient brute-forcer and resolver.

* Handles **wildcards** and **filters results**.
* Designed for performance at scale.

**Example Command**

```bash
user01@AcmeCorp:~$ puredns bruteforce /usr/share/wordlists/subdomains.txt AcmeCorp.local
```

**Example Output**

```
Found: qa.AcmeCorp.local → 203.0.113.60
Found: internal.AcmeCorp.local → 203.0.113.70
Found: mobile.AcmeCorp.local → 203.0.113.80
```

***

#### Strategy Note

* **dnsenum / dnsrecon / fierce** → classic brute-forcing and recursive discovery.
* **amass / assetfinder / puredns** → modern, scalable, OSINT-integrated.
* **Best Practice** → combine both classes of tools for comprehensive coverage and validation.

***

### DNS Zone Transfers

Zone transfers are designed for replication between DNS servers but can expose a complete domain map if misconfigured.

***

#### What is a Zone Transfer

A DNS zone transfer is a copy of all records in a zone (domain and subdomains) from one server to another. It ensures redundancy and consistency across DNS infrastructure.

**Steps in the process:**

1. **Zone Transfer Request (AXFR):** Secondary server requests transfer from primary.
2. **SOA Record Transfer:** Primary sends Start of Authority (SOA) record with zone details.
3. **DNS Records Transmission:** All records (A, AAAA, MX, CNAME, NS, etc.) are transferred.
4. **Zone Transfer Complete:** Primary signals end of records.
5. **Acknowledgement:** Secondary confirms receipt.

***

#### The Zone Transfer Vulnerability

If misconfigured, anyone can request a zone transfer and obtain:

* **Subdomains** – complete list, including hidden or internal services.
* **IP Addresses** – mappings for each subdomain, useful for network recon.
* **Name Server Records** – reveals authoritative servers and potential hosting info.

This effectively hands over the target’s DNS map. Historically common, but now mitigated by restricting transfers to trusted secondary servers. Misconfigurations still appear due to human error or outdated setups.

***

#### Exploiting Zone Transfers

Use `dig` to attempt a transfer:

```bash
user01@AcmeCorp:~$ dig axfr @ns1.AcmeCorp.local AcmeCorp.local
```

* `axfr` → request a full zone transfer.
* `@ns1.AcmeCorp.local` → query specific name server.
* `AcmeCorp.local` → target domain.

**Example Output (fictionalized):**

```
; <<>> DiG 9.18.12-1~Debian <<>> axfr @ns1.AcmeCorp.local AcmeCorp.local
;; (1 server found)
;; global options: +cmd

AcmeCorp.local.      7200 IN SOA ns1.AcmeCorp.local. admin.AcmeCorp.local. 2025083001 172800 900 1209600 3600
AcmeCorp.local.      7200 IN MX  10 mail.AcmeCorp.local.
AcmeCorp.local.      7200 IN NS  ns1.AcmeCorp.local.
AcmeCorp.local.      7200 IN NS  ns2.AcmeCorp.local.
www.AcmeCorp.local.  7200 IN A   203.0.113.10
dev.AcmeCorp.local.  7200 IN A   203.0.113.20
vpn.AcmeCorp.local.  7200 IN A   203.0.113.30
admin.AcmeCorp.local.7200 IN A   203.0.113.40
...
;; Query time: 8 msec
;; SERVER: 203.0.113.53#53(ns1.AcmeCorp.local) (TCP)
;; WHEN: Sat Aug 30 16:12:45 UTC 2025
;; XFR size: 25 records
```

***

#### Remediation

* Restrict zone transfers to **trusted secondary servers** only.
* Monitor logs for **unauthorized AXFR requests**.
* Regularly review DNS server configs for errors.

***

#### Field Notes

* Safe practice domain: **zonetransfer.me** (intentionally misconfigured for training).
* Quick test command: `dig axfr @nsztm1.digi.ninja zonetransfer.me`
* If a real target responds with records → **severe misconfiguration**, report immediately.

***

### Virtual Hosts

Virtual hosting allows one web server to serve multiple sites using the HTTP Host header. Servers such as [Apache HTTP Server](https://httpd.apache.org/), [Nginx](https://nginx.org/), and [Microsoft IIS](https://www.iis.net/) support this to separate domains, subdomains, and application roots.

***

#### How Virtual Hosts Work: VHosts vs Subdomains

* **Subdomains:** blog.example.com → DNS record for parent domain; resolves to same or different IPs; used for segmentation.
* **VHosts:** Server configs mapping Host header → document root and settings. Supports top-level domains and subdomains.
* **Local Overrides:** /etc/hosts or hosts file entry bypasses DNS.
* **Private Names:** Internal subdomains not in public DNS; discovered via VHost fuzzing.

```apacheconf

# Apache name-based virtual hosts

    ServerName www.example1.com
    DocumentRoot /var/www/example1



    ServerName www.example2.org
    DocumentRoot /var/www/example2



    ServerName www.another-example.net
    DocumentRoot /var/www/another-example

```

***

#### Server VHost Lookup

1. Browser requests server IP with Host header.
2. Web server reads Host header.
3. Server matches to VHost config.
4. Files from matched document root returned.

***

#### Types of Virtual Hosting

* **Name-Based:** Common. Host header selects site. One IP, many sites. Requires SNI for TLS.
* **IP-Based:** Each site has unique IP. Protocol-agnostic. More isolation. Consumes IPs.
* **Port-Based:** Different sites on different ports (80, 8080). Saves IPs, requires port in URL.

**Field Notes:**

* Use name-based by default.
* IP-based if isolation or legacy TLS required.
* Port-based suitable for admin tools/labs.

***

#### Virtual Host Discovery Tools

| Tool                                                 | Description                        | Features                                       |
| ---------------------------------------------------- | ---------------------------------- | ---------------------------------------------- |
| [gobuster](https://github.com/OJ/gobuster)           | Bruteforce vhosts via Host header. | Fast, custom wordlists, multiple HTTP methods. |
| [Feroxbuster](https://github.com/epi052/feroxbuster) | Rust-based fuzzer.                 | Recursion, wildcard handling, filters.         |
| [ffuf](https://github.com/ffuf/ffuf)                 | Header fuzzing tool.               | Flexible matches, filters, wordlists.          |

***

#### gobuster

* Bruteforces Host headers against target IP.
* Valid vhosts return distinct responses.

**Preparation:**

* Identify target server IP.
* Use curated or custom wordlist.

**Command Usage:**

```bash

analyst1@acmecorp:~$ gobuster vhost -u http://<target_ip> -w <wordlist> --append-domain
```

* `-u` = target URL/IP.
* `-w` = wordlist path.
* `--append-domain` required in newer versions.

**Version Notes:** Older releases appended base domain automatically; newer require `--append-domain`.

**Performance and Output:**

* `-t` = threads.
* `-k` = ignore TLS errors.
* `-o` = save output file.

**Example:**

```bash

analyst1@acmecorp:/opt$ gobuster vhost -u http://AcmeCorp.local:81 \
    -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
    --append-domain
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://AcmeCorp.local:81
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: forum.AcmeCorp.local:81     Status: 200   [Size: 100]
[...]
Progress: 114441 / 114442 (100.00%)
===============================================================
Finished
===============================================================
```

**Field Notes:**

* Adjust `-t` carefully; too high = rate limiting.
* Save output with `-o` for review.
* Validate small-size 200 responses (may be default pages).

***

### Certificate Transparency Logs

SSL/TLS certificates enable encrypted communication between browsers and websites. Attackers can abuse mis-issued or rogue certificates to impersonate domains, intercept data, or spread malware. Certificate Transparency (CT) logs mitigate this risk by recording certificate issuance publicly.

***

#### What are Certificate Transparency Logs?

* CT logs = public, append-only ledgers of SSL/TLS certificates.
* Certificate Authorities (CAs) must submit new certificates to multiple CT logs.
* Maintained by independent organisations, open for inspection.

**Purposes:**

* **Early Detection:** Spot rogue/misissued certificates early, revoke before abuse.
* **CA Accountability:** Public visibility of issuance practices; missteps damage trust.
* **Strengthen Web PKI:** Adds oversight and verification to the Public Key Infrastructure.

**Field Notes:**

* Think of CT logs as a global registry of certificates.
* Transparency = trust enforcement for CAs.

***

#### CT Logs and Web Recon

* Subdomain enumeration from CT logs = based on actual certificate records, not guesses.
* Reveals historical and inactive subdomains (expired/old certs).
* Exposes assets missed by brute-force or wordlist-based methods.

***

#### Searching CT Logs

| Tool                               | Key Features                                                         | Use Cases                                          | Pros                                          | Cons                               |
| ---------------------------------- | -------------------------------------------------------------------- | -------------------------------------------------- | --------------------------------------------- | ---------------------------------- |
| [crt.sh](https://crt.sh)           | Web interface, search by domain, shows cert details and SAN entries. | Quick subdomain checks, certificate history.       | Free, no registration, simple to use.         | Limited filtering and analysis.    |
| [Censys](https://search.censys.io) | Search engine for devices and certificates, advanced filtering.      | Deep analysis, misconfig detection, related hosts. | Extensive data, API access, flexible filters. | Requires registration (free tier). |

**Field Notes:**

* crt.sh = fast, simple queries.
* Censys = powerful filtering + pivoting on cert/IP attributes.

***

#### crt.sh Lookup

API queries allow automation. Example: find “dev” subdomains for facebook.com.

```bash

analyst1@acmecorp:~$ curl -s "https://crt.sh/?q=facebook.com&output=json" \
| jq -r '.[] | select(.name_value | contains("dev")) | .name_value' | sort -u

*.dev.facebook.com
*.newdev.facebook.com
*.secure.dev.facebook.com
dev.facebook.com
devvm1958.ftw3.facebook.com
facebook-amex-dev.facebook.com
facebook-amex-sign-enc-dev.facebook.com
newdev.facebook.com
secure.dev.facebook.com
```

* `curl` fetches JSON output from crt.sh.
* `jq` filters `name_value` fields containing "dev".
* `sort -u` removes duplicates, sorts results.

***

## Fingerprinting

### Fingerprinting

Fingerprinting extracts technical details about the technologies behind a site to expose stack components, versions, and potential weaknesses. Findings guide targeted exploitation, reveal misconfigurations, and help prioritize targets.

***

#### Why Fingerprinting Matters

* **Targeted Attacks:** Map tech/version → known exploits.
* **Find Misconfigurations:** Default settings, outdated software, risky headers.
* **Prioritization:** Focus on systems with higher risk/value.
* **Comprehensive Profile:** Combine with other recon for full context.

**Field Notes:**

* Correlate versions with CVEs; validate before exploitation.
* Respect scope and authorization boundaries.

***

#### Fingerprinting Techniques

* **Banner Grabbing:** Read service banners for product/version.
* **HTTP Header Analysis:** Inspect `Server`, `X-Powered-By`, security headers.
* **Probing for Specific Responses:** Send crafted requests; analyze unique errors/behaviors.
* **Page Content Analysis:** Inspect HTML/JS; look for framework/CMS artifacts and comments.

***

#### Tools

| Tool                                                            | Description                   | Features                                 |
| --------------------------------------------------------------- | ----------------------------- | ---------------------------------------- |
| [Wappalyzer](https://www.wappalyzer.com/)                       | Browser/online tech profiler. | CMS, frameworks, analytics, more.        |
| [BuiltWith](https://builtwith.com/)                             | Technology stack reports.     | Free + paid tiers, detailed inventories. |
| [WhatWeb](https://www.morningstarsecurity.com/research/whatweb) | CLI fingerprinting.           | Large signature database.                |
| [Nmap](https://nmap.org/)                                       | Network scanner.              | Service/OS detection, NSE scripts.       |
| [Netcraft](https://www.netcraft.com/)                           | Web security intelligence.    | Hosting, tech, risk reporting.           |
| [wafw00f](https://github.com/EnableSecurity/wafw00f)            | WAF detection (CLI).          | Identifies WAF product/family.           |

***

#### Fingerprinting SecureMail.net

Apply manual + automated techniques to a purpose-built host (_external demo domain_).

**Banner Grabbing**

Fetch headers only with [curl](https://curl.se/):

```bash

analyst1@acmecorp:~$ curl -I securemail.net
HTTP/1.1 301 Moved Permanently
Date: Fri, 31 May 2024 12:07:44 GMT
Server: Apache/2.4.41 (Ubuntu)
Location: https://securemail.net/
Content-Type: text/html; charset=iso-8859-1
```

Follow the redirect to HTTPS:

```bash

analyst1@acmecorp:~$ curl -I https://securemail.net
HTTP/1.1 301 Moved Permanently
Date: Fri, 31 May 2024 12:12:12 GMT
Server: Apache/2.4.41 (Ubuntu)
X-Redirect-By: WordPress
Location: https://www.securemail.net/
Content-Type: text/html; charset=UTF-8
```

Final destination:

```bash

analyst1@acmecorp:~$ curl -I https://www.securemail.net
HTTP/1.1 200 OK
Date: Fri, 31 May 2024 12:12:26 GMT
Server: Apache/2.4.41 (Ubuntu)
Link: <https://www.securemail.net/index.php/wp-json/>; rel="https://api.w.org/"
Link: <https://www.securemail.net/index.php/wp-json/wp/v2/pages/7>; rel="alternate"; type="application/json"
Link: <https://www.securemail.net/>; rel=shortlink
Content-Type: text/html; charset=UTF-8
```

***

**wafw00f**

Detect presence/type of WAF with [wafw00f](https://github.com/EnableSecurity/wafw00f):

```bash

analyst1@acmecorp:~$ wafw00f securemail.net

                ______
               /      \
              (  W00f! )
               \  ____/
               ,,    __            404 Hack Not Found
           |`-.__   / /                      __     __
           /"  _/  /_/                       \ \   / /
          *===*    /                          \ \_/ /  405 Not Allowed
         /     )__//                           \   /
    /|  /     /---`                        403 Forbidden
    \\/`   \ |                                 / _ \
    `\    /_\\_              502 Bad Gateway  / / \ \  500 Internal Error
      `_____``-`                             /_/   \_\

                        ~ WAFW00F : v2.2.0 ~
        The Web Application Firewall Fingerprinting Toolkit

[*] Checking https://securemail.net
[+] The site https://securemail.net is behind Wordfence (Defiant) WAF.
[~] Number of requests: 2
```

***

**Nikto (Fingerprinting Modules)**

Use [Nikto](https://github.com/sullo/nikto) for software identification (`-Tuning b`):

```bash

analyst1@acmecorp:~$ nikto -h securemail.net -Tuning b

- Nikto v2.5.0
---------------------------------------------------------------------------
+ Multiple IPs found: 203.0.113.25, 2001:db8:1:e0::32c:b001
+ Target IP:          203.0.113.25
+ Target Hostname:    www.securemail.net
+ Target Port:        443
---------------------------------------------------------------------------
+ SSL Info:        Subject:  /CN=securemail.net
                   Altnames: securemail.net, www.securemail.net
                   Ciphers:  TLS_AES_256_GCM_SHA384
                   Issuer:   /C=US/O=Let's Encrypt/CN=R3
+ Start Time:         2024-05-31 13:35:54 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ /: Link header found with value: ARRAY(0x55ab78790248).
+ /: Strict-Transport-Security header is not defined.
+ /: X-Content-Type-Options header is not set.
+ /index.php?: Uncommon header 'x-redirect-by' found: WordPress.
+ No CGI Directories found (use '-C all' to force)
+ /: Content-Encoding "deflate" (check BREACH considerations).
+ Apache/2.4.41 appears to be outdated (current is at least 2.4.59).
+ /: Valid response to junk HTTP methods (may cause false positives).
+ /license.txt: License file found may identify software.
+ /: A WordPress installation was found.
+ /wp-login.php?action=register: Cookie wordpress_test_cookie without HttpOnly.
+ /wp-login.php: X-Frame-Options deprecated; prefer CSP frame-ancestors.
+ /wp-login.php: WordPress login found.
+ 1316 requests: 0 error(s) and 12 item(s) reported on remote host
+ End Time:           2024-05-31 13:47:27 (GMT0) (693 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

**Field Notes:**

* Dual-stack IPs observed (IPv4 + IPv6).
* Apache/2.4.41 (Ubuntu) + WordPress; check for known CVEs and hardening gaps.
* Headers: add HSTS; set `X-Content-Type-Options: nosniff`; review redirects.
* Outdated server version → verify before reporting; consider vendor backports.

***

## Crawling

### Crawling

#### Concept

* Crawling (spidering) = automated bots systematically browse the web.
* Process: **seed URL** → fetch page → extract links → add to queue → repeat.
* Purpose: indexing, reconnaissance, mapping.

#### Example Crawl

```
Homepage
├── link1
├── link2
└── link3
```

* **Homepage** shows `link1`, `link2`, `link3`.
* Visiting **link1** reveals: `Homepage`, `link2`, `link4`, `link5`.
* Crawler continues expanding until all reachable links are found.
* Difference from fuzzing: crawling follows discovered links; fuzzing guesses paths.

#### Strategies

* **Breadth-First**: explore wide first, level by level. Best for site overview.
* **Depth-First**: follow one path deep, then backtrack. Best for nested content.

#### Data Collected

* **Links (internal/external):** map structure, hidden areas, external ties.
* **Comments:** may leak sensitive info.
* **Metadata:** titles, keywords, authors, timestamps.
* **Sensitive files:** backups (`.bak`, `.old`), configs (`web.config`, `settings.php`), logs, credentials, snippets.

#### Context

* One data point (e.g., “software version” in a comment) grows in value when linked with:
  * Metadata showing outdated software.
  * Exposed config/backup files.
* Example: repeated `/files/` directory → open browsing exposes archives/docs.
* Example: “file server” in comments + `/files/` discovery = exposed storage confirmed.

***

### robots.txt

***

#### Concept

* `robots.txt` = simple text file in a website’s root directory (`www.example.com/robots.txt`).
* Follows the **Robots Exclusion Standard** to guide crawlers.
* Acts like an etiquette guide: tells bots which areas they may or may not access.

#### Structure

* Organized into **records**, separated by blank lines.
* Each record =
  * **User-agent** → specifies which bot (e.g., `*` for all, `Googlebot`, `Bingbot`).
  * **Directives** → instructions for that bot.

#### Common Directives

| Directive       | Description                                                           | Example                                        |
| --------------- | --------------------------------------------------------------------- | ---------------------------------------------- |
| **Disallow**    | Block crawling of specified path(s).                                  | `Disallow: /admin/`                            |
| **Allow**       | Explicitly permit crawling of a path even under broader restrictions. | `Allow: /public/`                              |
| **Crawl-delay** | Sets time (seconds) between requests.                                 | `Crawl-delay: 10`                              |
| **Sitemap**     | Points bots to XML sitemap.                                           | `Sitemap: https://www.example.com/sitemap.xml` |

#### Example

```
User-agent: *
Disallow: /admin/
Disallow: /private/
Allow: /public/

User-agent: Googlebot
Crawl-delay: 10

Sitemap: https://www.example.com/sitemap.xml
```

* All bots blocked from `/admin/` and `/private/`.
* All bots allowed into `/public/`.
* Googlebot must wait 10s between requests.
* Sitemap provided at `/sitemap.xml`.

#### Importance

* **Server protection:** avoids overload from aggressive bots.
* **Sensitive info:** prevents indexing of private/confidential areas.
* **Compliance:** ignoring rules can breach terms of service or laws.
* **Limitations:** not enforceable—rogue bots can ignore it.

#### Use in Reconnaissance

* **Hidden directories:** disallowed entries often reveal admin panels, backups, or sensitive files.
* **Mapping:** disallow/allow entries create a rough site structure.
* **Crawler traps:** honeypot directories may be listed to catch malicious bots.

***

### .Well-Known URIs

#### Concept

* Defined in **RFC 8615**, `.well-known` is a standardized directory located at `/.well-known/` in a website’s root.
* Provides a central location for metadata and configuration files.
* Purpose: simplify discovery and access for browsers, apps, and security tools.
* Example: `https://example.com/.well-known/security.txt` → security policy information.

#### IANA Registry

* Registry maintained by the **Internet Assigned Numbers Authority (IANA)**.
* Each URI suffix is tied to a specification and standard.

| URI Suffix             | Description                                                        | Status      | Reference   |
| ---------------------- | ------------------------------------------------------------------ | ----------- | ----------- |
| `security.txt`         | Contact info for security researchers to report vulnerabilities    | Permanent   | RFC 9116    |
| `change-password`      | Standard URL for directing users to a password change page         | Provisional | W3C draft   |
| `openid-configuration` | Configuration details for OpenID Connect (OIDC)                    | Permanent   | OpenID spec |
| `assetlinks.json`      | Verifies ownership of digital assets (e.g., apps) linked to domain | Permanent   | Google spec |
| `mta-sts.txt`          | Policy for SMTP MTA Strict Transport Security (MTA-STS)            | Permanent   | RFC 8461    |

#### Web Recon Use

* `.well-known` entries often reveal endpoints and configurations of interest.
* Reconnaissance value: discover hidden areas, authentication details, or security policies.
* Particularly useful: **`openid-configuration`** endpoint.

#### Example: OpenID Connect Discovery

Endpoint: `https://example.com/.well-known/openid-configuration`

**Sample JSON Response:**

```json
{
  "issuer": "https://example.com",
  "authorization_endpoint": "https://example.com/oauth2/authorize",
  "token_endpoint": "https://example.com/oauth2/token",
  "userinfo_endpoint": "https://example.com/oauth2/userinfo",
  "jwks_uri": "https://example.com/oauth2/jwks",
  "response_types_supported": ["code", "token", "id_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "profile", "email"]
}
```

***

### Creepy Crawlies

#### Popular Web Crawlers

* **Burp Suite Spider** → integrated crawler in Burp Suite, maps applications, identifies hidden content, and uncovers vulnerabilities.
* **OWASP ZAP Spider** → part of ZAP, a free and open-source scanner; supports automated and manual crawling.
* **Scrapy** → Python framework for custom crawlers; powerful for structured data extraction and tailored reconnaissance.
* **Apache Nutch** → Java-based, extensible, scalable crawler; suitable for massive crawls or domain-focused projects.

{% hint style="info" %}
_Note: always follow ethical practices, obtain permission before crawling, and avoid overloading servers with excessive requests._
{% endhint %}

#### Scrapy

* Used here with a custom spider called **ReconSpider** for reconnaissance on `AcmeCorp.local`.
* Additional information on crawling techniques is covered in the “Using Web Proxies” module in CBBH.

#### Installing Scrapy

```bash
pcte-analyst1@lab[/lab]$ pip3 install scrapy
```

* Installs Scrapy and its dependencies.

#### ReconSpider

* Download and extract the custom spider:

```bash
pcte-analyst1@lab[/lab]$ wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip
$ unzip ReconSpider.zip
```

* Run the spider against a target:

```bash
pcte-analyst1@lab[/lab]$ python3 ReconSpider.py http://AcmeCorp.local
```

* Replace domain with target of choice.
* Output is saved to `results.json`.

#### results.json

**Sample structure:**

```json
{
    "emails": [
        "jane.smith@AcmeCorp.local",
        "contact@AcmeCorp.local"
    ],
    "links": [
        "https://www.SecureMail.net",
        "https://www.AcmeCorp.local/index.php/offices/"
    ],
    "external_files": [
        "https://www.AcmeCorp.local/files/reports/finance_goals.pdf"
    ],
    "js_files": [
        "https://www.AcmeCorp.local/assets/js/jquery/jquery-migrate.min.js?ver=3.3.2"
    ],
    "form_fields": [],
    "images": [
        "https://www.AcmeCorp.local/assets/images/AboutUs_01.png"
    ],
    "videos": [],
    "audio": [],
    "comments": [
        "<!-- #header -->"
    ]
}
```

#### JSON Keys

| Key                 | Description                   |
| ------------------- | ----------------------------- |
| **emails**          | Email addresses found.        |
| **links**           | Internal and external links.  |
| **external\_files** | External files such as PDFs.  |
| **js\_files**       | JavaScript files referenced.  |
| **form\_fields**    | HTML form fields.             |
| **images**          | Image files referenced.       |
| **videos**          | Video files (if found).       |
| **audio**           | Audio files (if found).       |
| **comments**        | HTML comments in source code. |

***

## Search Engine Discovery

### Search Engine Discovery

#### Concept

* Also called **OSINT (Open Source Intelligence) gathering**.
* Uses search engines as reconnaissance tools to uncover information on websites, organizations, and individuals.
* Leverages indexing and search operators to extract data not directly visible on target sites.

#### Importance

* **Open Source** → publicly accessible, legal, and ethical.
* **Broad Coverage** → access to a wide range of indexed data.
* **Ease of Use** → requires no advanced technical skills.
* **Cost-Effective** → freely available resource.

#### Applications

* **Security Assessment** → identify vulnerabilities, exposed data, login pages.
* **Competitive Intelligence** → gather data on competitors’ products, services, strategies.
* **Investigative Journalism** → reveal hidden connections or unethical practices.
* **Threat Intelligence** → track malicious actors and emerging threats.

{% hint style="info" %}
_Limitation: search engines do not index everything; some data is hidden or protected._
{% endhint %}

#### Search Operators

Operators refine searches to uncover precise information. Syntax may vary by search engine.

| Operator              | Description                 | Example                                  | Example Meaning                              |
| --------------------- | --------------------------- | ---------------------------------------- | -------------------------------------------- |
| `site:`               | Limit results to a domain   | `site:AcmeCorp.local`                    | Find indexed pages on AcmeCorp.local         |
| `inurl:`              | Match term in URL           | `inurl:login`                            | Look for login pages                         |
| `filetype:`           | Find specific file types    | `filetype:pdf`                           | Locate PDF documents                         |
| `intitle:`            | Match term in page title    | `intitle:"confidential report"`          | Find pages titled with “confidential report” |
| `intext:` / `inbody:` | Match term in body          | `intext:"password reset"`                | Find text mentioning password reset          |
| `cache:`              | Show cached version         | `cache:AcmeCorp.local`                   | View cached snapshot                         |
| `link:`               | Find backlinks              | `link:AcmeCorp.local`                    | Show sites linking to AcmeCorp.local         |
| `related:`            | Find similar sites          | `related:AcmeCorp.local`                 | Show similar websites                        |
| `info:`               | Show page details           | `info:AcmeCorp.local`                    | Get metadata on domain                       |
| `define:`             | Provide definitions         | `define:phishing`                        | Fetch definitions of phishing                |
| `numrange:`           | Search within number ranges | `site:AcmeCorp.local numrange:1000-2000` | Find numbers in range                        |
| `allintext:`          | Match all words in body     | `allintext:admin password reset`         | Find both terms in body                      |
| `allinurl:`           | Match all words in URL      | `allinurl:admin panel`                   | Find “admin panel” in URLs                   |
| `allintitle:`         | Match all words in title    | `allintitle:confidential report 2025`    | Find these words in titles                   |
| `AND`                 | Require all terms           | `site:AcmeCorp.local AND inurl:admin`    | Find admin pages on AcmeCorp.local           |
| `OR`                  | Match any term              | `"Linux" OR "Ubuntu"`                    | Find pages with either term                  |
| `NOT`                 | Exclude terms               | `site:BankCorp.local NOT inurl:login`    | Find pages excluding login                   |
| `*` (wildcard)        | Placeholder for words       | `filetype:pdf user* manual`              | Match “user guide,” “user handbook,” etc.    |
| `..`                  | Range search                | `"price" 100..500`                       | Match numbers between 100 and 500            |
| `""` (quotes)         | Exact phrase search         | `"information security policy"`          | Match the exact phrase                       |
| `-` (minus)           | Exclude term                | `site:NewsPortal.net -inurl:sports`      | Exclude sports content                       |

#### Google Dorking

* Technique using Google search operators to find sensitive or hidden information.
* Often referenced in the [**Google Hacking Database**](https://www.exploit-db.com/google-hacking-database).

**Examples:**

* **Login Pages**
  * `site:AcmeCorp.local inurl:login`
  * `site:AcmeCorp.local (inurl:login OR inurl:admin)`
* **Exposed Files**
  * `site:AcmeCorp.local filetype:pdf`
  * `site:AcmeCorp.local (filetype:xls OR filetype:docx)`
* **Configuration Files**
  * `site:AcmeCorp.local inurl:config.php`
  * `site:AcmeCorp.local (ext:conf OR ext:cnf)`
* **Database Backups**
  * `site:AcmeCorp.local inurl:backup`
  * `site:AcmeCorp.local filetype:sql`

***

## Web Archives

### Web Archives

#### What is the Wayback Machine?

* A digital archive of the **World Wide Web** and other internet resources.
* Created by the **Internet Archive**, a non-profit organization.
* Online since 1996, capturing website snapshots (“archives” or “captures”).
* Allows users to revisit earlier versions of websites, showing historical design, content, and functionality.

#### How it Works

**Three-step process:**

1. **Crawling** → Automated bots systematically browse websites, following links and downloading pages.
2. **Archiving** → Pages and resources (HTML, CSS, JS, images, etc.) are stored with a timestamp, creating a snapshot.
3. **Accessing** → Users enter a URL and select a date to view historical captures, search terms within archives, or download archived content.

* Frequency of snapshots varies (multiple daily to few per year).
* Influenced by popularity, update rate, and Internet Archive resources.
* Not every page is captured; priority is given to cultural, historical, or research value.
* Website owners can request exclusions, though not always guaranteed.

#### Reconnaissance Value

* **Uncover Hidden Assets** → Old pages, files, directories, or subdomains may expose sensitive data.
* **Track Changes** → Compare historical snapshots to identify shifts in structure, technologies, or vulnerabilities.
* **Gather Intelligence** → Archived content provides OSINT on past activities, marketing, employees, and technology.
* **Stealthy Reconnaissance** → Accessing archives is passive, leaving no trace on the target’s infrastructure.

#### Example

* The first archived version of **HackTheBox** is available on the Wayback Machine.
* Earliest capture: **2017-06-10 @ 04:23:01**.

***

## Automating Recon

### Automating Recon

***

#### Why Automate Reconnaissance?

Automation improves web reconnaissance by:

* **Efficiency** → handles repetitive tasks faster than humans.
* **Scalability** → expands recon across many targets or domains.
* **Consistency** → follows rules for reproducible results and fewer errors.
* **Comprehensive Coverage** → tasks include DNS enumeration, subdomain discovery, crawling, port scanning, etc.
* **Integration** → frameworks connect with other tools for seamless workflows.

#### Reconnaissance Frameworks

* [**FinalRecon**](https://github.com/thewhiteh4t/FinalRecon) → Python tool with modules for SSL checks, Whois, headers, crawling, DNS, subdomains, and directories.
* [**Recon-ng** ](https://github.com/lanmaster53/recon-ng)→ modular Python framework for DNS, subdomains, crawling, port scanning, and vulnerability exploitation.
* [**theHarvester**](https://github.com/laramies/theHarvester) → gathers emails, subdomains, employee names, and host data from search engines, PGP servers, Shodan, etc.
* [**SpiderFoot**](https://github.com/smicallef/spiderfoot) → OSINT automation tool collecting IPs, domains, emails, and social media data; supports DNS lookups, crawling, and port scans.
* [**OSINT Framework**](https://osintframework.com/) → curated collection of OSINT tools and resources.

#### FinalRecon

Capabilities include:

* **Header Information** → server details, technologies, security misconfigurations.
* **Whois Lookup** → domain registration and contact details.
* **SSL Certificate Info** → validity, issuer, and details.
* **Crawler** → extracts links, resources, comments, `robots.txt`, and `sitemap.xml`.
* **DNS Enumeration** → supports over 40 record types.
* **Subdomain Enumeration** → queries crt.sh, AnubisDB, ThreatMiner, CertSpotter, VirusTotal API, Shodan API, etc.
* **Directory Enumeration** → custom wordlists/extensions to uncover hidden files/paths.
* **Wayback Machine** → retrieves URLs from historical archives.
* **Fast Port Scan** → quick service discovery.
* **Full Recon** → runs all modules together.

#### Installing FinalRecon

```bash
pcte-analyst1@lab[/lab]$ git clone https://github.com/thewhiteh4t/FinalRecon.git
$ cd FinalRecon
$ pip3 install -r requirements.txt
$ chmod +x ./finalrecon.py
$ ./finalrecon.py --help
```

**Help Output (excerpt):**

```
usage: finalrecon.py [--url URL] [--headers] [--sslinfo] [--whois]
                     [--crawl] [--dns] [--sub] [--dir] [--wayback] [--ps]
                     [--full] ...

--url URL   Target URL
--headers   Header Information
--sslinfo   SSL Certificate Information
--whois     Whois Lookup
--crawl     Crawl Target
--dns       DNS Enumeration
--sub       Sub-Domain Enumeration
--dir       Directory Search
--wayback   Wayback URLs
--ps        Fast Port Scan
--full      Full Recon
```

#### Example Command

Gather header information and Whois lookup for `AcmeCorp.local`:

```bash
pcte-analyst1@lab[/FinalRecon]$ ./finalrecon.py --headers --whois --url http://AcmeCorp.local
```

**Sample Output (excerpt):**

```
[+] Target : http://AcmeCorp.local
[!] Headers :
Date : Tue, 11 Jun 2024 10:08:00 GMT
Server : Apache/2.4.41 (Ubuntu)
Content-Type : text/html; charset=UTF-8

[!] Whois Lookup :
Domain Name: ACMECORP.LOCAL
Registrar: Example Registrar, Inc.
Updated Date: 2023-07-03T01:11:15Z
Creation Date: 2019-08-05T22:43:09Z
Registry Expiry Date: 2024-08-05T22:43:09Z
Name Server: NS1.AcmeCorp.local
Name Server: NS2.AcmeCorp.local
```

***
