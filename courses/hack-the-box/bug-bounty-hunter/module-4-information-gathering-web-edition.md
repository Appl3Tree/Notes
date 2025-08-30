# Module 4: Information Gathering - Web Edition

### Introduction

Web reconnaissance is the first step in information gathering during penetration testing. Goal: map assets, discover hidden data, analyse attack surface, and collect intelligence. Used by attackers to plan and by defenders to harden.

***

#### Active Reconnaissance

Direct interaction with the target. Detailed results; higher detection risk.

<table><thead><tr><th>Technique</th><th>Command Example</th><th>Sample Output</th><th>Notes</th></tr></thead><tbody><tr><td>Port Scanning</td><td><pre class="language-bash"><code class="lang-bash">
user01@acme:~$ nmap -p- -T4 target.AcmeCorp.local
      
</code></pre></td><td><pre><code>
PORT     STATE SERVICE
80/tcp   open  http
443/tcp  open  https
8080/tcp open  http-proxy
      
</code></pre></td><td>Finds open ports/services. High detection risk.</td></tr><tr><td>Vulnerability Scanning</td><td><pre class="language-bash"><code class="lang-bash">
user01@acme:~$ nikto -h http://target.AcmeCorp.local
      
</code></pre></td><td><pre><code>
+ Server: Apache/2.4.50 (Unix)
+ /admin/: Admin login page found
+ /phpinfo.php: Output from phpinfo() found
      
</code></pre></td><td>Rapid checks for misconfig/CVEs. High detection; noisy.</td></tr><tr><td>Network Mapping</td><td><pre class="language-bash"><code class="lang-bash">
user01@acme:~$ traceroute target.AcmeCorp.local
      
</code></pre></td><td><pre><code>
 1  gw.AcmeCorp.local (10.0.0.1)     1.123 ms
 2  isp-edge.MailOps.net (192.0.2.1) 8.532 ms
 3  target.AcmeCorp.local (203.0.113.10) 18.241 ms
      
</code></pre></td><td>Reveals path and choke points. Medium–high detection.</td></tr><tr><td>Banner Grabbing</td><td><pre class="language-bash"><code class="lang-bash">
user01@acme:~$ nc target.AcmeCorp.local 80
GET / HTTP/1.0
      
</code></pre></td><td><pre><code>
HTTP/1.1 200 OK
Server: Apache/2.4.50 (Unix)
Content-Type: text/html; charset=UTF-8
      
</code></pre></td><td>Quick service/software hint. Low detection.</td></tr><tr><td>OS Fingerprinting</td><td><pre class="language-bash"><code class="lang-bash">
user01@acme:~$ nmap -O target.AcmeCorp.local
      
</code></pre></td><td><pre><code>
OS details: Linux 5.4 - 5.10
Network Distance: 3 hops
      
</code></pre></td><td>Low detection.</td></tr><tr><td>Service Enumeration</td><td><pre class="language-bash"><code class="lang-bash">
user01@acme:~$ nmap -sV -p80,443,8080 target.AcmeCorp.local
      
</code></pre></td><td><pre><code>
80/tcp   open  http    Apache httpd 2.4.50
443/tcp  open  https   nginx 1.18.0
8080/tcp open  http    Jetty 9.4.z-SNAPSHOT
      
</code></pre></td><td>Versions for CVE checks. Low detection.</td></tr><tr><td>Web Spidering</td><td>Burp Suite/ZAP Spider or wget spider</td><td><pre><code>
Found /login
Found /admin/
Found /backup.zip
Found /static/js/app.js
      
</code></pre></td><td>Maps pages/files. Low–medium detection.</td></tr></tbody></table>

***

#### Passive Reconnaissance

No direct interaction with target infrastructure. Stealthy; may be less complete.

<table><thead><tr><th>Technique</th><th>Command Example</th><th>Sample Output</th><th>Notes</th></tr></thead><tbody><tr><td>Search Engine Queries</td><td><pre><code>
site:AcmeCorp.local filetype:pdf "confidential"
      
</code></pre></td><td>Search results list with doc titles/snippets</td><td>Normal activity. Very low detection.</td></tr><tr><td>WHOIS Lookup</td><td><pre class="language-bash"><code class="lang-bash">
user01@acme:~$ whois AcmeCorp.local
      
</code></pre></td><td><pre><code>
Domain Name: ACMECORP.LOCAL
Registrant: Operations Team
Name Server: ns1.AcmeCorp.local
Name Server: ns2.AcmeCorp.local
Updated Date: 2025-07-12
      
</code></pre></td><td>Ownership, contacts, NS. Very low detection.</td></tr><tr><td>DNS Enumeration</td><td><pre class="language-bash"><code class="lang-bash">
user01@acme:~$ dig axfr @ns1.AcmeCorp.local AcmeCorp.local
      
</code></pre></td><td><pre><code>
; Transfer of 'AcmeCorp.local' from ns1.AcmeCorp.local
www     A   203.0.113.10
mail    A   203.0.113.20
dev     A   203.0.113.30
_stage  A   203.0.113.40
; Transfer completed.
      
</code></pre></td><td>Full zone only if misconfigured. Very low detection.</td></tr><tr><td>Web Archive Analysis</td><td><pre><code>
AcmeCorp.local in Wayback Machine
      
</code></pre></td><td>List of timestamps/snapshots; old paths and params visible</td><td>Historical pages, leaked endpoints. Very low detection.</td></tr><tr><td>Social Media Analysis</td><td><pre><code>
site:linkedin.com "AcmeCorp" ("engineer" OR "devops")
      
</code></pre></td><td>Employee names, titles, tech stacks, email patterns</td><td>Useful for social engineering. Very low detection.</td></tr><tr><td>Code Repositories</td><td><pre><code>
"AcmeCorp" "AWS_SECRET_ACCESS_KEY" site:github.com
      
</code></pre></td><td>Exposed tokens/configs if leaked</td><td>Public search. Very low detection.</td></tr></tbody></table>

***

