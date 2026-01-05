# Module 5: Attacking Web Applications with Ffuf

## Introduction

### Introduction

Fuzz Faster U Fool (FFUF)

* Purpose: Web fuzzing tool for discovering hidden application components.
* Method: Automates sending wordlist-based requests to a server, checking response codes.
* Example: A `200 OK` indicates the resource exists and should be inspected manually.

***

### Web Fuzzing

We start by fuzzing websites for directories with [ffuf](https://github.com/ffuf/ffuf). The example site shows only a landing page with no links, so fuzzing is the only way to find hidden content.

#### Fuzzing

* **Definition:** Technique where varied inputs are sent to an interface to study its response.
  * SQL injection fuzzing → random special characters.
  * Buffer overflow fuzzing → long strings of increasing length.
* **Web fuzzing:** Pre-defined wordlists are used to send requests for possible directories or pages.
  * Example:
    * `https://portal.AcmeCorp.local/doesnotexist` → returns `404 Not Found`.
    * `https://portal.AcmeCorp.local/login` → returns `200 OK` and shows a login page.
* Tools like ffuf automate this process, sending hundreds of requests per second and checking HTTP status codes.
* Goal: Quickly identify valid pages, then inspect them manually.

#### Wordlists

* Wordlists are essential, similar to password dictionaries.
* They usually identify the majority of pages (up to 90% success on some sites) but cannot detect uniquely named or random ones.
* High-quality lists are available in the [SecLists](https://github.com/danielmiessler/SecLists) project.
* In HTB's PwnBox, the repo is already located at `/opt/useful/SecLists`.
* Common choice for directory fuzzing: `directory-list-2.3`.

Example:

```bash
analyst1@AcmeCorp[/lab]$ locate directory-list-2.3-small.txt
/opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
```

{% hint style="info" %}
* Note: Some wordlists contain copyright comments at the beginning.
  * Use the `-ic` flag in ffuf to ignore comment lines.
{% endhint %}

***

## Basic Fuzzing

### Directory Fuzzing

Now that the concept of web fuzzing and wordlists is clear, we can use [ffuf](https://github.com/ffuf/ffuf) to discover hidden directories.

#### Ffuf

* Pre-installed on **HTB's PwnBox**.
*   Install on a local machine with:

    ```bash
    analyst1@AcmeCorp[/lab]$ sudo apt install ffuf -y
    ```
* Or download from the official GitHub repository.
* Start with the help menu to see available options:

```bash
analyst1@AcmeCorp[/lab]$ ffuf -h

HTTP OPTIONS:
  -H               Header "Name: Value", separated by colon. Multiple -H flags are accepted.
  -X               HTTP method to use (default: GET)
  -b               Cookie data "NAME1=VALUE1; NAME2=VALUE2"
  -d               POST data
  -recursion       Scan recursively. Only FUZZ keyword is supported, and URL (-u) has to end in it.
  -recursion-depth Maximum recursion depth. (default: 0)
  -u               Target URL
...SNIP...

MATCHER OPTIONS:
  -mc              Match HTTP status codes, or "all" for everything. (default: 200,204,301,302,307,401,403)
  -ms              Match HTTP response size
...SNIP...

FILTER OPTIONS:
  -fc              Filter HTTP status codes from response
  -fs              Filter HTTP response size
...SNIP...

INPUT OPTIONS:
...SNIP...
  -w               Wordlist file path and optional keyword. eg. '/path/to/wordlist:KEYWORD'

OUTPUT OPTIONS:
  -o               Write output to file
...SNIP...

EXAMPLE USAGE:
  ffuf -w wordlist.txt -u https://intra.AcmeCorp.local/FUZZ -mc all -fs 42 -c -v
```

The output is lengthy, so only the most relevant flags are shown here.

#### Directory Fuzzing

* Main options:
  * `-w` specifies wordlist.
  * `-u` specifies target URL.
* Assign the keyword `FUZZ` to a wordlist by appending `:FUZZ`.

```bash
analyst1@AcmeCorp[/lab]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ
```

* Place the `FUZZ` keyword in the URL where directories should be tested:

```bash
analyst1@AcmeCorp[/lab]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://webserver.AcmeCorp.local:8080/FUZZ
```

* Example run:

```bash
analyst1@AcmeCorp[/lab]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://webserver.AcmeCorp.local:8080/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://webserver.AcmeCorp.local:8080/FUZZ
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

blog                    [Status: 301, Size: 326, Words: 20, Lines: 10]
:: Progress: [87651/87651] :: Job [1/1] :: 9739 req/sec :: Duration: [0:00:09] :: Errors: 0 ::
```

* ffuf tested \~90,000 URLs in less than 10 seconds. Speed may vary based on network performance.
* Threads can be increased with `-t 200` to speed up scanning, but this is risky on remote sites as it can cause denial-of-service or connectivity issues.
* Visiting the discovered `/blog` directory may show an empty page but confirms access since no `404 Not Found` or `403 Forbidden` is returned.

***

### Page Fuzzing

We can now build on the earlier ffuf usage with wordlists and keywords to locate actual pages. The same target from the previous section can be reused here.

#### Extension Fuzzing

* In `/blog`, the directory appeared empty, so we check for hidden pages.
* First step: identify what file extensions the site uses (.php, .html, .aspx, etc.).
* Server headers sometimes hint at this (Apache often uses `.php`, IIS uses `.asp` or `.aspx`), but guessing is unreliable.
* Instead, we fuzz for extensions with ffuf:

```bash
analyst1@AcmeCorp[/lab]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://webserver.AcmeCorp.local:8080/blog/indexFUZZ
```

{% hint style="info" %}
Note: the `web-extensions.txt` wordlist already contains the dot (`.`), so `indexFUZZ` is sufficient.
{% endhint %}

Example run:

```bash
analyst1@AcmeCorp[/lab]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://webserver.AcmeCorp.local:8080/blog/indexFUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://webserver.AcmeCorp.local:8080/blog/indexFUZZ
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt
 :: Threads          : 5
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

.php                    [Status: 200, Size: 0, Words: 1, Lines: 1]
.phps                   [Status: 403, Size: 283, Words: 20, Lines: 10]
:: Progress: [39/39] :: Job [1/1] :: Duration: [0:00:00] :: Errors: 0 ::
```

* `.php` responds with 200 → valid.
* `.phps` responds with 403 → forbidden.
* Conclusion: site runs on PHP; continue fuzzing for PHP pages.

#### Page Fuzzing

* Use the same wordlist as directory fuzzing.
* Place `FUZZ` in the filename position before `.php`:

```bash
analyst1@AcmeCorp[/lab]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://webserver.AcmeCorp.local:8080/blog/FUZZ.php
```

Example run:

```bash
analyst1@AcmeCorp[/lab]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://webserver.AcmeCorp.local:8080/blog/FUZZ.php

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://webserver.AcmeCorp.local:8080/blog/FUZZ.php
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

index                   [Status: 200, Size: 0, Words: 1, Lines: 1]
reports                 [Status: 200, Size: 465, Words: 42, Lines: 15]
:: Progress: [87651/87651] :: Job [1/1] :: 5843 req/sec :: Duration: [0:00:15] :: Errors: 0 ::
```

* `index.php` exists but is empty.
* `reports.php` exists with content.
* Visiting these confirms accessible pages within `/blog`.

***

### Recursive Fuzzing

Manually fuzzing every directory and subdirectory is inefficient. Recursive fuzzing automates this process by scanning deeper into discovered directories.

#### Recursive Flags

* `-recursion`: Enables recursive scanning.
* `-recursion-depth`: Sets the depth of scanning.
  * Example: `-recursion-depth 1` → main directories + immediate children, but not deeper levels.
* `-e .php`: Adds `.php` as the extension to check site-wide.
* `-v`: Outputs full URLs for clarity.

This prevents wasted effort on very deep directory trees (e.g., `/login/user/content/uploads/...`) while allowing focus on interesting areas.

#### Recursive Scanning

Example run with recursion enabled:

```bash
analyst1@AcmeCorp[/lab]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://webserver.AcmeCorp.local:8080/FUZZ -recursion -recursion-depth 1 -e .php -v

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://webserver.AcmeCorp.local:8080/FUZZ
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions       : .php 
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

[Status: 200, Size: 986, Words: 423, Lines: 56] | URL | http://webserver.AcmeCorp.local:8080/
    * FUZZ: 

[INFO] Adding a new job to the queue: http://webserver.AcmeCorp.local:8080/forum/FUZZ
[Status: 200, Size: 986, Words: 423, Lines: 56] | URL | http://webserver.AcmeCorp.local:8080/index.php
    * FUZZ: index.php

[Status: 301, Size: 326, Words: 20, Lines: 10] | URL | http://webserver.AcmeCorp.local:8080/blog | --> | http://webserver.AcmeCorp.local:8080/blog/
    * FUZZ: blog

...SNIP...
[Status: 200, Size: 0, Words: 1, Lines: 1] | URL | http://webserver.AcmeCorp.local:8080/blog/index.php
    * FUZZ: index.php

[Status: 200, Size: 0, Words: 1, Lines: 1] | URL | http://webserver.AcmeCorp.local:8080/blog/
    * FUZZ: 
```

{% hint style="info" %}
Note:

* Recursive scans take significantly longer and send many more requests.
* Wordlist size doubles (once without extension, once with `.php`).
* Captures all earlier results in one run, plus new paths.
{% endhint %}

***

## Domain Fuzzing

### DNS Records

After accessing `/blog`, a message indicated the **Admin panel moved to `intra.AcmeCorp.local`**. Visiting that domain in a browser fails because the lab domains are not public.

#### Why It Fails

* Browsers resolve domains by checking first the local `/etc/hosts` file, then public DNS servers like `8.8.8.8`.
* Since `intra.AcmeCorp.local` is not public and not in `/etc/hosts`, resolution fails.
* Visiting the server’s IP directly works, but domains must be mapped manually.

#### Fix

Add the domain to `/etc/hosts`:

```bash
analyst1@AcmeCorp[/lab]$ sudo sh -c 'echo "SERVER_IP  intra.AcmeCorp.local" >> /etc/hosts'
```

Now browsing `http://intra.AcmeCorp.local:8080` works and shows the same site as the IP.\
Verifying `/blog/index.php` confirms both domain and IP serve the same content.

***

### Sub-domain Fuzzing

Sub-domains are underlying sites hosted under a primary domain. For example, `https://photos.google.com` is a sub-domain of `google.com`. With ffuf, we can attempt to discover these by fuzzing names before the main domain.

#### Sub-domains

* Purpose: Check if a sub-domain has a valid DNS record pointing to a server IP.
* Requirements:
  * A wordlist of common sub-domain names (available in SecLists under `/opt/useful/seclists/Discovery/DNS/`).
  * A target domain.
* Example wordlist: `subdomains-top1million-5000.txt`.

#### Example Scan

Targeting `AcmeFreight.net`:

```bash
analyst1@AcmeCorp[/lab]$ ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.AcmeFreight.net/

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : https://FUZZ.AcmeFreight.net/
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 381ms]
    * FUZZ: support

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 385ms]
    * FUZZ: ns3

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 402ms]
    * FUZZ: blog

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 180ms]
    * FUZZ: my

[Status: 200, Size: 22266, Words: 2903, Lines: 316, Duration: 589ms]
    * FUZZ: www

...SNIP...
```

Several sub-domains were identified: `support`, `ns3`, `blog`, `my`, and `www`.

#### Local Domains

Running the same command against `intra.AcmeCorp.local`:

```bash
analyst1@AcmeCorp[/lab]$ ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://FUZZ.intra.AcmeCorp.local/
```

Output:

```bash
:: Progress: [4997/4997] :: Job [1/1] :: 131 req/sec :: Duration: [0:00:38] :: Errors: 4997 ::
```

* No hits returned.
* Reason: Local domains like `intra.AcmeCorp.local` do not have public DNS records.
* Adding `intra.AcmeCorp.local` to `/etc/hosts` only covers the main domain, not its sub-domains.
* ffuf queries public DNS when fuzzing sub-domains, so nothing is found.

***

### Vhost Fuzzing

Public DNS records allow fuzzing for visible sub-domains, but non-public ones cannot be discovered this way. For those, **Vhost fuzzing** is used.

#### Vhosts vs. Sub-domains

* **Sub-domain:** A hostname under a domain, e.g., `photos.google.com`.
* **Vhost (Virtual Host):** A configuration on a web server that allows multiple sites to be served from the same IP using the `Host` header.
* Vhosts may or may not have DNS records.
* Sub-domain fuzzing finds only public entries; Vhost fuzzing can detect hidden ones on a known IP.

#### Vhost Fuzzing

* Technique: Fuzz the `Host` header instead of DNS.
* ffuf command example:

```bash
analyst1@AcmeCorp[/lab]$ ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://intra.AcmeCorp.local:8080/ -H 'Host: FUZZ.intra.AcmeCorp.local'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://intra.AcmeCorp.local:8080/
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

mail2                   [Status: 200, Size: 900, Words: 423, Lines: 56]
dns2                    [Status: 200, Size: 900, Words: 423, Lines: 56]
ns3                     [Status: 200, Size: 900, Words: 423, Lines: 56]
lists                   [Status: 200, Size: 900, Words: 423, Lines: 56]
webmail                 [Status: 200, Size: 900, Words: 423, Lines: 56]
static                  [Status: 200, Size: 900, Words: 423, Lines: 56]
web                     [Status: 200, Size: 900, Words: 423, Lines: 56]
www1                    [Status: 200, Size: 900, Words: 423, Lines: 56]
...SNIP...
```

{% hint style="info" %}
Note:

* Every entry in the wordlist returns `200 OK` since the server responds to any `Host` header.
* The trick is to look for **differences in response size**.
* When a valid Vhost is used, the returned page content changes, revealing a distinct site.
{% endhint %}

***

### Filtering Results

So far, results were implicitly filtered by HTTP status (excluding `404`). When many responses return `200 OK`, filter by other attributes to highlight meaningful findings.

#### Filtering

ffuf supports matching or filtering on status codes, lines, regex, sizes, and words. Relevant help excerpt:

```bash
analyst1@AcmeCorp[/lab]$ ffuf -h
...SNIP...
MATCHER OPTIONS:
  -mc              Match HTTP status codes, or "all" for everything. (default: 200,204,301,302,307,401,403)
  -ml              Match amount of lines in response
  -mr              Match regexp
  -ms              Match HTTP response size
  -mw              Match amount of words in response

FILTER OPTIONS:
  -fc              Filter HTTP status codes from response
  -fl              Filter by amount of lines in response
  -fr              Filter regexp
  -fs              Filter HTTP response size
  -fw              Filter by amount of words in response
...SNIP...
```

For Vhost fuzzing, unknown valid responses prevent precise **matching**, but we can **filter out** the known noise response size. If incorrect `Host` values return size `900`, exclude `900` with `-fs 900`:

```bash
analyst1@AcmeCorp[/lab]$ ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
-u http://intra.AcmeCorp.local:8080/ \
-H 'Host: FUZZ.intra.AcmeCorp.local' -fs 900

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://intra.AcmeCorp.local:8080/
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.intra.AcmeCorp.local
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response size: 900
________________________________________________

admin                   [Status: 200, Size: 0, Words: 1, Lines: 1]
:: Progress: [4997/4997] :: Job [1/1] :: 1249 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

Visit the discovered Vhost to verify:

```bash
analyst1@AcmeCorp[/lab]$ sudo sh -c 'echo "SERVER_IP  admin.intra.AcmeCorp.local" >> /etc/hosts'
analyst1@AcmeCorp[/lab]$ curl -i http://admin.intra.AcmeCorp.local:8080/
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Content-Length: 0
```

The empty page on `admin.intra.AcmeCorp.local` differs from the base site response, confirming a distinct Vhost. Checking a path that exists on the base site helps validate separation:

```bash
analyst1@AcmeCorp[/lab]$ curl -i http://admin.intra.AcmeCorp.local:8080/blog/index.php
HTTP/1.1 404 Not Found
Content-Type: text/html; charset=UTF-8
Content-Length: 123
```

{% hint style="info" %}
* Don't forget to add discovered vhosts, i.e. `admin.intra.AcmeCorp.local` to `/etc/hosts` before browsing.
{% endhint %}

***

## Parameter Fuzzing

### Parameter Fuzzing – GET

Running a recursive scan on `admin.intra.AcmeCorp.local` reveals `http://admin.intra.AcmeCorp.local:8080/admin/admin.php`.\
Accessing this page shows:

```
You don't have access to read the flag
```

This suggests access is controlled by a parameter passed to the page. Since no login or cookies are present, the backend may expect a GET or POST parameter.

{% hint style="success" %}
_Tip:_ Fuzzing parameters can uncover hidden ones that are often less secure and more vulnerable.
{% endhint %}

#### GET Request Fuzzing

*   GET parameters appear after a `?` in the URL:

    ```
    http://admin.intra.AcmeCorp.local:8080/admin/admin.php?param1=key
    ```
* Replace `param1` with `FUZZ` and scan.
* Wordlist: `/opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt`.
* Filter out default noise by excluding the common response size.

Example run:

```bash
analyst1@AcmeCorp[/lab]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
-u http://admin.intra.AcmeCorp.local:8080/admin/admin.php?FUZZ=key -fs 1234

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://admin.intra.AcmeCorp.local:8080/admin/admin.php?FUZZ=key
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response size: 1234
________________________________________________

token                   [Status: 200, Size: 256, Words: 15, Lines: 5]
```

Visiting the page with the discovered parameter:

```
http://admin.intra.AcmeCorp.local:8080/admin/admin.php?token=key
```

Response:

```
This method is deprecated
```

The parameter was identified but is no longer active, showing a deprecated feature.

***

### Parameter Fuzzing – POST

Unlike GET requests, POST requests send parameters in the request body rather than appending them to the URL.

To fuzz POST data with ffuf:

* Use `-X POST` to send POST requests.
* Use `-d` to define the request body.
* Place the `FUZZ` keyword inside the POST data.

{% hint style="info" %}
**Note:** In PHP applications, POST data is typically only parsed if the content type is `application/x-www-form-urlencoded`. Always include:

```bash
-H 'Content-Type: application/x-www-form-urlencoded'
```
{% endhint %}

Example scan:

```bash
analyst1@AcmeCorp[/lab]$ ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
-u http://admin.intra.AcmeCorp.local:8080/admin/admin.php -X POST \
-d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs 1234

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0-git
________________________________________________

 :: Method           : POST
 :: URL              : http://admin.intra.AcmeCorp.local:8080/admin/admin.php
 :: Wordlist         : FUZZ: /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : FUZZ=key
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response size: 1234
________________________________________________

id                      [Status: 200, Size: 345, Words: 20, Lines: 8]
```

#### Testing the Parameter

Send a POST request directly with curl:

```bash
analyst1@AcmeCorp[/lab]$ curl http://admin.intra.AcmeCorp.local:8080/admin/admin.php -X POST \
-d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'

<div class='center'><p>Invalid id!</p></div>
```

***

### Value Fuzzing

Once a valid parameter is found, the next step is fuzzing its **values** to discover the correct one that reveals sensitive content, such as a flag.

#### Custom Wordlist

* Pre-made wordlists may exist for values like usernames or passwords.
* For custom parameters (e.g., `id`), build a tailored list.
* If IDs are sequential, generate them with Bash:

```bash
analyst1@AcmeCorp[/lab]$ seq 1 1000 > ids.txt
```

Resulting file:

```bash
analyst1@AcmeCorp[/lab]$ cat ids.txt
1
2
3
4
5
6
...SNIP...
```

#### Value Fuzzing

Use the same POST fuzzing method as before, but place the `FUZZ` keyword in the parameter value and supply the custom wordlist:

```bash
analyst1@AcmeCorp[/lab]$ ffuf -w ids.txt:FUZZ \
-u http://admin.intra.AcmeCorp.local:8080/admin/admin.php -X POST \
-d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs 1234

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.0.2
________________________________________________

 :: Method           : POST
 :: URL              : http://admin.intra.AcmeCorp.local:8080/admin/admin.php
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : id=FUZZ
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response size: 1234
________________________________________________

42                        [Status: 200, Size: 512, Words: 30, Lines: 12]
```

***
