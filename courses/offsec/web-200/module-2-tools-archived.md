---
description: >-
  This topic has either been replaced or deprecated and is not required for any
  exams or assessments. The content remains available for those seeking
  additional research and learning opportunities.
---

# Module 2: Tools (archived)

## Getting Started

### Accessing The Lab Machines

_Updated your /etc/hosts file for the labs. IPs change, make sure they're updated when they do._

### About Proxies

_The "middleman"._

## Burp Suite

### Burp Suite's Built-In Browser

_Proxy > Open Browser._

### Using Burp Suite with Other Browsers

_Proxy settings: 127.0.0.1 port 8080;_

### Proxy

_Proxy manages interception of web traffic._

Intercept:

* Forward: pass the web request along.
* Drop: discard this request.

HTTP History:

* Sort all pages visited and traffic forwarded in sequential order.

Options:

* Add/Edit/Delete proxy settings.
* Match & Replace to modify requests/responses .

### Intruder

Used for modifying request/responses to attack the target with payloads. ex. brute forcing a login page.&#x20;

{% hint style="warning" %}
These requests are throttled in the Community edition.
{% endhint %}

### Repeater

Replays requests/responses, allowing us to modify them for testing purposes.

Inspector is available inside the Repeater tab, allowing decoding as well as viewing various attributes and headers with ease.

### Extra Mile

_This is just the lab._

## Nmap

### Nmap Scripts

_List of scripts can be found at /usr/share/nmap/scripts/_.

Use the `-sC` or `--script` option for running scripts with the Nmap scripting engine (NSE).

### Extra Mile

_Doing the lab._

## Wordlists

### SecLists Installation

_Just apt install seclists._

### Choosing a Wordlist

SecLists are split up into categories, make yourself familiar with them.

### Building Custom Wordlists

_Cewl_ can be used to crawl a webpage, generating a wordlist. The `-d` switch can be used to set the depth of the crawl. The `-m` switch sets the minimum word length.&#x20;

## Gobuster

### Installing Gobuster & Basic Usage



### Endpoint Discovery with Gobuster



### Go Bust Those Subdomains!



## Wfuzz

### File Discovery



### Directory Discovery



### Parameter Discovery



### Fuzzing Parameter Values



### Fuzzing POST Data



### Extra Mile



## Hakrawler

### Hakrawler Installation



### Hakrawler and the Wayback Machine



## Shells

### Web Technology



### Choosing the Correct Shell



### Payloads



### Extra Mile

