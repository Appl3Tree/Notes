# Module 5: Web Fuzzing

## Introduction

### Introduction

Web fuzzing automates malformed or unexpected input delivery to web applications to surface vulnerabilities before attackers do.

#### Fuzzing vs. Brute-forcing

Both techniques probe web applications with crafted inputs, but differ in scope and intent.

| Technique     | Approach           | Input Source                           | Target                                    |
| ------------- | ------------------ | -------------------------------------- | ----------------------------------------- |
| Fuzzing       | Wide, exploratory  | Wordlists, mutations, random sequences | Unexpected behavior, input handling flaws |
| Brute-forcing | Narrow, exhaustive | Predefined dictionaries                | Specific values (passwords, IDs)          |

Fuzzing tests how an application handles chaos; brute-forcing systematically enumerates possibilities for a known slot.

#### Why Fuzz Web Applications?

Manual testing cannot scale to cover all input surfaces of a modern web application. Fuzzing addresses this gap:

* **Hidden flaws:** Unexpected inputs trigger code paths that standard test cases skip.
* **Automation:** Payload generation and delivery are handled by the tool, freeing analysts for result triage.
* **Attack simulation:** Fuzzers replicate adversarial input patterns, enabling proactive remediation.
* **Input validation gaps:** Weaknesses enabling SQL injection (SQLi) and cross-site scripting (XSS) surface when malformed data is systematically injected.
* **Code quality:** Bug discovery feeds back into development, producing more robust output.
* **Continuous integration and continuous deployment (CI/CD) integration:** Fuzzing embedded in the software development lifecycle (SDLC) catches regressions early and keeps security testing continuous.

#### Essential Concepts

| Term              | Definition                                                                | Example                                                                                                                              |
| ----------------- | ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| Wordlist          | File containing words, paths, or parameter values used as fuzzing input   | `admin`, `backup`, `productID`, `checkout`                                                                                           |
| Payload           | The data unit sent to the application per fuzzing iteration               | `' OR 1=1 --` (SQLi probe)                                                                                                           |
| Response Analysis | Inspecting status codes and error messages to identify anomalous behavior | HTTP 500 with a database error vs. expected HTTP 200                                                                                 |
| Fuzzer            | Tool that automates payload delivery and response collection              | [ffuf](https://github.com/ffuf/ffuf), [wfuzz](https://github.com/xmendez/wfuzz), [Burp Suite](https://portswigger.net/burp) Intruder |
| False Positive    | A result flagged as a vulnerability that is not one                       | HTTP 404 for a non-existent path treated as a finding                                                                                |
| False Negative    | A real vulnerability the fuzzer fails to detect                           | A logic flaw in payment flow not triggered by any tested payload                                                                     |
| Fuzzing Scope     | The bounded target surface for a given fuzzing session                    | Single login endpoint or a specific API resource                                                                                     |

***



## Directory and File Fuzzing



## Parameter and Value Fuzzing



## Virtual Host and Subdomain Fuzzing



## Filtering Fuzzing Output



## Validating Findings



## Web APIs

