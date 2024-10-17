---
layout:
  title:
    visible: true
  description:
    visible: false
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
---

# Module 6: Theat Hunting Without IoCs

## Custom Threat Hunting

### What is Custom Threat Hunting?

_Targeted investigations looking for specific behaviors, patterns, anomalies, etc. aligning with a hypothesized threat._&#x20;

_Important tools: YARA; CyberChef;_

### Data Correlation for Threat Hunters

_Collect all the data, connect the dots._

## Threat Hunting for new IoCs

### Introduction to CrowdStrike Falcon

Falcon provides RTR which allows us to execute useful commands and such on hosts monitored.

Example CQL:

```splunk-spl
CLIENT4
| "#event_simpleName" = DnsRequest
| groupBy([@timestamp, DomainName])
```

### Introduction to the Environment

_Context for following sections._

### Custom Threat Hunting with CrowdStrike Falcon

Display all registered scheduled tasks and group them by their _aid (Agent Identifier)_. To show human-readable DNS names, we'll use ComputerName instead of aid:

```splunk-spl
#event_simpleName=ScheduledTaskRegistered
| groupBy([ComputerName, TaskName, TaskExecCommand, TaskAuthor], limit=max)
```

Using a wildcard to broaden our search:

```splunk-spl
#event_simpleName=ScheduledTask*
| groupBy([ComputerName, TaskName, TaskExecCommand, TaskAuthor], limit=max)
```

Turning HEX data from a Microsoft Shortcut file into some usable information:

<figure><img src="../../../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

Gathering filehashes of IoCs discovered:

```batch
C:\> filehash C:\Users\e.taylor\fin\6.exe
Filename : C:\Users\e.taylor\fin\6.exe
MD5      : 3B955958829C8EA45E2DE001BBD7DA4A
SHA1     : 6B0FEF8A7422608FA97D7D971774C469B24B9CFA
SHA256   : 5F78E94C7EABE39A9C6297DB3F12EF5161D835C7C65928D990EA98C0528E04EF

C:\> filehash C:\Users\e.taylor\fin\432.lnk
Filename : C:\Users\e.taylor\fin\432.lnk
MD5      : 791DB6B9FEA675AA4DC9A9428682AA4D
SHA1     : 4337467C073A1A4359B0A2ACFC89F9BD2A31FF92
SHA256   : 557F6E27B27C1CD1AC3167087A1CE547C9AB9D789F104CE4C7DA6D3D2712E1C8
```

With the file hashes in hand, we're now ready to compile a list of all IoCs uncovered so far:

* File hashes (SHA256) of **6.exe** and **432.lnk**
* File names **6.exe** and **432.lnk**
* DNS name **webdav.4shared.com**
* Scheduled Task names **WindowsUpdate** and **UpdateHealthCheck**
* Username **lasex69621@cohodl.com** and password **dE}9tBDaFK'Y%uv**

<figure><img src="../../../.gitbook/assets/image (1) (1) (1).png" alt=""><figcaption><p>Hunting with File Hashes</p></figcaption></figure>

No results by hash, let's search by filename:

```splunk-spl
#event_simpleName=ProcessRollup2 OR #event_simpleName=SyntheticProcessRollup2
| ComputerName != CLIENT2
| CommandLine = /6.exe/i OR CommandLine = /432.lnk/i
```

Also no results, let's search for the DNS names we found:

```splunk-spl
("webdav.4shared.com") or ("cohodl.com")
```

Still no results, maybe the scheduled tasks:

```splunk-spl
#event_simpleName=ScheduledTask*
| ComputerName != CLIENT2
| TaskName = WindowsUpdate OR TaskName = UpdateHealthCheck
```

Last item to search for being the credentials we found used:

```splunk-spl
("lasex69621@cohodl.com") or ("dE}9tBDaFK'Y%uv")
```

Still nothing.

### Iterative Searches using Sandboxes

<figure><img src="../../../.gitbook/assets/image (12).png" alt=""><figcaption><p>Cuckoo Analysis Summary of 6.exe</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (13).png" alt=""><figcaption><p>Cuckoo Sandbox Static Analysis Results</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (14).png" alt=""><figcaption><p>String Analysis Results</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (15).png" alt=""><figcaption><p>Behavioral Analysis Results</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (16).png" alt=""><figcaption><p>Newtork Behavior of 6.exe</p></figcaption></figure>

Use the information discovered to do additional research into IoCs discovered.
