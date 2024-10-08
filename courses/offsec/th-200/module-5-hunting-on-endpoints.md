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

# Module 5: Hunting on Endpoints

## Endpoints for Threat Hunters

### Types of Endpoint IoCs

Typical types of endpoint IoCs we rely on for intelligence-based threat hunting:

* Network-related IoCs
  * IPs
  * Domains
  * URLs
* File-related IoCs
  * Hashes
  * Names
* Behavioral IoCs
  * Anomalies in user activities
  * Irregular commands entered by users

### Sources of Endpoint Data

_Not much to add, talking about event logs, sysmon, EDR, etc._

### Endpoint IoC Considerations

_Nothin' to add. Consider TTPs, feeding intelligence into the hunt, enrichment, etc._

## Practical Endpoint Threat Hunting

### The Akira Ransomware Incident

_Context for the hands-on._

### Ransomware Artifacts

_Honestly, not much to add still. Couple new searches in Splunk..._

```splunk-spl
index="*" "akira_readme.txt" host=DB1
index="*" "akira" NOT "akira_readme.txt"
index="*" "passwords.kdbx" host=CLIENT3
```

### File Artifacts

Getting a file hash with PowerShell:

```powershell
PS C:\Resources> Get-FileHash -Path .\l9k1JEYlHZ.exe
```

Searching multiple filenames in splunk:

```splunk-spl
index="*" ("l9k1JEYlHZ.exe" OR "image_slider.exe" OR "db_update.exe")
```

Using threat intelligence, let's search for the other hashes of files known to be used by Akira ransomware variants:

{% code overflow="wrap" %}
```splunk-spl
index="*" ("337d21f964091417f22f35aee35e31d94fc3f35179c36c0304eef6e4ae983292" OR
"3c92bfc71004340ebc00146ced294bc94f49f6a5e212016ac05e7d10fcb3312c" OR 
"637e28b38086ff9efd1606805ff57aaf6cdec4537378f019d6070a5efdc9c983" OR 
"67afa125bf8812cd943abed2ed56ed6e07853600ad609b40bdf9ad4141e612b4" OR 
"678ec8734367c7547794a604cc65e74a0f42320d85a6dce20c214e3b4536bb33" OR 
"7b295a10d54c870d59fab3a83a8b983282f6250a0be9df581334eb93d53f3488" OR 
"8631ac37f605daacf47095955837ec5abbd5e98c540ffd58bb9bf873b1685a50" OR 
"1d3b5c650533d13c81e325972a912e3ff8776e36e18bca966dae50735f8ab296" OR 
"094d1476331d6f693f1d546b53f1c1a42863e6cde014e2ed655f3cbe63e5ecde" OR 
"35415d97038e091744e9cab3b88c78c1a7ca87f78d2b4a363f72f2c28d65932b" OR 
"6192beb56de670de902193a33380e5eb0f3b4b2e3e848e7eea8950075f00f2e5" OR 
"d1aa0ceb01cca76a88f9ee0c5817d24e7a15ad40768430373ae3009a619e2691" OR
"f157090fd3ccd4220298c06ce8734361b724d80459592b10ac632acc624f455e")
```
{% endcode %}

### Adapting our Methodology

_Just walking through searching via Splunk for IoCs._
