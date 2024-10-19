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

# Module 4: Hunting With Network Data

## Network Data for Threat Hunters

### Network IoCs

_Discussing fidelity for the most part. Using threat intell to gather info for attribution. A bit about using IDS/IPS for global traffic views rather than a host for their network traffic._

### Sources of Network IoCs

_Exactly what the title of the section is. IDS, IPS, etc._

## Practical Network Data Analysis

### The Lockbit Ransomware

Using **Splunk** to search for the top 20 destination IPs that CLIENT2 communicated with:

{% code overflow="wrap" %}
```splunk-spl
index="*" SourceHostname="CLIENT2.megacorpone.com" | top limit=20 DestinationIp
```
{% endcode %}

Now that we've found a sus IP, narrow down the searches to communication to that IP involving e.taylor -- the user who supposedly clicked the suspicious link. Change the output into a table of time the request occured, the file involved in the request, and the PID of the process:

{% code overflow="wrap" %}
```splunk-spl
index="*" DestinationIp="192.229.211.108" User="MEGACORPONE\\e.taylor" | table _time,Image,ProcessId
```
{% endcode %}

### Full Packet Capture Analysis

Wireshark filter to filter on our previously sus IP and CLIENT2:

```splunk-spl
ip.addr == 192.229.211.108 and ip.addr == 10.25.25.101
```

Gathering arp activity or smb:

```splunk-spl
(arp.src.proto_ipv4 == 10.25.25.101) or smb
```

Using NetWitness to dig deeper via Suricata captures.

<figure><img src="../../../.gitbook/assets/image (6) (1).png" alt=""><figcaption><p>Launching NetWitness</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (7) (1).png" alt=""><figcaption><p>Inspecting email data</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (8) (1).png" alt=""><figcaption><p>Inspecting emails on the second pcap session</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (9) (1).png" alt=""><figcaption><p>Searching for the mail attachment</p></figcaption></figure>

If we click the lockbit.exe, it asks if we want to run it. This looks terrifying but follows up with a question on actual actions to take:

<figure><img src="../../../.gitbook/assets/image (10) (1).png" alt=""><figcaption><p>Saving the attachment</p></figcaption></figure>

Getting the hash of the lockbit.exe for additional digging:

{% code overflow="wrap" %}
```powershell
PS C:\Resources> Get-FileHash -Algorithm SHA256 .\533-0-4_attach.1.lockbit.exe

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
SHA256          B240B6861889734EEE778D92BC1E2930E10570FE41D84A1A79CC518DC93F4E09       C:\Resources\533-0-4_attach.1.lockbit.exe
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (11) (1).png" alt=""><figcaption><p>Confirming the Lockbit sample in VirusTotal</p></figcaption></figure>
