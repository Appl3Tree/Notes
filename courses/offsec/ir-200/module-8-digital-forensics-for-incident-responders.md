# Module 8: Digital Forensics for Incident Responders

Fundamentals of Digital Evidence Handling

### Importance of Evidence Handling

Failing to handle evidence properly can result in the integrity of the evidence bein compromised or become untrustworthy.

### Evidence Collection and Preservation

1. Identify potential sources of digital evidence.
2. Gather content, and metadata.
   1. Limit interactino with media that may contain digital evidence to avoid altering the original data.
3. Maintain integrity via cryptographic hashes for validation.
4. Use a hardware write blocker when duplicating data.
5. Store evidence securely.
6. Protect sensitive data/digital evidence via encryption.
7. Control and monitor chain of custody.

### Kali Linux Forensics Mode

Kali live has a boot option for forensics mode which protects from writing/modifying contents of the hard drive(s). It also has auto-mounting disabled.

_Capturing a disk image using dd_

{% code overflow="wrap" %}
```bash
┌──(kali㉿kali)-[~]
└─$ sudo dd if=/dev/nvme0n1 of=/mnt/external/VICTIM-OS.raw bs=4M conv=sync,noerror status=progress
587202560 bytes (587 MB, 560 MiB) copied, 14 s, 41.6 MB/s
```
{% endcode %}



| Option                           | Explanation                                                                                                                                               |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `if=/dev/nvme0n1`                | This specifies the input file.                                                                                                                            |
| `of=/mnt/external/VICTIM-OS.raw` | This specifies the output file.                                                                                                                           |
| `bs=4M`                          | This specifies the size of each block.                                                                                                                    |
| `conv=sync,noerror`              | This is specifying that if there is a read error, pad the output block with null bytes to "sync" with the original device. If there are errors, continue. |
| `status=progress`                | Display a visual status of the progress of the image copy.                                                                                                |

`sha256sum` can be used to obtain a sha256 hash of the resulting image.

### Legal and Procedural Aspects of Evidence Handling

{% embed url="https://datatracker.ietf.org/doc/html/rfc3227" %}
Prominent resource by IETF
{% endembed %}

It is suggested that evidence is gathered in this order, with most volatile being first:

* Registers, cache
* Routing table, ARP cache, process table, kernel statistics, memory
* Temporary file systems
* Disk
* Remote logging and monitoring data that is relevant to the system in question
* Physical configuration, network topology
* Archival media

A very detailed, standardized, and methodical approach is provided in ISO 27037:

{% embed url="https://www.iso.org/standard/44381.html" %}

### Response Kits

Bare minimum necessities:

* Administrative Documents
* Hard Drive Cloner/Eraser
* Storage Devices
* SSD/HDD Converters
* Laptop
* Forensics Tools

## Forensic Tools and Techniques

### Computer Forensics

* Disk imaging
  * Offline imaging
  * Live imaging
  * remote imaging
  * VM imaging

<figure><img src="../../../.gitbook/assets/image (73).png" alt=""><figcaption><p>Creating a new Case in Autopsy</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (74).png" alt=""><figcaption><p>Adding a Data Source in Autopsy Step 1</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/fc7bbce0c9f8fccf64b933e571b05006-autopsy_sourcetypes.png" alt=""><figcaption><p>Adding a Data Source in Autopsy Step 2</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (76).png" alt=""><figcaption><p>Adding a Data Source in Autopsy Step 3</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/088ca5662a8f280e8c34c0f7eb55bc70-autopsy_ingest2 (1).png" alt=""><figcaption><p>Adding a Data Source in Autopsy Step 4</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (77).png" alt=""><figcaption><p>Adding a Data Source in Autopsy Step 5</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/83b2e6cf677913642697fadc2bb0fbe8-autopsy_analysis_no2.png" alt=""><figcaption><p>File System of WEB01</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/377721163b932338e758b49610fa58ac-autopsy_dumphex2.png" alt=""><figcaption><p>Navigating to the database file dump.db</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/d66377e872ba7f835060ca054b8761f7-autopsy_timeline1 (1).png" alt=""><figcaption><p>Creating a Timeline</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/47a07d01758f0b1a1b977ec32d3fd32c-autopsy_timeline_sudo.png" alt=""><figcaption><p>Analyzing the Timeline</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/405a70407cc019e7fbb08256e673351f-autopsy_timeline_usermod.png" alt=""><figcaption><p>Following the activities in the Timeline</p></figcaption></figure>

### Memory Forensics

_Using volatility to perform some memory forensics._

_Displaying Windows Information with Volatility3:_

{% code overflow="wrap" %}
```powershell
PS C:\Tools\volatility3> python vol.py -f E:\memdump.mem windows.info
Volatility 3 Framework 2.5.0
Progress:  100.00               PDB scanning finished                        
Variable        Value

Kernel Base     0xf80621600000
DTB     0x1ae000
Symbols file:///home/kali/volatility3-2.5.0/volatility3/symbols/windows/ntkrnlmp.pdb/CF32DE2E4A334C7C06FB63FCB6FAFB5C-1.json.xz
Is64Bit True
IsPAE   False
layer_name      0 WindowsIntel32e
memory_layer    1 FileLayer
KdVersionBlock  0xf806222099a0
Major/Minor     15.22621
MachineType     34404
KeNumberProcessors      2
SystemTime      2023-11-15 15:45:06
NtSystemRoot    C:\Windows
NtProductType   NtProductWinNt
NtMajorVersion  10
NtMinorVersion  0
PE MajorOperatingSystemVersion  10
PE MinorOperatingSystemVersion  0
PE Machine      34404
PE TimeDateStamp        Tue Jun 17 09:32:46 2036
```
{% endcode %}

_Displaying Networking Information with Volatility3_

{% code overflow="wrap" %}
```powershell
PS C:\Tools\volatility3> python vol.py -f E:\memdump.mem windows.netstat.NetStat
Volatility 3 Framework 2.5.0
Progress:  100.00               PDB scanning finished                        
Offset  Proto   LocalAddr       LocalPort       ForeignAddr     ForeignPort     State   PID     Owner   Created

0xe38e07e278a0  TCPv4   172.16.50.92    49917   192.229.211.108 80      ESTABLISHED     -       -       N/A
0xe38e07e148a0  TCPv4   172.16.50.92    49903   192.229.211.108 80      ESTABLISHED     -       -       N/A
0xe38e08c51010  TCPv4   172.16.50.92    49850   52.226.139.180  443     ESTABLISHED     -       -       N/A
0xe38e06d08aa0  TCPv4   172.16.50.92    49790   172.16.50.80    389     ESTABLISHED     -       -       N/A
0xe38e0657a490  TCPv4   172.16.50.92    49718   172.16.50.80    389     ESTABLISHED     -       -       N/A
0xe38e06586520  TCPv4   172.16.50.92    49763   192.168.48.130  443     ESTABLISHED     -       -       N/A
...
```
{% endcode %}

{% hint style="warning" %}
Advanced C2 frameworks such as Cobalt Strike or Sliver typically use beacons instead of fully-fledged reverse shells that maintain a permanent connection to the attacker's infrastructure. If the memory dump wasn't created at the exact moment the beacon check-in was performed, NetStat will not show this connection.
{% endhint %}

_Displaying Process Tree Information with Volatility3_

{% code overflow="wrap" %}
```powershell
PS C:\Tools\volatility3> python vol.py -f E:\memdump.mem windows.pstree.PsTree

Volatility 3 Framework 2.5.0
Progress:  100.00               PDB scanning finished                        
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime

4       0       System  0xe38e038ec040  174     -       N/A     False   2023-11-15 15:37:13.000000      N/A
* 380   4       smss.exe        0xe38e0566e040  2       -       N/A     False   2023-11-15 15:37:13.000000      N/A
...
684     580     winlogon.exe    0xe38e06533080  2       -       1       False   2023-11-15 15:37:20.000000      N/A
* 5552  684     userinit.exe    0xe38e0891c080  0       -       1       False   2023-11-15 15:37:36.000000      2023-11-15 15:38:00.000000 
** 5580 5552    explorer.exe    0xe38e089450c0  74      -       1       False   2023-11-15 15:37:37.000000      N/A
*** 8768        5580    application_bu  0xe38e09306080  2       -       1       False   2023-11-15 15:38:19.000000      N/A
**** 8904       8768    cmd.exe 0xe38e091aa080  1       -       1       False   2023-11-15 15:38:29.000000      N/A
***** 8912      8904    conhost.exe     0xe38e085020c0  4       -       1       False   2023-11-15 15:38:29.000000      N/A
***** 9032      8904    powershell.exe  0xe38e0955c080  12      -       1       False   2023-11-15 15:38:38.000000      N/A
...
6412    3416    FTK Imager.exe  0xe38e092f3080  23      -       1       False   2023-11-15 15:40:20.000000      N/A
```
{% endcode %}

### Network Forensics

Useful sources:

* Netflow data
* Full Packet Capture (FPC)

<figure><img src="../../../.gitbook/assets/b39f952fbb7401d1d866d4345d9f1f9e-netwitness_landing.png" alt=""><figcaption><p>Starting NetWitness Investigator</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/7f02c9ae34e57f9d180fea24d7c080b7-netwitness_newcollection.png" alt=""><figcaption><p>Creating a new Local Connection</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/e8191517e739988479f411f0b422fabb-netwitness_pcaps.png" alt=""><figcaption><p>Selecting the PCAP files recorded on IDS01</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/c276aedb5ef9a1c8ff3b8cadae543fc2-netwitness_artifacts.png" alt=""><figcaption><p>Values identified by NetWitness Investigator</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/0c2e3dc26a4f48b895458ae2cad3da2d-netwitness_application.png" alt=""><figcaption><p>Reviewing Attachments</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/ea7fa3a5ee524b3f9533575e97ad75f5-netwitness_email.png" alt=""><figcaption><p>Analyzing one of the phishing emails</p></figcaption></figure>

### Log Forensics

_We already did this earlier via Splunk. Do it again._

## Malware Analysis

### Basic Static Analysis

<figure><img src="../../../.gitbook/assets/ee82b25aa918fca772e8b86a88724452-pestudio_meta.png" alt=""><figcaption><p>Loaded Binary in pestudio</p></figcaption></figure>

_PowerShell Script to calculate Shannon's Entropy for all .exe files in a specified directory_

{% code overflow="wrap" %}
```powershell
function Get-FileEntropy {
    param ([string]$FilePath)

    $bytes = [System.IO.File]::ReadAllBytes($FilePath)
    $freq = @{}
    $bytes | ForEach-Object { $freq[$_] = $freq[$_]+1 }
    $entropy = 0
    $freq.Values | ForEach-Object {
        $p = $_ / $bytes.Length
        $entropy -= $p * [Math]::Log($p, 2)
    }
    $entropy
}

$dir = "C:\Tools\"
Get-ChildItem -Path $dir -Filter "*.exe" | ForEach-Object {
    Write-Host "$($_.Name) entropy: $(Get-FileEntropy $_.FullName)"
}
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/eb6310ad585750954a2563418f92d2e8-virustotal_hash (1).png" alt=""><figcaption><p>Searching for the hash in VirusTotal</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/0efa73342aa42c8c77e8d30b1d040276-pestudio_strings.png" alt=""><figcaption><p>String Analysis in PEStudio</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/83a73f5f08ca6e70ab27a2a0ba8ea8d9-pestudio_indicators.png" alt=""><figcaption><p>Analysis of Indicators</p></figcaption></figure>

### Basic Dynamic Analysis

{% hint style="warning" %}
It is **critical** that your system is isolated before executing potentially destructive binaries.
{% endhint %}

<figure><img src="../../../.gitbook/assets/37972e05ba6afe0f3a5a64f09c813d9d-procmon_main.png" alt=""><figcaption><p>ProcMon displaying numerous events</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/f5a1714bdce5badfabf25504cacd8348-procmon_filter.png" alt=""><figcaption><p>Creating a ProcMon filter</p></figcaption></figure>

_Starting the binary application\_builder.exe in PowerShell_

```powershell
PS C:\Tools> .\application_builder.exe
```

<figure><img src="../../../.gitbook/assets/764ce181f32f99524c1de15de31b385e-procmon_start.png" alt=""><figcaption><p>ProcMon shows events related to the started binary</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/a4274936899912fcbef88a63e4290ffb-procmon_kernel.png" alt=""><figcaption><p>The binary loads kernel32.dll</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/92638f5885cef4388fc6dc1750a08d9e-procmon_ws2_322.png" alt=""><figcaption><p>The binary loads ws2_32.dll</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/6ffb7c12f4aef5ac051c1b2bced093da-procmon_reconnects2.png" alt=""><figcaption><p>The binary attempts network connections to 192.168.48.130</p></figcaption></figure>

### Automated Analysis

_Use tools like_ [_VirusTotal_](https://www.virustotal.com/gui/home/upload)_,_ [_ANY.RUN_](https://any.run/)_,_ [_Hybrid Analysis_](https://www.hybrid-analysis.com/)_,_ [_Joe Sandbox Cloud's Community Edition_](https://www.joesandbox.com/#windows)_,_ [_Cuckoo Sandbox_](https://github.com/cuckoosandbox/cuckoo)_, etc. If they have APIs, you can automate this even further._
