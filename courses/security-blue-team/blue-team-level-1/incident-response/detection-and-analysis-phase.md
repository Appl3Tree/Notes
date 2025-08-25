# Detection and Analysis Phase

## Section Introduction

This section explains how incidents are detected using tools like SIEM and IDPs, and how logs and PCAPs are analyzed to identify indicators of compromise for threat exposure checks and sharing.

***

## Common Events & Incidents

Security operations teams regularly investigate common security events, some of which may escalate into incidents requiring deeper analysis. Events are categorized as remote to local (R2L), local to remote (L2R), or local to local (L2L). Internal systems are considered local, while external or public systems are remote.

***

### R2L Port Scanning

An external system scans the organization’s public IPs to identify active hosts and open ports. This is among the most frequent alerts analysts encounter.

**Detection:** Collect firewall and web application firewall logs. Alerts should trigger when multiple ports are contacted in a short timeframe, especially non-standard ports outside HTTP (80) and HTTPS (443).

**Potential Impact:** Scans are usually harmless but may overwhelm older systems or consume bandwidth, leading to a denial-of-service (DoS).

***

### R2L DoS/DDoS

External IPs send excessive requests or malformed packets to a target system, attempting to crash or overload it. DoS involves one attacker, while DDoS involves multiple.

**Detection:** Establish traffic baselines and alert when request rates exceed normal thresholds.

**Potential Impact:** Attacks can take services offline, causing financial loss, reputational damage, and operational disruption. For example, the 2016 DDoS against Dyn DNS caused outages at Amazon, PayPal, Reddit, and Twitter.

***

### L2L Scanning

An internal host scans other private IPs on the same network, often to map active systems, operating systems, and running services.

**Detection:** Configure SIEM rules to detect rapid connections between private IPs. Whitelist legitimate vulnerability scanners to avoid false positives.

**Potential Impact:** If a system is compromised, attackers may perform lateral movement by scanning internal hosts for accessible services.

***

### Login Failures

Login failures occur for benign reasons, such as password resets or forgotten credentials, but can also indicate malicious attempts to gain access. Windows Security Log Event ID **4625** records failed login attempts, with status and substatus codes explaining the cause.

| **Status / Substatus Code** | **Description**                                                                                          |
| --------------------------- | -------------------------------------------------------------------------------------------------------- |
| 0xC0000064                  | Username does not exist                                                                                  |
| 0xC000006A                  | Username is correct but the password is wrong                                                            |
| 0xC0000234                  | User is currently locked out                                                                             |
| 0xC0000072                  | Account is currently disabled                                                                            |
| 0xC000006F                  | User tried to log on outside allowed day/time restrictions                                               |
| 0xC0000070                  | Workstation restriction or Authentication Policy Silo violation (see Event ID 4820 on domain controller) |
| 0xC0000193                  | Account has expired                                                                                      |
| 0xC0000071                  | Password has expired                                                                                     |
| 0xC0000133                  | Clocks between domain controller and client system are too far out of sync                               |
| 0xC0000224                  | User is required to change password at next logon                                                        |
| 0xC0000225                  | Windows bug; not considered a risk                                                                       |
| 0xC000015B                  | User not granted requested logon type (logon right) on this machine                                      |

**Detection:** Monitor Event ID 4625 and configure thresholds to trigger alerts on repeated failures for a single account or low failures spread across many accounts (possible password spraying). Codes provide immediate insight into whether issues are user-driven or potential indicators of attack.

**Potential Impact:**

* Ordinary cases (expired password, mistyped password) usually cause temporary lockouts and productivity loss.
* Malicious cases (invalid usernames, repeated lockouts, logons outside allowed restrictions) may indicate brute-force or dictionary attacks, suggesting an attacker is attempting to gain access to internal accounts.

***

## Using Baselines & Behaviour Profiles

Baselining is the process of recording normal activity on a system or network—such as network utilization, protocol usage, active hours, user activity, and port numbers—and comparing it against current behavior to identify anomalies. This technique, known as anomaly-based detection, highlights deviations that may indicate threats or performance issues.

For example, if a baseline shows normal usage on ports 22, 25, 80, 443, and 3389, but suddenly large amounts of Telnet traffic appear on port 23, the system would flag this as an anomaly. The cause may be malicious activity, such as command and control via Telnet, or simply a legitimate new service. Further analysis is required to determine the true cause.

***

### Anomaly-Based Detection

Anomaly-based detection is comparable to spotting the “odd one out.” Just as a red apple among green apples stands out, abnormal network or system behavior can indicate a threat.

This method is effective against new or unknown attacks, unlike signature-based detection which relies on known identifiers such as file hashes. It works well for detecting DoS/DDoS activity and suspicious traffic, even when encrypted.

However, it has drawbacks:

* Large networks produce high volumes of false positives.
* Establishing a baseline can take time and must be repeated after major changes.
* Analysis, especially manual review, is resource-intensive.

The example of finding an anomaly among rotated or reflected shapes illustrates these challenges: time spent baselining, analyzing, and filtering false positives can slow response.

***

### Enhanced Detection

Anomaly-based detection should integrate with broader security controls to strengthen overall defenses. By alerting incident response teams quickly, potential attacks can be investigated or stopped early.

Logs from anomaly detection systems can be forwarded to a centralized SIEM, where they are correlated with other sources such as firewall or endpoint logs to give responders a complete picture of events before and during an incident.

Anomaly-based detection prepares organizations for unknown threats because it identifies deviations rather than relying on a signature database. Common tools include [Cisco Stealthwatch](https://www.cisco.com/c/en/us/products/security/stealthwatch/index.html), [IBM QRadar](https://www.ibm.com/qradar), and [Flowmon ADS](https://www.progress.com/network-monitoring/flowmon/anomaly-detection-system).

***

## Introduction to Wireshark (GUI)

Wireshark is a free and widely used tool for capturing and analyzing network traffic. It is included in [Kali Linux](https://www.kali.org/) and can also be downloaded from the [official Wireshark site](https://www.wireshark.org/). The interface is divided into two main screens: the **Startup Window**and the **Main Window**.

***

### Wireshark Startup Window

The Startup Window is displayed when Wireshark launches. It allows you to begin a new capture or load saved capture files.

* **\[1] Start Capture:** Blue button (top left) begins capturing packets on the selected interface with optional capture filters.
* **\[2] Open Saved Files:** Supports `.cap`, `.pcap`, and `.pcapng` files, which open in the Main Window for analysis.
* **\[3] Capture Filter:** Restricts the types of packets captured. Example: `not arp` avoids capturing ARP packets. Filters can be saved for reuse.
* **\[4] Capture Interface Selection:** Lists available interfaces (e.g., `en0` for Wi-Fi, `vboxnet0` for virtual networks) with graphs of recent activity.

**Promiscuous Mode:** Recommended for broader visibility. It allows capture of packets not addressed to the host, such as other frames on a wireless network. This setting is toggled via the cog-shaped button in the top menu bar.

***

### Wireshark Main Window

The Main Window is where traffic is captured and analyzed. It provides detailed information from high-level flow summaries to low-level packet bytes.

* **\[1] Menu Bar:** Controls capture (start, stop, restart), interface settings, and file management. The magnifying glass icon allows searching packets via display filters, strings, or bytes.
*   **\[2] Display Filter:** Shows only packets that match specific criteria. Filters use header fields and values with logical operators.

    _Example:_

    ```
    http.request.method == "POST" and tcp.port == 80 and ip.dst == 203.0.113.25
    ```

    Displays only TLS 1.2 packets from source `192.168.1.7` over TCP port 443.
* **\[3] Panes:** The window has three panes—packet list, packet headers, and hex/ASCII representation.
* **\[4] Packet List:** Displays an overview of captured packets in columns: packet number, time, source, destination, protocol, length, and a summary.
* **\[5] Packet Headers:** Expands headers in a hierarchical structure, from Layer 1 (frame) to Layer 7 (application). Provides detailed protocol information such as DNS query flags and answers.

**Hex Dump & ASCII:** The bottom pane shows the raw packet in hexadecimal and ASCII. Highlighting a section reveals its corresponding field, such as `tcp.seq` for TCP sequence numbers, which aids in constructing display filters.

***

## Introduction to Wireshark (Analysis)

This section explains how to use Wireshark features to enhance manual network traffic analysis. It covers applying display filters, following protocol streams, customizing packet list columns, and viewing capture statistics such as protocol hierarchies, conversations, and endpoints.

***

### Applying Display Filters

Display filters refine the packet list to show only relevant traffic.

*   To filter by protocol or header field:

    ```plaintext
    dns
    icmp
    ```

    These show only DNS traffic or ICMP pings.
*   To filter by header field values:

    ```plaintext
    tcp.port == 22
    ip.addr == 10.0.5.25
    ```

    These display SSH traffic or packets involving a specific internal host.
*   To combine filters with logical operators:

    ```plaintext
    (http.request.method == "POST" || http.request.method == "PUT") && ip.dst == 203.0.113.45
    ```

    Shows only outbound HTTP uploads (POST or PUT) to the external server `203.0.113.45`.
*   To exclude traffic:

    ```plaintext
    not tls
    ```

    Hides encrypted sessions so only clear-text protocols are displayed.

***

### Following Streams & Custom Columns

When analyzing multi-packet communications, Wireshark’s _Follow Stream_ feature reconstructs conversations.

* Example: Right-click a suspicious TCP packet on port 21 and select **Follow > TCP Stream**. This reconstructs the FTP login sequence, allowing you to see credentials in plain text.
* Example: Following an HTTP stream shows full requests and responses, such as `GET /confidential.pdf` and the server’s file content.

**Custom Columns:**

* Add `dns.qry.name` as a column to quickly identify hosts querying unusual domains like `malware-update.securemail.net`.
* Add `tcp.flags.syn` as a column to quickly see which packets initiated new connections, useful for spotting scans or floods.

***

### Viewing Capture Statistics

#### Protocol Hierarchy

Breaks down traffic by protocol layers.

* Example: An internal capture shows 60% SMB traffic, 30% HTTP, and 10% “other.” The “other” reveals unexpected IRC packets, worth investigating as possible command-and-control traffic.

#### Conversations

Lists who is talking to whom, including ports, bytes, and packets.

* Example: Host `10.0.5.30` has sent 50 MB of traffic to `198.51.100.77` on TCP port 4444, but received almost nothing back — a strong sign of data exfiltration.

#### Endpoints

Shows all unique hosts with their total transmitted and received traffic.

* Example: Host `10.0.5.99` sent 1,200 packets but received only 12. Sorting by transmitted packets highlights it as an outlier, possibly uploading bulk data to cloud storage.

Right-clicking on any entry in these statistics windows lets you auto-generate filters and pivot into detailed packet inspection.

***

## CMD and PowerShell For Incident Response

Windows systems can be investigated during incident response using built-in command line and PowerShell tools. These commands help identify unusual accounts, backdoors, persistence mechanisms, and active network connections.

***

### Command Line (CMD)

#### ipconfig /all

Displays full network configuration, including hostname, IP address, MAC address, and DNS servers.

```batch
C:\> ipconfig /all

Host Name . . . . . . . . . . . . : ACME-IR-LAB
Physical Address. . . . . . . . . : 00-16-3E-7B-9C-21
IPv4 Address. . . . . . . . . . . : 192.168.50.23
DNS Servers . . . . . . . . . . . : 192.168.50.10
```

***

#### tasklist

Lists running processes with their PIDs and memory usage.

```batch
C:\> tasklist

Image Name                     PID Session Name        Mem Usage
========================= ======== ================ ============
explorer.exe                 1420 Console             78,424 K
svchost.exe                  1108 Services            49,120 K
notepad.exe                  3244 Console             10,560 K
crypto_miner.exe             4120 Console            255,876 K
```

***

#### wmic process get description, executablepath

Shows processes and their associated executable paths.

```batch
C:\> wmic process get description, executablepath

Description        ExecutablePath
chrome.exe         C:\Program Files\Google\Chrome\Application\chrome.exe
explorer.exe       C:\Windows\explorer.exe
crypto_miner.exe   C:\Users\maria88\Downloads\crypto_miner.exe
```

***

#### net user

Lists all local system users.

```batch
C:\> net user

User accounts for \\ACME-IR-LAB
---------------------------------------------------
Administrator
DefaultAccount
Guest
john.smith
maria88
svc_update
```

***

#### net localgroup administrators

Shows members of the local Administrators group.

```batch
C:\> net localgroup administrators

Members of Administrators group:
---------------------------------------------------
Administrator
john.smith
svc_update
```

***

#### sc query | more

Lists services and their states.

```batch
C:\> sc query | more

SERVICE_NAME: Spooler
        STATE              : 4  RUNNING
SERVICE_NAME: WinDefend
        STATE              : 4  RUNNING
SERVICE_NAME: AcmeUpdater
        STATE              : 4  RUNNING
SERVICE_NAME: SuspiciousSvc
        STATE              : 4  RUNNING
```

***

#### netstat -ab

Displays listening ports and associated executables.

```batch
C:\> netstat -ab

Proto  Local Address    Foreign Address  State   PID
TCP    0.0.0.0:135      0.0.0.0:0        LISTEN  1088  [svchost.exe]
TCP    0.0.0.0:3389     0.0.0.0:0        LISTEN  1204  [svchost.exe]
TCP    0.0.0.0:8080     0.0.0.0:0        LISTEN  4120  [crypto_miner.exe]
```

***

### PowerShell

#### Get-NetIPAddress

Displays detailed network information.

```powershell
PS C:\> Get-NetIPAddress | Select-Object IPAddress, InterfaceAlias

IPAddress       InterfaceAlias
---------       --------------
192.168.50.23   Ethernet0
fe80::216:3eff:fe7b:9c21   Ethernet0
```

***

#### Get-LocalUser

Lists local users.

```powershell
PS C:\> Get-LocalUser

Name           Enabled Description
----           ------- -----------
Administrator  True    Built-in account
john.smith     True
maria88        True
svc_update     True    Suspicious service account
```

***

#### Get-LocalUser -Name svc\_update | Select \*

Retrieves all properties for a specific user.

```powershell
PS C:\> Get-LocalUser -Name svc_update | Select *

AccountExpires            : Never
Enabled                   : True
FullName                  :
PasswordChangeableDate    : 1/1/2025 12:00:00 AM
PasswordExpires           : Never
UserMayNotChangePassword  : False
PasswordRequired          : True
```

***

#### Get-Service | Where Status -eq "Running"

Shows running services.

```powershell
PS C:\> Get-Service | Where Status -eq "Running"

Status   Name             DisplayName
------   ----             -----------
Running  Spooler          Print Spooler
Running  WinDefend        Windows Defender
Running  SuspiciousSvc    Suspicious Service
```

***

#### Get-Process | Format-Table -View priority

Displays processes grouped by priority.

```powershell
PS C:\> Get-Process | Format-Table -View priority

PriorityClass Name              Id  CPU   WS
------------- ----              --  ---   --
Normal        explorer         1420  10 78424
Normal        notepad          3244   1 10560
Normal        chrome           3560  15 150000
High          crypto_miner     4120  95 255876
```

***

#### Get-ScheduledTask

Lists scheduled tasks, which can be used for persistence.

```powershell
PS C:\> Get-ScheduledTask

TaskName           State
--------           -----
AcmeUpdate         Ready
UserCleanup        Ready
SuspiciousTask     Ready
```

***

#### Get-ScheduledTask -TaskName SuspiciousTask | Select \*

Retrieves all properties for a specific scheduled task.

```powershell
PS C:\> Get-ScheduledTask -TaskName SuspiciousTask | Select *

TaskName      : SuspiciousTask
Author        : AcmeCorp\svc_update
Description   : Runs hidden binary on logon
Triggers      : LogonTrigger at startup
Actions       : C:\Users\maria88\AppData\Roaming\payload.exe
```

***

## DeepBlueCLI For Event Log Analysis

[DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI) is a PowerShell script created by SANS to help investigate and triage Windows Event Logs. It can analyze exported `.evtx` files or run live against local logs. It is capable of detecting activities such as user creation, group membership changes, password guessing or spraying, use of BloodHound, obfuscated PowerShell commands, suspicious service creation, Mimikatz credential dumping, and more.

***

### Using DeepBlueCLI

After downloading DeepBlueCLI, the folder contains the core script `DeepBlue.ps1` along with supporting files. Analysis can be performed against saved log files or the live system’s event logs.

#### Preparing the Environment

When run for the first time, PowerShell may block execution because the script is unsigned. Bypass this restriction for the current user:

```powershell
PS C:\Users\john.smith\Downloads\DeepBlueCLI> Set-ExecutionPolicy Bypass -Scope CurrentUser
```

***

#### Analyzing an Exported Log File

Navigate into the tool’s folder and run the script against a log file.

```powershell
PS C:\Users\john.smith\Downloads\DeepBlueCLI> ./DeepBlue.ps1 ../Log1.evtx
```

**Example output:**

```powershell
04/30/2019  09:15:23  Password Spray Attack Detected
  Targeted Accounts: maria88, steve.e, guest
  Count of Accounts: 3
  Attacker Account: attacker01
  Hostname: ACME-WIN-SRV1
  Event ID: 4625
```

This result shows multiple failed logins consistent with a password spraying attack, including the usernames involved and the system details.

***

#### Detecting Suspicious Command Lines

Targeting another file may reveal obfuscated or malicious activity.

```powershell
PS C:\Users\john.smith\Downloads\DeepBlueCLI> ./DeepBlue.ps1 ../Log2.evtx
```

**Example output:**

```powershell
Suspicious Command Line Detected
  Encoded PowerShell Command:
  powershell.exe -NoP -Enc SQBmACgAWwBJAG4AdAB...
```

The output highlights suspicious long Base64-encoded PowerShell commands, which may indicate malware delivery or post-exploitation.

***

#### Analyzing Local System Logs

DeepBlueCLI can also analyze the active system’s event logs directly:

```powershell
PS C:\Users\john.smith\Downloads\DeepBlueCLI> ./DeepBlue.ps1 -log security
PS C:\Users\john.smith\Downloads\DeepBlueCLI> ./DeepBlue.ps1 -log system
```

These commands allow live investigation of security and system logs without requiring exported `.evtx` files.

***
