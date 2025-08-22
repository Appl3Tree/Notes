# Logging and Aggregation

## Section Introduction

Overview of logging, its role in SIEM, and how it enables aggregation, normalization, and detection of suspicious activity across an environment.

***

## What is Logging?

Logs record application details, system performance, and user activities, providing insight into usage, network traffic, security events, and errors. Every activity—from emails and logins to firewall updates—should be logged for monitoring.

Examples include:

* **Windows Active Directory logs** track account logins, failed password attempts, admin account use, and account creation/deletion, helping detect brute-force or password spraying attacks.
* **Firewall connection logs** capture port scans, vulnerability scans, denial-of-service attempts, and network issues.

Because SIEMs are analysis platforms, not storage repositories, it is critical to define what logs are collected. Proper scoping reduces noise and ensures focus on relevant, actionable data.

***

## Syslog

System Logging Protocol (Syslog) is a standard defined in RFC 5424 for transmitting system and event log messages to a central server. It centralizes data collection from devices such as switches, routers, firewalls, Linux/Unix systems, and custom applications.

Windows systems use their own event manager by default but can be configured to forward logs via Syslog.

By default, Syslog uses **UDP 514**. **TCP 514** may be enabled for reliability, and **TCP 6514** is often used when secure transfer is required. Syslog does not natively provide authentication or encryption, leaving it open to certain attacks.

Syslog plays a critical role in network monitoring by capturing events that may not otherwise be noticed. Best practice is to use Syslog in combination with other monitoring tools for complete visibility.

***

### Syslog Messages

A Syslog message consists of three parts: **Priority Value (PRI)**, **Header**, and **Message**.

#### Priority Value (PRI)

The PRI value is derived from the **Facility Code** and the **Severity Level**, calculated as:

```plaintext
(facility code * 8) + severity value = PRI
```

**Facility Codes**

| Code  | Facility            |
| ----- | ------------------- |
| 0     | kernel messages     |
| 1     | user-level messages |
| 2     | mail system         |
| 3     | system daemons      |
| 4     | security/auth       |
| 5     | syslog              |
| 6     | line printer        |
| 7     | network news        |
| 8     | UUCP                |
| 9     | clock daemon        |
| 10    | security/auth (10)  |
| 11    | FTP daemon          |
| 12    | NTP subsystem       |
| 13    | log audit           |
| 14    | log alert           |
| 15    | clock daemon (15)   |
| 16–23 | local use 0–7       |

**Severity Levels**

| Value | Severity      | Description                      |
| ----- | ------------- | -------------------------------- |
| 0     | Emergency     | System is unusable               |
| 1     | Alert         | Immediate action required        |
| 2     | Critical      | Critical conditions              |
| 3     | Error         | Error conditions                 |
| 4     | Warning       | Warning conditions               |
| 5     | Notice        | Normal but significant condition |
| 6     | Informational | Informational messages           |
| 7     | Debug         | Debug-level messages             |

***

#### Header

Contains metadata such as timestamp, hostname, application name, and message ID. This identifies where the message originated.

#### Message

Carries the log content. The format is not strictly defined and may include human-readable or machine-readable text. Each message includes:

* **Facility** – describes the function of the application that generated it (e.g., mail servers use the “mail” facility).
* **Severity** – indicates the importance of the event.
* **Action** – typically a file location in the `/var/log/` directory tree where the message is stored.

***

## Windows Event Logs

Windows Event Logs are binary `.evtx` files stored locally on Windows systems.

*   **Windows 2000 – XP / Server 2003**:

    ```
    %WinDir%\system32\Config\*.evt
    ```
*   **Windows Vista – 10 / Server 2008 – 2019**:

    ```
    %WinDir%\system32\WinEVT\Logs\*.evtx
    ```

These logs record hardware events, logins, program executions, and installations, enabling administrators to monitor system activity and diagnose issues.

#### Event Categories

* **Application** – Logged by applications (execution, deployment errors).
* **System** – Logged by the OS (device loading, startup errors).
* **Security** – Login/logout events, file deletion, admin permission changes.
* **Directory Service** – AD events (Domain Controllers only).
* **DNS Server** – DNS service events (DNS servers only).
* **File Replication Service** – Replication events (Domain Controllers only).

**Further reading:**

* [Event Log Tutorial – ManageEngine](https://www.manageengine.eu/network-monitoring/Eventlog_Tutorial_Part_I.html)
* [Windows Logging Basics – Loggly](https://www.loggly.com/ultimate-guide/windows-logging-basics/)

***

### Security Event Logs

Security Event Logs store records tied to **Windows Security Audit policies**, providing fine-grained monitoring.

Key elements include:

* Account logon events (valid/invalid sign-ons and sign-offs).
* Account management (create, modify, delete accounts).
* Privilege use.
* Resource usage (file operations).

**Further reading:**

* [Windows Security Audit – NXLog](https://docs.nxlog.co/integrate/windows-security-audit.html)
* [Security Log Encyclopedia – Ultimate Windows Security](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx)
* [Windows Security Event Logs Cheatsheet – Andrea Fortuna](https://www.andreafortuna.org/2019/06/12/windows-security-event-logs-my-own-cheatsheet/)

***

### Event Viewer

Windows 10 includes **Event Viewer** for visualizing logs. Launch it via the search bar.

* **Summary of Administrative Events** – Shows high-level event counts (Critical, Error, Warning).
* **Windows Logs categories**: Application, Security, Setup, System, Forwarded Events.

#### Security Events Example

* **Event ID 5379** – User logon with Credential Manager check.
  * _Security ID_ – Account SID.
  * _Account Name_ – Username.
  * _Account Domain_ – Domain (default: WORKGROUP).
  * _Logon ID_ – Semi-unique session identifier.
  * _Read Operation_ – Credential validation.
* **Event ID 4624 (Logon)** – User logon.
* **Event ID 4672 (Special Logon)** – Administrative account logon.

Monitoring these IDs helps detect:

* Logons at unusual hours (possible compromise).
* Administrative activity (potential insider threat or elevated compromise).

***

### Custom Views

Custom Views in Event Viewer allow filtered monitoring by date, log type, source, keywords, or event IDs.

#### Example: Monitoring User Logins/Logoffs

Event IDs to include:

* **4624** – User logon successful.
* **4672** – Special logon.
* **4647** – User-initiated logoff.
* **4634** – User logoff.

This filter produces a clean timeline of user login/logout activity.

**Tip:** Create and save Custom Views for recurring monitoring needs, such as employee login times or admin account activity.

***

## Sysmon

Sysmon (System Monitor) is a Windows service and driver that persists across reboots to log detailed system activity into the Windows Event Log. It provides visibility into process creation, network connections, driver/DLL loading, and file creation changes. Sysmon logs can be collected via Windows Event Collection or SIEM agents, enabling detection of malicious or anomalous behavior and helping analysts understand attacker techniques.

***

### Benefits and Capabilities

* Logs process creation with full command line for current and parent processes.
* Includes a session GUID in each event for correlation across a logon session.
* Logs driver and DLL loading with signatures and hashes.
* Optionally logs network connections with process, IPs, ports, and hostnames.
* Detects changes in file creation timestamps, often used by malware to evade detection.
* Supports rule-based filtering to include or exclude events dynamically.

Windows Event Logs provide limited visibility, while Sysmon produces more detailed and better-formatted records. Many professionals prefer Sysmon for endpoint monitoring due to the depth of information it supplies.

**Recommended resource:** [Sysmon overview video by Black Hills Information Security](https://youtu.be/9qsP5h033Qk?t=491).

***

### Installing Sysmon

1. Download Sysmon from the [Sysinternals website](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
2. Extract the folder.
3. Open Command Prompt as Administrator.
4. Navigate to the folder with Sysmon executables.
5. Run:

```bash
sysmon -i
```

**Sample Output:**

```plaintext
System Monitor v14.14 - System activity monitor
Copyright (C) 2014-2023 Mark Russinovich and Thomas Garnier
Sysinternals - www.sysinternals.com

Sysmon installed.
SysmonDrv installed.
Starting SysmonDrv.
Sysmon service started.
```

Once installed, Sysmon logs can be viewed in Event Viewer by creating a **Custom View**. In enterprise environments, logs should be forwarded to the SIEM. To reduce noise, configuration files can be applied, such as the [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config).

***

## Other Logs

This lesson covers log sources outside of Syslog, Windows Event Logs, and Sysmon. These include cloud service logs, universal endpoint agents, and network traffic capture tools.

***

### Microsoft Azure

Microsoft Azure uses [Azure Monitor](https://azure.microsoft.com/en-us/services/monitor/#features) and [Log Analytic Workspaces](https://docs.microsoft.com/en-us/azure/azure-monitor/platform/manage-access) for logging and monitoring.

* Logs originate from virtual machines, virtual networks, Azure Active Directory, Security Center, and on-premises services.
* Three primary categories of logs: **Control/Management logs**, **Data Plane logs**, and **Processed Events**.
* Data is fed through the [REST API](https://searchapparchitecture.techtarget.com/definition/RESTful-API), Microsoft Graph API, JSON, and other sources.
* Logs can integrate with third-party SIEMs such as Splunk or Azure Sentinel.

To query logs, Azure uses [Kusto Query Language (KQL)](https://docs.microsoft.com/en-us/azure/azure-monitor/log-query/query-language). Example:

```plaintext
SecurityAlert
| where TimeGenerated > ago(1h)
```

***

### Amazon Web Services

AWS exposes an extensive [API](https://docs.aws.amazon.com/index.html) to manage and monitor services. Example API call:

```plaintext
https://ec2.amazonaws.com/?Action=RunInstances
&ImageId=ami-60a54009
&MaxCount=3
&MinCount=1
&Placement.AvailabilityZone=us-east-1b
&Monitoring.Enabled=true
&AUTHPARAMS
```

This call runs 1–3 instances using a specific Amazon Machine Image (AMI) in a defined availability zone, with monitoring enabled. Authentication parameters ensure security of the request.

***

### OSQuery

[Osquery](https://github.com/facebook/osquery) is an open-source endpoint agent developed by Facebook in 2014. It treats the operating system as a high-performance relational database.

* Queries use standard **SQL**, enabling cross-platform monitoring without proprietary query languages.
* Provides rich data sets for security monitoring and investigations.
* Acts as a flexible framework but requires planning for:
  * Configuration, deployment, and agent management.
  * Query pack scheduling.
  * Data storage, cost, and analysis strategy.
  * Handling suspicious activity and integrations with existing tools.
  * Troubleshooting and custom development.

***

### Moloch (Arkime)

[Moloch (Arkime)](https://github.com/aol/moloch) enhances security infrastructure by capturing and indexing network traffic in **PCAP** format.

* Provides a web interface for browsing, searching, and exporting packet captures.
* Exposes APIs for PCAP and JSON session data access.
* Stores packets in standard PCAP format, enabling use with other analysis tools like Wireshark.
* Scales to tens of gigabits/sec of traffic.
* Retention depends on sensor disk capacity (PCAP) and Elasticsearch cluster size (metadata).

***

## Log Aggregation Explained

Log aggregation is the process of collecting logs from multiple systems, parsing them, extracting structured data, and combining them into a format that is easily searchable by modern data tools.

There are four common aggregation methods, often combined in practice:

* **Syslog** – Standard protocol where a Syslog server collects logs from multiple systems in a condensed, queryable format.
* **Event Streaming** – Protocols such as SNMP, NetFlow, and IPFIX provide device operation data that can be parsed and stored centrally.
* **Log Collectors** – Software agents running on devices that capture, parse, and forward logs to a central aggregator.
* **Direct Access** – Aggregators pull logs directly via API or network protocol, requiring custom integrations per source.

***

### Data Types

Logs ingested into a SIEM fall into two main categories:

* **Structured data** – Logs with well-defined fields, such as Apache, IIS, Windows events, or Cisco device logs. These are easier to parse and normalize.
* **Unstructured data** – Logs from custom-built applications where formatting varies, messages may span multiple lines, and event boundaries are unclear. This type makes up the majority of SIEM data.

Normalization techniques are applied to unify log formats, enabling efficient searches across diverse data sources.

***
