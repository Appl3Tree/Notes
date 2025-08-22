# Windows Investigations

## Section Introduction

This section covers digital forensic techniques, artifacts, and investigation methods specific to Microsoft Windows operating systems.

***

## Windows Artifacts - Programs

Artifacts related to applications on Windows provide evidence of program execution, including timestamps, file paths, and frequency of use. Key artifacts include LNK files, Prefetch files, and Jump List files.

***

### LNK Files / Shortcut Analysis

#### Artifact Description

LNK files act as shortcuts linking to applications or files. They store metadata such as linked path, creation/modification/access times, and file size.

#### Artifact Location

`C:\Users\$USER$\AppData\Roaming\Microsoft\Windows\Recent`

#### Artifact Analysis

LNK files can be examined with [Windows File Analyzer](https://www.mitec.cz/wfa.html) to extract metadata in a readable format.

#### Example

```powershell
dir C:\Users\john.smith\AppData\Roaming\Microsoft\Windows\Recent
```

```plaintext
05/29/2024  10:11 AM    <DIR>          .
05/29/2024  10:11 AM    <DIR>          ..
05/29/2024  09:55 AM             3,584 ProjectPlan_AcmeCorp.lnk
05/28/2024  08:32 PM             2,048 Report_Q2_AcmeCorp.lnk
```

***

### Prefetch Files

#### Artifact Description

Prefetch files record data about program execution, including executable name, path, last run time, number of executions, and related file paths.

#### Artifact Location

`C:\Windows\Prefetch`

#### Artifact Analysis

Tools such as [Prefetch Explorer Command Line (PECmd.exe)](https://ericzimmerman.github.io/#!index.md) display prefetch metadata.

#### Example

```powershell
PECmd.exe -f C:\Windows\Prefetch\OUTLOOK.EXE-12345678.pf
```

```plaintext
Application Name  : OUTLOOK.EXE
Run Count         : 15
Last Run Time     : 2024-05-29 09:48:00
Created Time      : 2024-04-12 14:10:33
Modified Time     : 2024-05-29 09:48:00
Related Files:
  C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE
  C:\Users\john.smith\AppData\Roaming\AcmeCorp\Profile.dat
```

***

### Jump List

#### Artifact Description

Jump List files track application usage, pinned programs, and opened files. Two formats exist:

* **automaticDestination-ms**
* **customDestination-ms**

They contain paths, timestamps, and AppIDs.

#### Artifact Location

* `C:\Users\$USER$\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations`
* `C:\Users\$USER$\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations`

#### Artifact Analysis

Use [JumpList Explorer](https://ericzimmerman.github.io/#!index.md) to parse and review application usage evidence.

#### Example

```powershell
dir C:\Users\john.smith\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations
```

```plaintext
05/29/2024  10:05 AM    3,210  1b4dd67f29cb1962.customDestinations-ms
05/29/2024  09:50 AM    2,842  9d1f905ce5044aee.customDestinations-ms
```

***

In practice, LNK, Prefetch, and Jump List artifacts provide a timeline of user activity, program execution, and file access on Windows systems.

***

## Windows Artifacts - Browsers

Browser artifacts provide detailed evidence of user activity, including visited websites, search terms, downloads, cached webpages, cached images, cookies, and stored credentials. On Windows, these artifacts are most commonly retrieved from Microsoft Edge, Google Chrome, and Mozilla Firefox.

For analysis, three tools are typically used:

* [KAPE](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape) – Collection of browser artifacts from a live system.
* [Browser History Viewer (BHV)](https://www.foxtonforensics.com/browser-history-viewer) – Free tool for viewing browsing history, cached webpages, and cached images.
* [Browser History Capturer (BHC)](https://www.foxtonforensics.com/browser-history-capturer) – Companion tool to reliably capture browser data for import into BHV.

***

### Acquisition via KAPE

#### Description

KAPE can be configured to target browser artifacts from Chrome, Edge, and Firefox during live acquisition. Data is extracted directly from a system’s C drive to a specified output folder.

#### Example

```powershell
kape.exe --target Browser --tdest C:\ --odest C:\Users\john.smith\Desktop\KAPE_Browser_Forensics
```

```plaintext
KAPE executed successfully in 52 seconds.
Output stored at: C:\Users\john.smith\Desktop\KAPE_Browser_Forensics
```

#### Output Locations

* Chrome: `KAPE_Browser_Forensics\C\Users\john.smith\AppData\Local\Google\Chrome\User Data`
* Firefox: `KAPE_Browser_Forensics\C\Users\john.smith\AppData\Roaming\Mozilla\Firefox\Profiles`
* Edge: `KAPE_Browser_Forensics\C\Users\john.smith\AppData\Local\Microsoft\Edge\User Data`

***

### Browser History Viewer (BHV) with Browser History Capturer (BHC)

#### Description

BHC collects browser artifacts (including Edge data, which BHV alone may miss) and stores them in a capture directory. BHV then parses this data to provide a graphical interface for analysis.

#### Workflow

1. Run **BHC** to capture browser data for a specific user profile.
2. Import the captured folder into **BHV** via _File > Load History_.
3. Use BHV to examine artifacts across three main panes:
   * **Pane 1:** Website History, Cached Images, Cached Web Pages.
   * **Pane 2:** Website Visit Counts.
   * **Pane 3:** Filtering by browser, date, or keyword.

#### Example – Capturing Data

```powershell
BrowserHistoryCapturer.exe --user john.smith --out C:\Tools\BHC\Capture
```

```plaintext
Capture complete.
Data stored at: C:\Tools\BHC\Capture
```

#### Example – Loading into BHV

```plaintext
File > Load History > Load history captured using Browser History Capturer
```

#### Analysis Capabilities

* **Website History:** URLs, visit counts, access dates, and browser source.
* **Cached Images:** Display of stored web images, often linked to browsing sessions or ads.
* **Cached Web Pages:** Offline storage of visited pages, allowing investigators to reconstruct what the user saw.

***

By combining KAPE, BHC, and BHV, investigators can reliably collect and analyze web artifacts, reconstruct browsing sessions, and identify evidence of malicious downloads or suspicious searches.

***

## Windows Artifacts - Logon Events

Logon events provide evidence of account activity on a Windows system. Tracking successful, special, failed logons, and logoffs allows investigators to attribute user activity to specific accounts and sessions.

***

### Artifact Description

Relevant event IDs:

* **4624** – Successful Logon
* **4672** – Special Logon (administrative privileges)
* **4625** – Failed Logon
* **4634** – Logoff

***

### Artifact Location

Windows Event Logs are stored at:\
`C:\Windows\System32\winevt\Logs\`

The Security logs of interest are located in:\
`C:\Windows\System32\winevt\Logs\Security.evtx`

#### Example

```powershell
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 4624} | Select-Object -First 3
```

```plaintext
   ProviderName: Microsoft-Windows-Security-Auditing

TimeCreated           Id LevelDisplayName Message
-----------           -- ---------------- -------
5/29/2024 9:55:22 AM 4624 Information     An account was successfully logged on.
5/29/2024 9:48:13 AM 4624 Information     An account was successfully logged on.
5/29/2024 8:02:45 AM 4624 Information     An account was successfully logged on.
```

***

### Artifact Analysis – 4624 Successful Logon

Event 4624 records account logons. **Logon Type** values are especially important:

* 2 – Interactive (physical logon)
* 3 – Network (network access)
* 4 – Batch (automated job)
* 5 – Service (service account logon)
* 6 – Proxy (rare; legacy)
* 7 – Unlock (resuming a locked session)
* 8 – NetworkCleartext (cleartext credentials)
* 9 – NewCredentials (`RunAs /netonly`)

#### Example

```powershell
Get-WinEvent -LogName Security -FilterHashtable @{Id=4624} | Select-Object -First 1 | Format-List
```

```plaintext
Id          : 4624
Logon Type  : 2
Account Name: john.smith
Domain      : AcmeCorp
Logon ID    : 0x25A036D
TimeCreated : 5/29/2024 9:55:22 AM
```

***

### Artifact Analysis – 4672 Special Logon

Event 4672 indicates privileged accounts (administrators) logging in. Key fields include **Subject information** (username, domain, Security ID), **Logon ID** (for session tracking), and **Timestamp**.

#### Example

```powershell
Get-WinEvent -LogName Security -FilterHashtable @{Id=4672} | Select-Object -First 1 | Format-List
```

```plaintext
Id          : 4672
Account Name: john.smith@outlook.com
Security ID : ACMEPC01\john.smith
Logon ID    : 0x25A036D
Privileges  : SeDebugPrivilege, SeImpersonatePrivilege
TimeCreated : 5/29/2024 9:55:23 AM
```

***

### Artifact Analysis – 4625 Failed Logon

Event 4625 captures failed logon attempts, including **status/error codes** that identify why the attempt failed.

#### Common NETLOGON Error Codes

| Error Code | Description                                                                    |
| ---------- | ------------------------------------------------------------------------------ |
| 0xC0000064 | The specified user does not exist                                              |
| 0xC000006A | The value provided as the current password is not correct                      |
| 0xC000006C | Password policy not met                                                        |
| 0xC000006D | The attempted logon is invalid due to a bad user name                          |
| 0xC000006E | User account restriction has prevented successful login                        |
| 0xC000006F | The user account has time restrictions and may not be logged onto at this time |
| 0xC0000070 | The user is restricted and may not log on from the source workstation          |
| 0xC0000071 | The user account’s password has expired                                        |
| 0xC0000072 | The user account is currently disabled                                         |
| 0xC000009A | Insufficient system resources                                                  |
| 0xC0000193 | The user’s account has expired                                                 |
| 0xC0000224 | User must change password before first logon                                   |
| 0xC0000234 | The user account has been automatically locked                                 |

Repeated failed attempts with certain codes (e.g., 0xC000006D – bad username, or 0xC0000072 – disabled account) may indicate brute force or account enumeration.

#### Example

```powershell
Get-WinEvent -LogName Security -FilterHashtable @{Id=4625} | Select-Object -First 1 | Format-List
```

```plaintext
Id          : 4625
Account Name: admin123
Domain      : AcmeCorp
Failure Code: 0xC000006A
Logon Type  : 3
TimeCreated : 5/29/2024 9:57:41 AM
```

***

### Artifact Analysis – 4634 Logoff

Event 4634 logs user session termination. **Logon ID** links it to the corresponding logon (4624 or 4672). Combined with timestamps, it allows investigators to map session duration.

#### Example

```powershell
Get-WinEvent -LogName Security -FilterHashtable @{Id=4634} | Select-Object -First 1 | Format-List
```

```plaintext
Id          : 4634
Account Name: john.smith
Domain      : AcmeCorp
Logon ID    : 0x25A036D
Logon Type  : 7
TimeCreated : 5/29/2024 10:15:03 AM
```

***

## Windows Artifacts - Recycle Bin

The Windows Recycle Bin temporarily stores deleted files before permanent removal. In digital forensics, it is useful for recovering deleted data, tracing user activity, and analyzing deletion attempts. Even when emptied, file remnants may still be recoverable through carving techniques.

***

### Artifact Description

Key forensic values of the Recycle Bin:

* **Recovery of deleted files**: Recently deleted items can be restored or examined.
* **Tracing user activity**: Presence of files can indicate attempts to hide or destroy evidence.
* **File remnants**: Emptied bins may still yield recoverable content via carving.
* **Metadata analysis**: $I files store original filename, path, size, and deletion timestamp.

***

### Artifact Location

On Windows 10, the Recycle Bin is located at:\
`C:\$Recycle.Bin`

Each user has a subfolder named after their **SID**.

If the Recycle Bin is emptied, artifacts are lost unless remnants are carved from disk.

#### Example

```batch
dir C:\$Recycle.Bin /a
```

```plaintext
05/29/2024  09:55 AM    <DIR>          .
05/29/2024  09:55 AM    <DIR>          ..
05/29/2024  09:55 AM    <DIR>          S-1-5-21-1234567890-2345678901-3456789012-1010
```

***

### Artifact Analysis Overview

Tools used for Recycle Bin analysis:

* **Command Prompt (CMD)** – list hidden Recycle Bin contents.
* [**RBCmd**](https://github.com/EricZimmerman/RBCmd) – parse $I/$R file pairs for metadata.
* **CSVQuickViewer** – review RBCmd CSV output in a readable format.

***

### Technical Analysis

1.  **Identify user SID folder**

    ```batch
    wmic useraccount get name,SID
    ```

    ```plaintext
    Name          SID
    john.smith    S-1-5-21-1234567890-2345678901-3456789012-1010
    ```

    The SID ending in `1010` belongs to `john.smith`.
2.  **Inspect hidden contents**

    ```batch
    dir C:\$Recycle.Bin\S-1-5-21-...-1010 /a
    ```

    ```plaintext
    $I1UOZ51.xlsx
    $R1UOZ51.xlsx
    ```

    * `$R*` → actual file contents.
    * `$I*` → metadata for the corresponding $R file.
3.  **Analyze a single file with RBCmd**

    ```batch
    C:\Tools\RBCmd.exe -f $I1UOZ51.xlsx
    ```

    ```plaintext
    Original Filename : DU Financials 2022.xlsx
    Original Path     : C:\Users\john.smith\Downloads\
    File Size         : 1.8 MB
    Deletion Time     : 2023-04-12 13:18:00
    ```
4.  **Analyze an entire directory and export results**

    ```batch
    C:\Tools\RBCmd.exe -d . --csv "C:\Users\john.smith\Desktop\RBCmdOutput"
    ```

    ```plaintext
    Processing directory: .
    Found 12 $I files
    Output written to: C:\Users\john.smith\Desktop\RBCmdOutput
    ```

    The CSV can then be opened with CSVQuickViewer for review.
5. **System-wide analysis**\
   Run RBCmd from `C:\$Recycle.Bin` with `-d .` to recurse through all user SID subfolders.

***
