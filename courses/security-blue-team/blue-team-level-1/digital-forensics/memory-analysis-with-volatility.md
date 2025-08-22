# Memory Analysis With Volatility

## Section Introduction

This section introduces Volatility for analyzing memory dumps and locating digital evidence.

***

## What is Volatility?

[Volatility](https://volatilityfoundation.org/volatility-training/) is an open-source memory forensics tool designed for incident response and malware analysis. It is built in Python and supports Windows, macOS, and Linux memory dumps. Created by Aaron Walters, it stems from his research in memory forensics.

Key capabilities include:

* Enumerating running processes.
* Listing active and closed network sessions.
* Viewing Internet Explorer browsing history.
* Locating and extracting files from memory.
* Reading open Notepad contents.
* Recovering commands from Windows CMD.
* Scanning memory with YARA rules.
* Extracting screenshots and clipboard data.
* Dumping hashed passwords.
* Retrieving SSL keys and certificates.

***

## Volatility Walkthrough

### imageinfo

**Explanation:** Determines the suggested profile (OS, version, architecture) needed for analysis of the memory image.

```bash
volatility -f memdump.mem imageinfo
```

**Example Output:**

```plaintext
Suggested Profile(s) : Win7SP1x64, Win7SP0x64
KDBG : 0xf80002a120a0
Number of Processors : 2
Image date and time : 2023-03-10 12:41:23 UTC+0000
```

***

### pslist

**Explanation:** Lists processes that were running in the memory image, showing IDs, parent IDs, threads, handles, and timestamps.

```bash
volatility -f memdump.mem --profile=Win7SP1x64 pslist
```

**Example Output:**

```plaintext
Offset(V)  Name          PID   PPID  Thds  Hnds  Time
0x827c5d48 System         4      0    72   490  2023-03-10 12:38:12 UTC+0000
0x824e8da0 smss.exe     228      4     2    29  2023-03-10 12:38:13 UTC+0000
```

***

### pstree

**Explanation:** Displays processes in a hierarchical tree view, making it easier to see parent-child relationships.

```bash
volatility -f memdump.mem --profile=Win7SP1x64 pstree
```

**Example Output:**

```plaintext
System(4)
  smss.exe(228)
    csrss.exe(340)
    wininit.exe(368)
      services.exe(456)
        svchost.exe(600)
```

***

### psscan

**Explanation:** Scans memory for process objects, including hidden or terminated processes often used by malware. Compare with `pslist` to spot discrepancies.

```bash
volatility -f memdump.mem --profile=Win7SP1x64 psscan
```

**Example Output:**

```plaintext
Offset(P)   Name         PID  PPID   Time
0x2f3c5d40  malware.exe 1420  368  2023-03-10 12:39:45 UTC+0000
```

***

### psxview

**Explanation:** Cross-checks process listings across multiple techniques, showing whether each process appears in expected places. Differences can reveal hidden processes.

```bash
volatility -f memdump.mem --profile=Win7SP1x64 psxview
```

**Example Output:**

```plaintext
Offset(P)   Name        PID   pslist psscan thrdproc pspcid csrss session desk
0x2f3c5d40  malware.exe 1420  False  True   True     True   False  False  False
```

***

### procdump

**Explanation:** Dumps a process executable from memory to disk. Requires specifying the process ID. Useful for further malware analysis.

```bash
volatility -f memdump.mem --profile=Win7SP1x64 procdump -p 1420 --dump-dir=./
```

**Example Output:**

```plaintext
Process(V) ImageBase Name         Result
0x2f3c5d40 0x400000  malware.exe  OK: dumped
```

***

### netscan

**Explanation:** Identifies network connections (active and closed) at the time of capture. Useful for tracking communication with remote systems.

```bash
volatility -f memdump.mem --profile=Win7SP1x64 netscan
```

**Example Output:**

```plaintext
Offset(P) Proto Local Address       Foreign Address     State
0x3f2c89a0 TCP   192.168.1.15:49213 93.184.216.34:80    ESTABLISHED
```

***

### timeliner

**Explanation:** Builds a timeline of activity (process creation, file events, etc.) from timestamps in the memory image. Helpful for reconstructing an incident.

```bash
volatility -f memdump.mem --profile=Win7SP1x64 timeliner
```

**Example Output:**

```plaintext
2023-03-10 12:39:45 UTC+0000  [Process] Created: malware.exe (PID 1420)
2023-03-10 12:40:12 UTC+0000  [Network] Connection to 93.184.216.34:80
```

***

### iehistory

**Explanation:** Extracts Internet Explorer browsing history from memory. Shows visited sites and timestamps.

```bash
volatility -f memdump.mem --profile=Win7SP1x64 iehistory
```

**Example Output:**

```plaintext
User: john.smith
URL: http://msn.com/
Visited: 2023-03-10 12:41:00 UTC+0000
```

***

### filescan

**Explanation:** Searches memory for file objects and lists them. Can reveal files that were in use or opened.

```bash
volatility -f memdump.mem --profile=Win7SP1x64 filescan
```

**Example Output:**

```plaintext
Offset(P)  File Name
0x3c7d2e40 \Program Files\Wireshark\wireshark.exe
0x3c7d5f90 \Users\john.smith\Desktop\Report.docx
```

***

### cmdline

**Explanation:** Retrieves the command-line arguments a process was launched with. Often useful for spotting malicious execution parameters.

```bash
volatility -f memdump.mem --profile=Win7SP1x64 cmdline -p 1420
```

**Example Output:**

```plaintext
malware.exe pid: 1420
Command line : malware.exe --connect 93.184.216.34 --stealth
```

***

### dumpfiles

**Explanation:** Extracts files referenced in memory to a specified directory for analysis.

```bash
volatility -f memdump.mem --profile=Win7SP1x64 dumpfiles -n --dump-dir=./
```

**Example Output:**

```plaintext
Dumped \Users\john.smith\Desktop\Report.docx
Dumped \Program Files\Wireshark\wireshark.exe
```

***

## Volatility 3

Volatility 2 was released in 2011 and support ended in August 2021. Volatility 3, released in 2020, is a complete rewrite that improves performance, functionality, and usability.

***

### Volatility 3 Changes

Profiles are no longer required. In Volatility 2, analysts had to run:

```bash
volatility -f memdump.mem imageinfo
```

and then include `--profile=PROFILE` in every command. Volatility 3 replaces this with **symbol tables**, which automatically identify structures in memory images and streamline analysis.

The way plugins are used has also changed. Instead of generic plugin names, Volatility 3 uses **OS-specific plugins**.

***

### Command Differences

| Purpose                       | Volatility 2 Command                                         | Volatility 3 Command                                   |
| ----------------------------- | ------------------------------------------------------------ | ------------------------------------------------------ |
| Get process tree              | `volatility --profile=PROFILE pstree -f file.dmp`            | `python3 vol.py -f file.dmp windows.pstree`            |
| List services                 | `volatility --profile=PROFILE svcscan -f file.dmp`           | `python3 vol.py -f file.dmp windows.svcscan`           |
| List available registry hives | `volatility --profile=Win7SP1x86_23418 -f file.dmp hivelist` | `python3 vol.py -f file.dmp windows.registry.hivelist` |
| Print cmd commands            | `volatility --profile=PROFILE cmdline -f file.dmp`           | `python3 vol.py -f file.dmp windows.cmdline`           |

* `--profile` is no longer present in Volatility 3.
* Generic plugin names are now replaced with OS-specific variants:
  * `pstree` → `windows.pstree`, `linux.pstree`, `mac.pstree`.
* Analysts must learn different plugin names, but resources like the [Volatility Cheat Sheet](https://blog.onfvp.com/post/volatility-cheatsheet/) help with conversion.

***

## Volatility Workbench

[Volatility Workbench](https://www.osforensics.com/tools/volatility-workbench.html) is a free, open-source GUI variant of Volatility 3 that runs on Windows.

Advantages:

* No Python installation required.
* No command-line parameters to remember.
* Saves platform and process list alongside the image in a `.CFG` file for faster reloads.
* Easier copy and paste.
* Simple saving of dumped data to disk.
* Drop-down of available commands with short descriptions.
* Command execution is time-stamped.

***

### Using Volatility Workbench

Launch `VolatilityWorkbench.exe`.

* Click **Browse Image** (top right) and select the memory dump.
* Choose **Platform (OS)** and a command from the drop-downs (top left).
* Run the command to view results. Example: executing `windows.pslist` returns process listings immediately.
* Use **Copy** (bottom right) to place results on the clipboard, or **Save to file** to export.

Note: The tool runs on Windows only; it isn’t available natively on Linux.

***
