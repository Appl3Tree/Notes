# Forensics Fundamentals

## Section Introduction

This section introduces core digital forensics concepts, including file systems, storage media, data representation, metadata, file carving, memory analysis, and the principle of Order of Volatility.

***

## Introduction to Data Representation

Data can be expressed in multiple formats, many of which are relevant to digital forensics and cybersecurity. Key representations include Binary, Base64, Hexadecimal, Octal, and ASCII. Tools such as [CyberChef](https://gchq.github.io/CyberChef/) are commonly used to encode, decode, and analyze these formats.

### Binary

Binary uses only two states, 0 and 1, to represent data. In hardware, 0 represents no electrical signal, and 1 represents the presence of a signal. One bit holds a single binary value, while one byte holds eight bits, allowing 256 possible values. Large files are stored as collections of these binary digits. Binary’s simplicity, efficiency in representing electrical signals, and compatibility with logic circuits make it the foundation of all computer data representation.\
**Example:** The letter **A** is represented as `01000001` in binary.

### Base64

Base64 is a reversible encoding algorithm that transforms binary data into ASCII text strings. It was developed to address compatibility issues when older systems or protocols, such as email, could only transmit text. By encoding files such as images or videos into text, Base64 enables transmission across systems and later decoding back into the original format. In forensics, Base64 may hide data such as images or illicit content within text files, making detection and decoding critical.\
**Example:** The word **Hello** is represented as `SGVsbG8=` in Base64.

### Hexadecimal

Hexadecimal (hex) is a base-16 numeral system using digits 0–9 and letters A–F. It provides a compact way to represent binary values and is widely used in programming and digital forensics. Hex is particularly useful for analyzing memory dumps, raw disk data, and low-level file structures, where binary values are translated into a more human-readable form.\
**Example:** The decimal number **255** is represented as `FF` in hex.

### Octal

Octal is a base-8 numeral system that groups binary digits into sets of three, each mapped to a single octal digit. It was historically used to simplify binary representation in systems with 12-, 24-, or 36-bit word lengths. Today, its primary application is in Linux and UNIX systems for representing file permissions using the `chmod` command.\
**Example:** The binary number **110101** is represented as `65` in octal.

### ASCII

ASCII (American Standard Code for Information Interchange) represents text using 8-bit binary values. Each letter, number, or symbol maps to a unique binary or decimal number (e.g., 65 for “A,” 97 for “a”). While modern systems often use Unicode for broader character sets, ASCII remains fundamental for analyzing text files and encoded data in digital forensics.\
**Example:** The string **Hi** is represented as `72 105` in ASCII decimal values.

### Using CyberChef

[CyberChef](https://gchq.github.io/CyberChef/), developed by GCHQ, is a powerful free tool that performs hundreds of operations on data, including encoding, decoding, parsing, and analysis. It is widely used in digital forensics to quickly identify and manipulate data representations.

***

## Hard Disk Drive Basics

Hard drives are a primary source of digital evidence, making it essential to understand how they function and where hidden data may exist. Key concepts include platters, sectors, clusters, and slack space.

### What are HDDs?

A hard disk drive (HDD) is a non-volatile storage device that reads and writes data on magnetic disks. HDDs typically store operating systems, applications, and user files, and connect to the motherboard using ATA, SATA, or SCSI interfaces. They are housed in drive bays and powered by the computer’s PSU.

### Platters

Platters are circular, rigid disks inside the HDD where magnetic data is stored. A hard drive usually contains multiple platters mounted on a spindle, each with two read/write heads to access both sides.

**Example:** A 1 TB HDD may use multiple platters, each storing hundreds of gigabytes per side, accessed by separate heads.

### Sectors

Sectors are subdivisions of tracks on a platter and represent the smallest storage unit. Traditionally, each sector stores 512 bytes, though modern drives use 4096-byte (4 KiB) sectors. Each sector includes a header (for addressing and error correction) and a data area.

**Example:** A file of 600 bytes stored on a 512-byte/sector drive will occupy 2 sectors: one full, one partially filled.

### Clusters

Clusters are groups of sectors and serve as the smallest allocation unit used by file systems. A file typically spans multiple clusters, and each cluster has a unique identifier that allows the drive to locate data efficiently.

**Example:** If a cluster is 8 KB (16 sectors of 512 bytes) and a file is 20 KB, it will occupy 3 full clusters plus part of a fourth.

### Slack Space

Slack space is unused storage within a cluster when a file does not completely fill its allocated space. This leftover data may contain fragments of previously deleted files, which can be valuable in forensic investigations.

**Example:** If a cluster is 8 KB and a file is only 6 KB, the remaining 2 KB may contain remnants of an old file that was stored in that space.

***

## Solid State Disk Drive Basics

Solid-state drives (SSDs) are a common source of digital evidence, making it important to understand their functionality and how data may be lost or hidden. Key concepts include garbage collection, TRIM, and wear leveling.

### What are SSDs?

SSDs are flash-based storage devices that are significantly faster than mechanical hard disk drives due to low read-access times and fast throughputs. Instead of magnetic platters, SSDs store data in “pages,” which are grouped into “blocks” for writing and management.

### Garbage Collection

Garbage collection is a background process in which the SSD controller identifies unused or outdated pages, moves valid data to new blocks, and erases old blocks to free up space.\
**Forensics impact:** Evidence can be permanently lost if garbage collection erases relevant data. To preserve evidence, SSDs must be powered off immediately by a hard shut-down or power removal, rather than a standard operating system shutdown.

### Trim

TRIM is a command that improves SSD efficiency by permanently clearing deleted data rather than just marking it as unallocated. Unlike traditional hard drives where deleted data can often be recovered, TRIM makes recovery nearly impossible.\
**Forensics impact:** As with garbage collection, investigators should power systems off immediately to avoid TRIM clearing potentially recoverable data.

### Wear Leveling

Wear leveling extends the lifespan of SSDs by evenly distributing writes across memory blocks to prevent damage from repeated use of the same cells. It is managed by the SSD’s controller or firmware using algorithms:

* **Dynamic wear leveling:** Moves data in frequently rewritten blocks to new ones, balancing wear but leaving static data unmoved.
* **Static wear leveling:** Moves even static data when erase counts fall below a threshold, achieving better wear distribution at the cost of slower write performance.

***

## File Systems

A file system is the method by which an operating system organizes, stores, and retrieves data on storage devices such as hard drives and optical disks. It provides mechanisms for data storage, hierarchical organization, management, navigation, access, and recovery. Forensics investigators must be able to identify and analyze different file systems, as each has unique structures and limitations.

### FAT16

File Allocation Table 16 (FAT16) uses a table to track file positions. It was the original file system for DOS and early Windows versions. FAT16 supported only small partitions, and if the table was corrupted or lost, the operating system could no longer locate files.

### FAT32

FAT32, introduced with Windows 98, expanded FAT16’s capabilities by supporting larger partitions and long filenames. It is compatible with a wide range of devices and operating systems, making it widely used. However, FAT32 has significant limitations, including a 4 GB maximum file size, 8 TB maximum partition size, lack of compression, encryption, and resilience against power loss.

### NTFS

NTFS (New Technology File System) was introduced with Windows NT and remains the default file system for Windows. It includes advanced features such as journaling, metadata support, improved reliability, and access control lists (ACLs). NTFS is more secure and efficient than FAT-based systems, though write support in macOS is limited without third-party tools.

### EXT3 / EXT4

#### Linux Architecture

Linux file systems consist of three main layers:

* **User Space:** Applications sending system calls.
* **Kernel Space:** The kernel managing I/O, memory, and file systems.
* **Disk Space:** Device drivers handling read/write requests to storage.

#### EXT3

EXT3 is a journaling file system widely used in Linux. It logs file system changes in a journal, enabling faster recovery after crashes compared to non-journaled systems.

#### EXT4

EXT4, released in 2008, supports volumes up to 1 exbibyte and files up to 16 tebibytes. It introduced extents, which group contiguous storage blocks, reducing fragmentation and improving performance.

### Identifying File Systems

During forensic analysis, tools like **FTK Imager** can identify the file system from disk images. By adding an evidence item (e.g., `disk2.img`) and examining it in FTK Imager, investigators can determine whether the system uses FAT, NTFS, EXT, or another file system.

***

## Digital Evidence and Handling

Digital evidence refers to any probative information stored or transmitted in digital form. Like physical trace evidence, digital activity often leaves traces when systems interact—for example, a webserver logging an IP address or a website placing cookies on a user’s device. However, because threat actors can easily manipulate digital evidence, it must be corroborated and verified before it can be trusted.

### Digital Evidence Forms

* **E-mails:** Written communications that may include attachments.
* **Digital Photographs:** Images themselves or metadata such as location and device details.
* **Logs:** System logs, such as Windows Event Logs, that record user activity.
* **Files:** Documents, code, images, or software that reveal user actions.
* **Messages:** Texts, iMessages, or chat platform communications.
* **Browser History:** Records of websites and resources accessed.
* **Backups:** Copies of deleted or overwritten files that can still be examined.
* **Video/Audio Files:** Media files that can serve as evidence and may contain metadata.

### Can We Trust It?

Digital evidence is voluminous, easily duplicated, and easily altered, which raises concerns about authenticity. Courts may require additional safeguards for digital evidence but increasingly reject authenticity challenges without proof of tampering. To mitigate risks, forensic examiners use hashing to verify the integrity of acquired data.

### Evidence Handling

Proper evidence handling ensures forensic soundness and admissibility in legal proceedings.

* **Altering the Original Evidence:** Analysts should avoid interacting with original evidence unless absolutely necessary. Any unavoidable alteration must be documented with justification.
* **Using Write-Blockers:** Write-blockers prevent accidental modifications to evidence.
  * _Software write-blockers_ operate at the OS level but are limited to specific systems.
  * _Physical write-blockers_ function at the hardware level and prevent changes regardless of OS.
* **Documentation:** Every action taken must be recorded in notes, diagrams, or photographs. The principle “If you didn’t write it down, it didn’t happen” ensures accountability and supports reconstruction of events if evidence integrity is questioned.

***

## Order of Volatility

When collecting digital evidence, it is crucial to understand volatility—how quickly data may be lost when a system powers down or changes state. Volatile evidence must be prioritized during acquisition to preserve its integrity. The **Internet Engineering Task Force (IETF)** provides formal guidance in [RFC 3227: Guidelines for Evidence Collection and Archiving](https://www.rfc-editor.org/rfc/rfc3227).

### Order of Volatility

#### 1 – Registers & Cache

The CPU cache and registers are the most volatile, changing constantly as instructions are processed. This data must be captured immediately or it will be lost.

#### 2 – Memory

RAM holds temporary information such as running processes, active network connections, and open files. A power loss or shutdown clears RAM, making it the next most volatile source of evidence.

#### 3 – Disk (HDD and SSD)

Disks provide persistent storage, but volatility arises when data is overwritten. SSDs are particularly vulnerable due to Garbage Collection and TRIM operations that can permanently erase data. If powered off, disks are no longer considered volatile.

#### 4 – Remote Logging and Monitoring Data

Logs stored on remote servers or monitoring systems are more stable than memory but subject to regular updates or overwrites. While valuable, they are typically collected after hard drive evidence.

#### 5 – Physical Configuration, Network Topology, Archival Media

System hardware details, network diagrams, and archived data (e.g., USB drives, external HDDs) are the least volatile. These change rarely and can be collected later in the process.

### Key Principle

Investigators must collect evidence in order of volatility, prioritizing the most fleeting sources (cache, RAM) before moving to persistent media. Volatile evidence should be quickly preserved on stable, non-volatile media such as external drives to prevent loss.

***

## Metadata and File Carving

Metadata provides descriptive details about data, while file carving enables recovery of hidden or deleted files. Together, they play a significant role in digital forensics by helping analysts extract deeper insights and recover critical evidence.

### Metadata

Metadata is “data about data.” For example, the text in a Word document is data, while metadata may include the author, date created, or word count. Images may include camera settings, resolution, or GPS location.

* **Windows:** Metadata can be viewed by right-clicking a file → **Properties** → **Details** tab.
* **Linux:** Commands such as `ls -lisap <file>` and `stat <file>` display metadata like permissions, file size, and timestamps.

**Example: `ls -lisap` output**

```bash
524288  4 drwxr-xr-x  2 ubuntu web     4096 Aug 20 13:59 ./  
524287  4 drwxr-xr-x  6 ubuntu web     4096 Aug 19 18:22 ../  
131072  8 -rw-r--r--  1 ubuntu web     3492 Aug 20 14:05 WebServer_Q3_AcmeCorp.conf  
```

**Example: `stat WebServer_Q3_AcmeCorp.conf` output**

```bash
File: WebServer_Q3_AcmeCorp.conf  
Size: 3492        Blocks: 8          IO Block: 4096   regular file  
Device: 802h/2050d   Inode: 131072    Links: 1  
Access: (0644/-rw-r--r--)  Uid: (1000/ubuntu)   Gid: (1001/web)  
Access: 2025-08-20 14:06:02.000000000 -0600  
Modify: 2025-08-20 14:05:37.000000000 -0600  
Change: 2025-08-20 14:05:40.000000000 -0600  
Birth:  2025-08-18 09:11:03.000000000 -0600  
```

* **ExifTool:** A versatile utility for retrieving metadata from many file types. Run `exiftool <filename>` to display detailed properties.

**Example: `exiftool SamplePhoto.jpg` output**

```bash
ExifTool Version Number         : 12.70  
File Name                       : SamplePhoto.jpg  
File Size                       : 245 kB  
File Modification Date/Time     : 2025:08:20 15:22:14-06:00  
File Access Date/Time           : 2025:08:20 15:24:01-06:00  
File Inode Change Date/Time     : 2025:08:20 15:22:14-06:00  
File Permissions                : rw-r--r--  
File Type                       : JPEG  
MIME Type                       : image/jpeg  
Make                            : Canon  
Camera Model Name               : Canon EOS 80D  
Create Date                     : 2025:08:15 12:18:03  
Modify Date                     : 2025:08:15 12:18:03  
GPS Latitude                    : 40 deg 45' 12.00" N  
GPS Longitude                   : 111 deg 53' 25.00" W  
```

This example shows both standard file properties and embedded camera/GPS metadata.

***

### File Carving

File carving is the process of recovering files from raw data streams, such as disk images, even after deletion. Tools like **Scalpel** are used to scan disk images and reconstruct deleted files by identifying file headers and footers.

**Steps with Scalpel:**

1. Edit `/etc/scalpel/scalpel.conf` to enable the desired file type (e.g., remove “#” in the JPG section).
2. Run the tool:

```bash
scalpel -o <output_directory> <disk_image_file>  
```

**Example:**

```bash
scalpel -o /root/Desktop/ScalpelOutput DiskImage1.img  
```

**Example output:**

```bash
Scalpel version 2.1  
Opening target "DiskImage1.img"  
Image file pass 1/2.  
Audit log is /root/Desktop/ScalpelOutput/audit.txt  
Allocated 16 file handlers.  
  
Scalpel is done, files carved = 1, elapsed = 0 seconds.  
```

3. Review the output directory for recovered files and audit logs.

Scalpel can also be customized with user-defined profiles for detecting specific or proprietary file types.

***

### Chown Command

In Linux forensics, permissions often affect access to evidence files. The `chown` command (change owner) modifies file ownership.

**Syntax:**

```bash
chown [options] new_owner[:new_group] file(s)  
```

**Example:** Change ownership of **WebServer\_Q3\_AcmeCorp.conf** to user `ubuntu`:

```bash
chown ubuntu WebServer_Q3_AcmeCorp.conf  
ls -l WebServer_Q3_AcmeCorp.conf  
```

**Verification output:**

```bash
-rw-r--r--  1 ubuntu web  3492 Aug 20 14:05 WebServer_Q3_AcmeCorp.conf  
```

This confirms ownership has been updated. Use `sudo` if permissions are restricted.

***

## Memory, Pagefile, and Hibernation File

This lesson introduces memory, pagefiles, swapfiles, and hibernation files, all of which can provide critical evidence during digital forensic investigations.

### Memory

#### What is Memory?

Memory refers to high-speed storage used by computers to hold data for immediate use, typically random-access memory (RAM). Unlike slower storage devices, memory operates at much higher speeds but is volatile.

#### What is Memory Analysis?

Memory forensics, or memory analysis, involves examining volatile data from a memory dump. This allows investigators to identify attacks, malicious code, or activity that may not leave traces on persistent storage.

#### What is in a Memory Dump?

A memory dump (core/system dump) is a snapshot of memory at a given instant. It may contain information about running processes, network connections, and in-memory malware.

#### Why is Memory Forensics Important?

Memory forensics reveals runtime system activity such as network connections, executed commands, credentials, chat messages, encryption keys, injected code, and in-memory malware. Because many threats exist only in RAM, memory analysis is vital for uncovering sophisticated attacks that evade traditional antivirus or EDR solutions.

***

### Pagefile

#### What is Pagefile.sys?

In Windows, **Pagefile.sys** is a hidden system file that stores data from RAM when memory becomes full. It acts as virtual memory by moving infrequently used memory pages to disk, freeing space in RAM for active processes. It can also serve as a backup of data during system crashes. By default, Windows manages the file size, though users can adjust or move it to another drive.

#### Deleting Pagefile.sys

Deleting Pagefile.sys may cause system instability because Windows relies on it for memory management. It is hidden by default to prevent accidental removal.

***

### Swapfile

#### The Swap File in Linux

Linux uses swap space similarly to Windows, offloading inactive memory pages when RAM is full. Traditionally, swap exists as a partition, but it can also be configured as a swap file. Swap files allow flexible resizing, unlike partitions.

**Example command to create a swap file:**

```bash
sudo fallocate -l 2G /swapfile
```

#### Swap Space Related Commands

To view swap space usage:

```bash
free -h
```

**Example output:**

```bash
              total        used        free      shared  buff/cache   available
Mem:           15Gi       4.2Gi       7.1Gi       512Mi       3.8Gi        10Gi
Swap:         2.0Gi       256Mi       1.7Gi
```

To identify whether swap space is a file or partition:

```bash
swapon --show
```

**Example output:**

```bash
NAME      TYPE  SIZE  USED  PRIO
/swapfile file  2G    256M   -2
```

Linux also allows configuration of swap usage frequency (swappiness), which can be tuned from 0 (minimal use, suited for servers) to 100 (maximum use, suited for desktops).

***

### Hibernation File

#### What is a Hibernation File?

Windows introduced hibernation in Windows 2000 to save the system state when powered off or in sleep mode. The file **hiberfil.sys** stores the contents of memory, allowing the system to restore its previous state.

For forensic investigators, hibernation files are valuable because they contain memory data without requiring specialized tools to capture RAM directly.

***

## Hashing and Integrity

Hashing is central to digital forensics because it ensures that evidence remains unchanged and verifiable. By generating unique hash values for files or media, investigators can prove integrity and detect tampering.

### What are Hashes?

A hash is a unique fingerprint of data represented as a text string. Even small changes in a file produce a completely different hash value. For example, the string `ABC` has a different hash than `ABCD`.

Common hashing algorithms:

* **MD5:** Fast but insecure due to collisions.
* **SHA1:** More secure than MD5, but considered weak.
* **SHA256:** Widely used standard for forensic integrity today.

***

### Gathering Hashes in Windows

In PowerShell, the `Get-FileHash` cmdlet generates hashes. By default, it produces SHA256, but flags can be used to specify other algorithms.

**Example command:**

```powershell
Get-FileHash -Algorithm MD5 WebServer_Q3_AcmeCorp.conf
```

**Example output:**

```
Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
MD5             098f6bcd4621d373cade4e832627b4f6                                       C:\Users\ubuntu\Desktop\WebServer_Q3_AcmeCorp.conf
```

***

### Gathering Hashes in Linux

Linux provides direct commands for common hash algorithms.

**Example commands:**

```bash
sha256sum WebServer_Q3_AcmeCorp.conf
md5sum WebServer_Q3_AcmeCorp.conf
sha1sum WebServer_Q3_AcmeCorp.conf
```

**Example output:**

```bash
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  WebServer_Q3_AcmeCorp.conf
098f6bcd4621d373cade4e832627b4f6  WebServer_Q3_AcmeCorp.conf
a9993e364706816aba3e25717850c26c9cd0d89d  WebServer_Q3_AcmeCorp.conf
```

Hashing text strings is also possible:

```bash
echo -n "AcmeCorp123" | sha256sum
```

**Example output:**

```
6ad14ba9986e3615423dfca256d04e3f5d9b6ad5f3d3f1f2b5f8c8a7b4a1e5ef  -
```

***

### Evidence Integrity

Forensic procedures rely on hashing to validate evidence. Investigators:

1. Generate a hash of the original evidence (e.g., a hard drive).
2. Create a bit-by-bit forensic copy.
3. Hash the copy.
4. Compare the two values.

If both hashes match, the copy is proven identical to the original. Analysts then work only on the copy, ensuring the original remains intact and admissible in court.

***
