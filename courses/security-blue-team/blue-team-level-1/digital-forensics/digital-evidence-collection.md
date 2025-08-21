# Digital Evidence Collection

## Section Introduction

This section introduces proper methods for collecting digital evidence, including ACPO principles, live acquisition, and forensically sound hard drive imaging.

***

## Equipment

Proper planning and the right equipment are critical in digital forensics to prevent evidence contamination. Investigators must use tools comparable to those in forensic laboratories to ensure integrity and maintain the chain of custody.

### Forensic Laptop or Workstation

Designated forensic laptops are used for capturing evidence on-site, often running specialized Linux distributions like CAINE or DEFT, or commercial law enforcement systems.

### Electro-Static Evidence Bags with Tamper-proof Stickers

These bags protect digital components from electrostatic discharge during transport. Tamper-proof seals preserve the chain of custody by showing if evidence has been accessed.

### Labels

Labels identify hardware without needing to open it, ensuring clarity for all investigators handling the evidence.

### Photographs

Digital photos document how systems and equipment were originally found, including connected cables, devices, and screen contents, preserving the scene context.

### Grounding Bracelets

Bracelets prevent static discharge when handling sensitive components, reducing the risk of accidental damage.

### Hardware Write-Blockers

Write-blockers ensure storage devices are accessed in read-only mode, preventing tampering. They may be physical devices or software solutions.

### Blank Hard Drives

High-capacity blank drives are necessary for forensic imaging. The destination drive must be larger than the source to accommodate full bit-by-bit copies.

### Specialist Equipment

Some cases require additional tools:

* **Wireless Stronghold/Faraday Boxes** – block external signals to prevent remote wiping or tampering.
* **Specialized Write-Blockers** – support non-standard devices like cell phones or IoT hardware.
* **Phone Jammers** – block network access, similar to Faraday enclosures.
* **Dedicated Flash Drives** – preloaded with forensic software such as EnCase, FTK, CSILinux, or MacQuisition.

***

## ACPO Principles

Computer-based electronic evidence follows the same standards as all other evidence in court. The prosecution must prove the evidence is unchanged from its original seizure. Because digital systems naturally alter data during operation, strict adherence to the [ACPO Good Practice Guide](https://www.nationalcrimeagency.gov.uk/who-we-are/publications/396-acpo-good-practice-guide-for-digital-evidence/file) is required.

Where possible, investigators should acquire a full bit-by-bit image using hardware write-blockers. If accessing the original device directly is unavoidable, the examiner must be competent and able to justify their actions in court. Evidence handling must always be objective, reproducible, and transparent.

### ACPO Principle 1

No action should change data stored on a digital device that may later be relied on in court.

### ACPO Principle 2

If original data must be accessed, the examiner must be competent and able to explain their actions and their effects on the evidence.

### ACPO Principle 3

A complete record of all actions must be maintained, enabling an independent third-party expert to reproduce the process and reach the same result.

### ACPO Principle 4

The lead investigator holds overall responsibility for ensuring ACPO principles are applied consistently throughout the investigation.

***

## Chain of Custody

The Chain of Custody ensures digital evidence remains untampered and admissible in court by documenting every stage of its handling, from acquisition to presentation. It protects evidence integrity by recording who accessed it, when, how, and under what conditions. A broken chain may lead to evidence dismissal.

### Why It Is Important

Courts require a documented Chain of Custody to confirm that evidence has not been altered. Documentation tracks handlers, tools, times, and storage, safeguarding both integrity and examiner accountability.

### Following the Chain of Custody

#### Evidence Integrity Hashing

Before analysis or copying, always hash evidence. Hashes provide a unique fingerprint, enabling verification before and after handling. Use at least two algorithms, typically MD5 and SHA1, or SHA256 for stronger assurance. Example:

```bash
md5sum WebServer_Q3_AcmeCorp.conf
```

```bash
e2fc714c4727ee9395f324cd2e7f331f  WebServer_Q3_AcmeCorp.conf
```

```bash
sha256sum WebServer_Q3_AcmeCorp.conf
```

```bash
559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd  WebServer_Q3_AcmeCorp.conf
```

Hardware write-blockers should be used when connecting evidence to prevent accidental modification.

#### Taking a Forensic Copy

Forensic copies protect originals from alteration. Tools include the Linux `dd` command for bit-by-bit cloning or specialized imaging tools like EnCase and FTK that add metadata and Chain of Custody details. Example:

```bash
dd if=/dev/sdb of=/mnt/evidence/ServerBackup_AcmeCorp.img bs=4M conv=noerror,sync
```

```bash
4194304 bytes (4.2 MB, 4.0 MiB) copied, 0.012345 s, 341 MB/s
```

#### Storing Digital Evidence

* Use antistatic bags to protect against electrostatic discharge.
* Store in Faraday cages to block wireless interference.
* Keep evidence in locked containers, under authorized supervision during transport.

#### Chain of Custody Form

Each examiner must complete a form documenting:

* Description of the evidence.
* Acquisition and transfer details (who, when, where).
* Contact details of handlers.
* Access, collection, and storage methods.

This prevents gaps in tracking and ensures accountability across the investigation lifecycle.

***

## Disk Imager: FTK Imager

[FTK Imager](https://www.exterro.com/ftk-imager) is a widely used forensic tool that allows investigators to create forensically sound memory and disk images. It supports RAM capture, hard drive imaging, hash verification, and file exports while preserving evidence integrity.

### Key Features

* Capture RAM and save as `.mem` for analysis in tools like Volatility.
* Create full bit-by-bit disk images for use in Autopsy, EnCase, or FTK.
* Export files directly from disk images.
* Generate MD5 and SHA1 hashes for verification.
* Provide read-only viewing of disk contents.

### Dumping Memory

1. Open **File > Capture Memory**.
2. Select a destination folder and filename (e.g., `memdump.mem`).
3. Optionally select AD1 format (not required for practice).
4. Click **Capture Memory**.

FTK Imager produces a `.mem` file, which can later be examined using Volatility or similar tools.

### Hard Drive Imaging

In professional investigations, a suspect drive is connected to a forensic workstation through a write-blocker, then copied bit-by-bit to a blank drive. FTK Imager allows creating `.img` image files that replicate every sector of a disk.

Steps for creating a disk image:

1. **File > Create Disk Image**.
2. Select **Physical Drive**.
3. Choose the target device (e.g., USB drive).
4. Optionally enter Evidence Item Information (for chain of custody).
5. Choose an output filename (e.g., `USBImage.img`) and location.
6. Set **Image Fragment Size** to `0 MB` to keep the image as one file.
7. Click **Finish** to begin imaging.

Upon completion, FTK Imager generates and verifies MD5/SHA1 hashes to confirm forensic integrity.

### Practical Notes

* Imaging small USB drives is fast; large drives may take many hours.
* Deleted data not yet overwritten is also copied, making recovery possible.
* FTK Imager can also image folder contents for practice scenarios.

***

## Live Forensics

Live forensics involves collecting evidence from systems while they are powered on. It focuses on volatile artifacts, such as RAM contents, running processes, and active network connections, which disappear once a system is shut down.

### Why It Is Important

* **Volatile evidence** such as RAM contents, encryption keys, and cached data is lost if power is removed.
* **Modern systems** with large RAM and 64-bit operating systems store significant amounts of potentially valuable evidence in memory.
* **Encryption bypass** is possible by retrieving keys from memory.
* **Cloud evidence** can be identified and collected while the system remains connected.
* **Remote response** allows centralized security teams to investigate systems in remote offices, capturing memory snapshots and reviewing live activity without needing trained staff on-site.

Live forensics enables investigators to quickly acquire volatile data without leaving systems unnecessarily exposed, balancing the need to preserve evidence with minimizing risk of data alteration.

***

## Live Acquisition: KAPE

[KAPE (Kroll Artifact Parser and Extractor)](https://www.kroll.com/en/services/cyber-risk/investigate-and-respond/kroll-artifact-parser-extractor-kape) is a triage tool designed to quickly collect and parse forensic artifacts from live systems or disk images. It provides investigators with actionable evidence within minutes, even before full disk images are acquired.

### Key Features

* Collects forensic artifacts such as browser history, system logs, email, and deleted files.
* Supports both **targets** (data sources to acquire) and **modules** (parsers and analyzers).
* Can be deployed at scale via PowerShell for remote acquisition and centralized analysis.
* Outputs logs and organized evidence directories for easy review.

### Workflow with gkape.exe (Graphical Interface)

1. **Set Target Source** – typically a disk image, but can be the live system (e.g., `C:\`).
2. **Set Output Destination** – e.g., `Documents\KAPE Output`.
3. **Select Targets** – choose artifacts such as browser data (Chrome, Firefox, Edge).
4. **Select Modules (Optional)** – run parsing or analysis on collected artifacts.
5. **Execute** – KAPE launches a terminal, retrieves artifacts, and saves them to the output folder.

### Example Findings

* **Firefox**: cookies and form history showing visited sites and personal data entries.
* **Chrome**: browsing activity and cached session data.
* **Edge/IE**: web caches and temporary files.
* **System Logs**: Windows event logs, antivirus activity, and metadata.

### Practical Use

KAPE is highly valuable in incident response and investigations where time is critical. It allows quick retrieval of key evidence while a full forensic image is still being created, enabling investigators to generate leads immediately.

***

## Evidence Destruction

Once digital evidence has surpassed its retention period, it must be securely destroyed to prevent unauthorized recovery. Multiple techniques exist, each with different applications depending on whether media will be discarded or reused.

### Degaussing

A degausser generates a powerful magnetic field that neutralizes magnetic storage media such as tapes and hard drives. It guarantees erasure, making data permanently unrecoverable.

### File Shredding

Basic deletion is insecure, as files remain recoverable until overwritten. File shredding tools improve security by overwriting data, often using standards such as the **DoD 5220.22-M Wipe Method**:

* **Pass 1**: Write zero → verify.
* **Pass 2**: Write one → verify.
* **Pass 3**: Write random character → verify.

### Physical Shredding

Storage media such as hard drives and USBs are mechanically shredded into small fragments using industrial equipment. This destroys platters, electronics, and mechanisms, making recovery impossible.

### Hydraulic Crusher

A hydraulic press drives a metal rod through the hard drive with thousands of kilos of pressure, fracturing platters and magnetic surfaces. Variants include bending or snapping drives to irreparably damage them.

### Overwriting

For media intended to be reused, overwriting is effective. Writing zeros or patterns across the entire device eliminates recoverable data without destroying the hardware. Example using Windows **diskpart**:

```bash
diskpart
```

```bash
DISKPART> list disk
DISKPART> select disk 2
DISKPART> clean all
```

```bash
DiskPart succeeded in cleaning the disk.
```

This process writes zeros to all sectors, leaving the drive reusable but cleared of evidence.

***
