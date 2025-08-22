# Disk Analysis With Autopsy

## What is Autopsy?

Autopsy is a forensic tool used by the military, law enforcement, and corporate examiners to investigate activity on computers and smartphones. It uses a plug-in architecture that supports add-on modules or custom development in Java or Python, enabling additional automation and features. Autopsy is included in Kali Linux and is also available as a free download for Windows.

***

## Autopsy’s Main Features

* **Multi-User Cases**: Supports collaboration on large investigations.
* **Keyword Search**: Extracts and indexes text for term or pattern searches.
* **Timeline Analysis**: Provides a graphical display of system events to track activity.
* **Web Artifacts**: Recovers browsing activity from common web browsers.
* **LNK File Analysis**: Identifies shortcuts and accessed documents.
* **Email Analysis**: Parses MBOX messages, including Thunderbird data.
* **Registry Analysis**: Integrates RegRipper to reveal accessed documents and USB devices.
* **EXIF Metadata**: Extracts geolocation and camera details from JPEG images.
* **File Type Sorting**: Groups content by type to quickly locate images or documents.
* **Media Playback**: Opens videos and images directly within the tool.
* **Thumbnail Viewer**: Displays image thumbnails for rapid review.
* **Robust File System Analysis**: Supports NTFS, FAT12/16/32/ExFAT, HFS+, ISO9660, Ext2/3/4, Yaffs2, and UFS via The Sleuth Kit.
* **Tags**: Mark files with custom tags (e.g., “bookmark” or “suspicious”) and attach comments.
* **Unicode Strings Extraction**: Pulls text from unallocated space and unknown file types in multiple languages.
* **File Type Detection**: Identifies content through signatures and detects extension mismatches.
* **Interesting Files Module**: Flags files or directories based on name or path.
* **Android Support**: Extracts SMS, call logs, contacts, and app data such as Tango and Words with Friends.

***

## Autopsy Walkthrough

***

### Starting a New Case – Importing a Data Source and Running Ingest Modules

Open Autopsy and select **New Case**.\
Provide a case name and choose a base directory to store case files. For example, use `AcmeCorp_AutopsyWalkthrough` saved in your Documents folder.

You may then enter optional metadata about the investigation, commonly used by law enforcement and security teams.

Next, add a **Data Source**. Select **Disk Image or VM File**, browse to the `.E01` image, and confirm.

Autopsy will then prompt you to select **Ingest Modules**. These modules automate analysis and extract useful artifacts. Choose **All Files, Directories, and Unallocated Space**, and select modules such as:

* Recent Activity
* File Type Identification
* Embedded File Extractor
* Exif Parser
* Email Parser
* Encryption Detection

(Names may vary depending on the version.)

A progress bar in the bottom-right corner shows module status. As processing continues, the left-hand navigation pane updates with discovered artifacts.

***

### Analyzing Ingest Module Results

When ingest completes, the progress bar disappears. The navigation tree will display numbers next to categories, indicating findings.

#### Partition Table and Volumes

Expand **Data Sources > AcmeCorp\_EmployeeDesktop.E01**. Three volumes appear: `vol1`, `vol2`, `vol3`.\
Clicking the image file in the tree shows partition details in the right-hand pane. For example, `vol2` may be formatted as NTFS/exFAT, beginning at sector 2048 with length 125825024. This is the primary volume containing user data.

Double-clicking `vol2` opens a read-only file structure, allowing you to browse directories as if navigating a live system.

***

#### Web History

Under **Results**, select **Web History**. This displays visited sites, timestamps, page titles, and the browser used.\
Example: access to `forum.MailOps.net/rules` via Chrome on `2013-12-18 02:35 AM GMT`.

This data helps reconstruct user browsing habits and timelines.

***

#### Recycle Bin

Navigate to **Recycle Bin** to view deleted items. The pane lists file paths, users, and deletion timestamps.\
For example, three deleted files may appear, one named `Suspicious_Image_AcmeCorp001.jpg`.

Right-click to **Export** any file for review. Autopsy enables exporting of any identified file, not just deleted items.

***

#### Installed Programs

Select **Installed Programs** to view software installed on the system. The list includes installation dates and program names such as WinRAR, GIMP, WinZIP, and Google Chrome.

***

#### Email Accounts

Expand **Accounts > Email** to view email files downloaded to the system.\
Highlight a file and export it for analysis.

You can open the file in an email client like Thunderbird or Outlook, or examine it in a text editor. Extracted metadata may include:

* Sender and recipient
* Date and time
* Subject line
* Sending server IP

This helps investigations by identifying communications or malicious emails linked to an incident.

***
