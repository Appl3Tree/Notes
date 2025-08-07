# Active Directory

## Introduction to Active Directory

Active Directory Domain Services (AD DS), commonly referred to as **Active Directory (AD)**, is a directory service developed by Microsoft. It is a foundational component in Windows-based environments, offering **authentication**, **authorization**, and **resource management** capabilities for businesses ranging from small networks to large enterprise infrastructures.

AD functions like the **central nervous system** of a network—it defines who can access what, enforces security policies, and ensures that users only see what they need to do their jobs.

For example:

* A **salesperson** might need access to Microsoft Office, but not advanced tools like PowerShell or Control Panel.
* A **developer** might need access to Visual Studio Code and scripting tools but not necessarily Office apps.

Without a system like AD, the network would become disorganized and vulnerable, with users having access to unnecessary or sensitive systems.

***

### Active Directory Features

#### Authentication

* AD allows users to log into the network using organization-managed accounts.
* Security features include:
  * Account lockout after failed login attempts
  * Manual account disabling or suspension

#### Authorization

* Once authenticated, users are granted access to resources based on:
  * **Permissions**
  * **Group memberships**
* These determine what files, folders, or systems a user can access, and what actions they can perform.

#### Centralized Management

* AD provides administrators with tools to:
  * Create and manage user/computer accounts
  * Assign printers and devices
  * Apply security and access policies
* Changes made in AD are reflected across the entire domain, streamlining IT management.

#### Group Policy

* Group Policy allows configuration and enforcement of settings across the domain:
  * Security policies
  * Software deployment
  * Desktop and user environment settings
* These policies ensure consistency and compliance throughout the organization.

***

## Objects and Organizational Units

An **object** in Active Directory is a digital representation of a resource within the network, such as a user, computer, group, printer, or shared folder. These objects are the building blocks of the AD environment and allow administrators to manage resources, security, and permissions.

Each object has **attributes** that describe its properties. For example:

* **User objects** can include job title, manager, contact details, and group memberships.
* **Computer objects** can include security policies, assigned permissions, and system details.

Every object is assigned:

* A **Globally Unique Identifier (GUID)**, which stays the same even if the object is renamed or moved.
* A **Distinguished Name (DN)**, which reflects its location in the AD structure and changes if the object is moved.

***

### Types of Objects in Active Directory

#### User Objects

* Represent individual users in the organization.
* Store information such as username, password, personal details, and group memberships.
* Each user account has a **Security Identifier (SID)**, which remains constant unless the account is deleted and recreated.

#### Computer Objects

* Represent computers joined to the domain.
* Used to manage security settings, permissions, and policies for devices.
* Each computer also has a unique SID assigned when it joins the domain.

#### Group Objects

* Collections of users, computers, or other groups.
* Simplify administration by assigning permissions to the group rather than individual users.
* Types of groups:
  * **Security Groups** – Used to manage permissions for resources.
  * **Distribution Groups** – Used for email distribution lists (no security permissions).

#### Organizational Units (OUs)

* Containers used to organize and manage objects in the domain.
* Can hold users, computers, groups, or even other OUs.
* Enable delegated administration and targeted application of Group Policies.
* Example: A **Finance OU** may contain only finance department users and their devices.

#### Printer Objects

* Represent network printers.
* Store configuration details and access permissions.

#### Shared Folder Objects

* Represent network file shares.
* Manage permissions for user access.

***

### Security Identifiers (SIDs)

Each object (user or computer) has a unique **SID**, made of:

* **Domain SID** – Same for all objects in the domain.
* **Relative Identifier (RID)** – Unique value for each object.

**Example:**

* Domain SID: `S-1-5-21-123456789-987654321-123456789`
* User RID: `1000` → User SID: `S-1-5-21-123456789-987654321-123456789-1000`
* Computer RID: `1001` → Computer SID: `S-1-5-21-123456789-987654321-123456789-1001`

This structure ensures all objects have unique security identifiers within the domain.

***

## Searching AD Objects

In security investigations, it's often necessary to collect detailed information about Active Directory (AD) objects—especially user accounts. This might include verifying if an account is disabled, locked, expired, or checking group memberships and descriptive attributes.

Two primary methods to search and retrieve this information are through **PowerShell** and **Lightweight Directory Access Protocol (LDAP)** tools.

***

### Using PowerShell

PowerShell provides direct access to AD object data using the `ActiveDirectory` module.

#### Basic Query

To retrieve all attributes of a user account:

```powershell
Get-ADUser -Identity "NameHere" -Properties *
```

Using `-Properties *` returns every available property for the user. Notable ones include:

* `lastLogonTimestamp` – Indicates the last time the user logged in.
* `LockedOut` – Whether the account is currently locked.
* `MemberOf` – Lists the security groups the user belongs to.
* `modifyTimeStamp` or `Modified` – Shows the last time the account was changed.

#### Targeted Query

To narrow results, specify only the attributes you want:

```powershell
Get-ADUser -Identity "NameHere" -Properties LastLogonDate,LockedOut,Modified,PasswordExpired,PasswordLastSet
```

This makes output more manageable and focused during investigations or audits.

***

### Using LDAP

**LDAP** is a widely-used protocol for querying and managing directory services, including Active Directory. While it can be accessed programmatically, it’s often used with GUI-based tools to simplify the experience.

#### GUI-Based LDAP Browsers

Tools like **Softerra LDAP Browser** allow visual exploration of the AD structure. Users can:

* Browse OUs and containers
* View and search object attributes
* Export data for reporting or analysis

In the interface, selecting a user (e.g., "Admin Ferris") reveals all related attributes such as group membership, account status, and personal details—similar to what’s available via PowerShell.

***

## Domain Controllers

A **Domain Controller (DC)** is a server that runs the **Active Directory Domain Services (AD DS)** role, responsible for managing authentication, authorization, and policy enforcement in a Windows domain.

***

### Key Functions of a Domain Controller

* **Credential Validation**\
  When a user logs in to a domain-joined system, the DC verifies their username and password against stored credentials in Active Directory.
* **Access Control**\
  After authentication, the DC determines the resources a user can access based on permissions and group memberships, enforcing security policies.
* **Directory Access**\
  DCs store and provide access to the Active Directory database, containing information on all domain objects (users, computers, groups). This can be queried locally or remotely via LDAP.
* **Group Policy Enforcement**\
  DCs apply Group Policies that define security settings, software deployments, and other configurations for users and computers.
* **Replication Across DCs**\
  In multi-DC environments, changes on one DC (e.g., account modifications) are replicated to all others to maintain consistency and redundancy.

***

### Types of Domain Controllers

* **Primary Domain Controller (PDC)**\
  Manages password changes and certain legacy operations. In modern environments, one DC is assigned the **PDC Emulator** role for backward compatibility.
* **Backup Domain Controller (BDC)**\
  Used in older Windows NT environments to maintain a read-only copy of the accounts database. Modern Windows domains replace this with multi-master replication.
* **Read-Only Domain Controller (RODC)**\
  Holds a read-only copy of the AD database, ideal for branch offices or sites with lower physical security. RODCs can authenticate users but cannot make directory changes.

***

## AD Structure Examples

### Single Domain Example

In a single-domain environment, all resources are managed under one root domain.\
Example:

* **Root Domain**: **examplecorp.local**
* **Domain Controller**: EXDC01
* **Organizational Units (OUs)**:
  * HR OU for human resources user accounts
  * Finance OU for finance department user accounts
  * IT OU for computers and technical staff accounts

This model is simple and ideal for small to medium organizations.

***

### Multi-Domain Example (Tree/Forest)

In a multi-domain setup, subdomains branch off from a root domain.\
Example:

* **Root Domain**: examplecorp.local
* **Child Domains**:
  * finance.examplecorp.local
  * engineering.examplecorp.local

Each subdomain can have its own OUs and policies. Even with one tree, the full structure is considered a **forest**.

***

### Multi-Root Domain Example (Forest)

When companies merge, separate root domains can be brought into the same forest.\
Example:

* **Root Domain 1**: examplecorp.local
* **Root Domain 2**: sampletech.local

These root domains can operate independently while sharing a **forest configuration**. Establishing **trust relationships** allows resource sharing—such as users from sampletech.local accessing shared servers in examplecorp.local.

***

## Security Groups

Security groups in Active Directory are used to manage access by assigning permissions to groups rather than individual accounts. This approach simplifies administration and enforces consistency in access control.

While **Organizational Units (OUs)** are designed for logical organization and policy application, **Security Groups (SGs)**&#x61;re focused on **permissions and resource access**.

***

### Naming Structure

Although Active Directory doesn’t enforce a standard naming scheme, most organizations use an internal convention to make each group’s purpose clear.

| Element    | Example                     | Description                                |
| ---------- | --------------------------- | ------------------------------------------ |
| Prefix     | SG-                         | Identifies it as a Security Group          |
| Department | Dev, HR, Sales              | Team or department                         |
| Permission | ReadOnly, Write, FullAccess | Access level assigned                      |
| Location   | Denver, Berlin, Sydney      | Optional—used for multi-site organizations |

**Example Names:**

* SG-Dev-FullAccess-Denver
* SG-HR-ReadOnly-Berlin
* SG-Sales-Write-Sydney

***

### Using Security Groups

**Scenario:**\
A company sets up a central file server. Access needs to be restricted so each department only has access to its own files.

**Steps:**

1. **Create Security Groups**
   * SG-Dev-FileServer
   * SG-HR-FileServer
2. **Add Relevant Users**
   * Developers are added to SG-Dev-FileServer
   * HR staff are added to SG-HR-FileServer
3. **Organize File Server Folders**
   * `D:/FileShare/Development/`
   * `D:/FileShare/HumanResources/`
4. **Assign Permissions**
   * Right-click the folder → **Properties** → **Security Tab**
   * Add the appropriate SG with the correct access rights

**Result:**

* SG-Dev-FileServer users can access only the Development folder
* SG-HR-FileServer users can access only the Human Resources folder

This ensures **least privilege** and makes future permission management easier.

***

## Group Policy

In a large environment, manually managing hundreds or thousands of computers creates inconsistency and security gaps. **Group Policy** allows centralized configuration, enforcing security settings and controlling user actions without visiting each machine.

***

### What is Group Policy?

Group Policy settings can exist locally or in **Active Directory**. In AD, these settings are grouped into **Group Policy Objects (GPOs)**.

Example: At **AcmeCorp**, the IT department wants to block USB storage for all devices in the `Workstations` OU. Instead of configuring each PC manually, a single GPO can apply the restriction across all targeted computers.

***

### Types of GPOs

#### Local GPOs

* Apply to a single computer only
* Useful for standalone systems or testing
* Example: Local password policy applied to a kiosk computer in the AcmeCorp lobby

#### Non-Local GPOs

* Stored in Active Directory and applied across multiple users or computers
* Example: Disabling USB storage for all devices in the `Operations` OU

#### Starter GPOs

* Templates with pre-configured settings for creating new GPOs quickly
* Example: Starter GPO used for pre-configured remote work security settings

***

### GPO Processing Order

1. **Local** – Computer’s own policy applies first
2. **Site** – Policies linked to the site apply next
3. **Domain** – Domain-level GPOs follow
4. **Organizational Unit (OU)** – From top-level OU down to nested OUs

If conflicts occur, the **last applied policy (closest to the object)** takes precedence.\
**Enforced GPOs** override others regardless of order.

***

### Creating a GPO

**Scenario:** Enable command-line logging for process creation on all workstations in the `AcmeCorp.local` domain.

1. **Open Group Policy Management**
   * Server Manager → Group Policy Management
   * Windows Search → "Group Policy Management"
   * `Win + R` → `gpedit.msc`
2. **Create the GPO**
   * Right-click `AcmeCorp.local` → **Create GPO**
   * Name it `GPO-CommandLineLogging`
3. **Edit the GPO**
   * Right-click the new GPO → **Edit**
   * Navigate to the logging configuration
   * Enable the setting, apply, and close the editor
4. **Link the GPO**
   * Right-click the `Workstations` OU → **Link an Existing GPO**
   * Select `GPO-CommandLineLogging`
5. **Enforce (if required)**
   * Right-click the GPO → **Enforce** (ensures it overrides conflicting policies)

**Result:** When policies refresh, all workstations in the `Workstations` OU will have command-line process logging enabled.

***

## Authentication and Security

Active Directory (AD) authentication mechanisms are critical for ensuring secure access to network resources. They validate that users are who they claim to be before granting access to services such as file servers, email systems, and intranet applications. Understanding how different authentication methods work—such as Kerberos, NTLM, and LDAP—is key to maintaining a secure and functional AD environment. Implementing strong security practices like regular auditing, applying the principle of least privilege, segregating duties, and maintaining a consistent patch management process strengthens defenses against potential threats.

***

### AD Authentication

#### Kerberos Authentication

Kerberos is a secure, ticket-based authentication system widely used in AD environments. It minimizes the need to repeatedly transmit passwords by issuing encrypted tickets that allow users to access multiple services after logging in once.

**Example:**

* Sarah logs in to her workstation, which requests a Ticket Granting Ticket (TGT) from the Key Distribution Center (KDC).
* The KDC’s Authentication Server verifies her credentials and returns the TGT.
* When Sarah accesses email, her TGT is presented to the Ticket Granting Server (TGS), which issues a Service Ticket for the email server.
* The email server validates the Service Ticket and grants access without requiring Sarah’s password again.

This approach reduces credential exposure and provides efficient access to authorized services.

***

#### NTLM (NT LAN Manager)

NTLM is an older challenge-response protocol used for authentication in Windows environments. While largely replaced by Kerberos, it may still be present for legacy compatibility.

**Example:**

* John attempts to open a shared folder.
* His username is sent to the server, which replies with a random challenge.
* John’s computer encrypts the challenge with his password hash and returns the response.
* The server validates the response and grants or denies access accordingly.

Although functional, NTLM is less secure than Kerberos due to its susceptibility to certain attacks (e.g., relay attacks).

***

#### LDAP (Lightweight Directory Access Protocol)

LDAP is a protocol for accessing and managing directory information services like AD. It authenticates users and determines their permissions to access specific resources.

**Example:**

* Maria logs into her company intranet.
* Her credentials are sent to the LDAP server in a bind request.
* The LDAP server verifies the credentials and returns a success result.
* Maria’s session is then authorized to access intranet resources based on her account permissions.

LDAP is fundamental for directory queries and authentication across many AD-integrated services.

***

### Best Practices for AD Security

#### Regular Auditing and Monitoring

* Continuously monitor AD for unauthorized access attempts, unusual logon patterns, and modifications to objects.
* Review Windows Event Logs to identify suspicious behavior early.

#### Least Privilege Principle

* Assign only the permissions necessary for a user’s job role.
* Reduces risk exposure if credentials are compromised.

#### Segregation of Duties

* Divide critical responsibilities to prevent one individual from having end-to-end control of sensitive processes.
* Example: One admin creates accounts, another manages security permissions.

#### Patch Management

* Keep AD servers and related systems updated to address known vulnerabilities.
* Apply security patches promptly to reduce exploit risks.
