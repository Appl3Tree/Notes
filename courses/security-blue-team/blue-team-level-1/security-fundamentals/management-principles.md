# Management Principles

## Section Introduction

This part of the Security Fundamentals domain introduces **core management principles** in cybersecurity, focusing on how organizations reduce risk and maintain security standards.

***

### **Key Focus Areas**

* **Risk**: What it is in a business context and how it is managed.
* **Policies & Procedures**: Their role in maintaining consistent security practices.
* **Compliance**: Ensuring security meets legal, regulatory, or industry requirements.

***

## Risk

Risk is the **potential for negative impact** to business operations, finances, or security. In cybersecurity, risk emerges when a **vulnerability** can be exploited by a **threat**. While threats cannot be controlled, vulnerabilities can be managed by applying **security controls** to reduce risk to an acceptable level. Risks can exist at any scale, from a single device to an entire department.

The **likelihood** of a risk depends on:

* Existence of a threat
* Presence of a vulnerability
* Effectiveness of current controls

***

### **Risk Assessments**

Risk assessments identify and evaluate potential risks, measuring both **likelihood** and **impact**. These help organizations make informed decisions and prioritize mitigation. In some industries, risk assessments are a **legal requirement**.

**Example**: A corporate laptop being lost

* Likelihood: Chance the loss occurs
* Impact: Equipment and data loss
* Mitigation: Encryption, tracking, or strict handling procedures

***

### **Conducting an Assessment**

Typical steps in a risk assessment:

1. Identify potential hazards
2. Identify who or what might be affected
3. Evaluate risk (severity and likelihood) and define precautions
4. Implement controls and document findings
5. Periodically review and update

Risk assessments must be **dynamic**, adjusting as threats and environments change.

***

### **Managing Risk**

Risk can be addressed in four main ways:

* **Mitigation** – Apply technical and administrative controls (patching, firewalls, policies) to reduce risk.
* **Transfer** – Shift potential loss to another party (e.g., insurance).
* **Acceptance** – Proceed with the risk if it is minimal, unavoidable, or tolerable.
* **Avoidance** – Remove the hazard entirely to prevent the risk.

***

## Policies and Procedures

Policies and procedures are **administrative security controls** that guide behavior, outline responsibilities, and establish consistent practices across an organization. They help reduce risk by clearly stating what is allowed, what is prohibited, and how specific activities must be performed.

***

### **Policies**

A **policy** is a high-level plan or directive that defines expectations and responsibilities. Policies set the framework for how an organization operates and may be enforced by law, regulation, or internal governance.

* **Purpose**:
  * Establish rules and responsibilities
  * Provide a clear reference for acceptable behavior
  * Ensure accountability
* **Best practice**:
  * Understand policies relevant to your role in detail
  * Be aware of related policies and where to find guidance

#### **Common Policy Examples**

* **Acceptable Use Policy (AUP)** – Defines permitted and prohibited activities on company networks or internet access (e.g., restrictions on personal browsing, consequences for violations).
* **Service Level Agreement (SLA)** – Outlines commitments between a service provider and customer, including performance targets and consequences for failure.
* **Bring Your Own Device (BYOD)** – Specifies rules for connecting personal devices to corporate networks.
* **Memorandum of Understanding (MOU)** – Documents a formal, non-binding agreement between parties, often preceding a contract.

***

### **Standard Operating Procedures (SOPs)**

**SOPs** are step-by-step instructions for routine tasks to ensure **consistency, efficiency, and compliance**.

* **Purpose**:
  * Standardize processes
  * Reduce errors and miscommunication
  * Meet regulatory requirements
* **Key points**:
  * May vary locally due to regulations or operational needs
  * Often created by management but designed with input from end users
  * Must be reviewed periodically and tested before full implementation

***

## Change and Patch Management

Understanding how organizations manage change and apply patches is essential in reducing security risks, ensuring accountability, and meeting compliance requirements. While these topics are beyond the scope of BTL1, they remain critical components of enterprise cybersecurity programs.

***

### **Change Management**

**Definition:**\
Change management is the structured process for introducing and documenting changes in an organization. It ensures changes are planned, authorized, and tracked.

**Key Benefits:**

* Identifies **who made a change**, when, and why
* Ensures **stakeholders are informed** before changes happen
* Helps in **root cause analysis** during incidents
* Enforces a **consistent approval process**

**Common Change Scenarios:**

* Patching systems
* Modifying firewall rules
* Deploying new security tools

***

### **Patch Management**

**Definition:**\
Patch management is the process of applying updates to software and operating systems to fix security vulnerabilities and improve stability.

**Why It Matters:**

* Reduces exposure to known vulnerabilities
* Supports **compliance** (e.g., Cyber Essentials+, PCI DSS)
* Keeps systems up to date and secure

**Patch Deployment Tools:**

#### **1. Windows Server Update Services (WSUS)**

* Centralized update server
* Downloads updates from Microsoft
* Pushes updates to endpoints without requiring direct internet access

#### **2. Microsoft System Center Configuration Manager (SCCM)**

* Paid solution with advanced patching features
* Integrates with WSUS
* Supports patch scheduling, custom rules
* Limited support for non-Windows systems

#### **3. Commercial Patch Management Tools (e.g., ManageEngine Patch Manager Plus)**

* Cross-platform support: Windows, macOS, Linux
* Patches Microsoft Office, browsers, Adobe, utilities
* Scans endpoints for missing patches
* Offers **patch testing** before deployment
* Useful for large or mixed environments

***

### **Retroactive Patch Releases**

In rare, critical situations, vendors issue patches for unsupported operating systems.\
**Example:**

* Microsoft released a patch for **Windows XP** to mitigate **BlueKeep (CVE-2019-0708)** despite it reaching end-of-life in **2014**.
* These retroactive patches highlight the **severity** of some vulnerabilities.
