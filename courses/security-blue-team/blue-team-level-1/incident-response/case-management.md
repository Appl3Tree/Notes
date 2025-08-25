# Case Management

## What are Case Management Tools?

Case management tools are platforms used in Security Operations Centres (SOCs) to record investigations during security incident response. They support compliance and operations by documenting analyst actions, correlating case details, and enabling collaboration between team members.

Commonly used solutions include **ServiceNow**, **IBM Resilient**, **Jira Service Management**, and **TheHive**. TheHive is an open-source platform built specifically for incident response case management.

IBM Resilient provides a clear example of these tools in practice. Its interface organizes investigations into task-based workflows modeled on the PICERL incident response lifecycle: discovery and identification, enrichment and validation, then containment and remediation.

Key features include:

* **Tasks**: Analysts add notes and mark tasks complete as they progress through the investigation.
* **People**: Displays case ownership, such as assignment to user groups (e.g., Tier 1 Analysts).
* **Related Incidents**: Correlates indicators like IP addresses, email addresses, file names, URLs, and hashes across cases to reveal links and emerging threats.
* **Attachments**: Stores investigation artifacts such as logs, emails, PCAPs, or memory dumps.
* **Newsfeed**: Maintains a timeline of activity, including notes, task updates, attachments, and membership changes.

These capabilities help SOC teams document investigations consistently, ensure accountability, and meet compliance requirements.

***

## TheHive Explained

TheHive is an open-source Security Incident Response Platform (SIRP) designed to centralize the management and investigation of cybersecurity events. It provides a single platform for handling tasks, cases, observables, and alerts, making incident response more structured and efficient. The project is maintained on [GitHub](https://github.com/TheHive-Project/TheHive).

### Functionality and Features

**Case management**: Cases represent security incidents and include tasks, observables (such as IP addresses, domains, or file hashes), and related alerts. Analysts can assign tasks, set deadlines, and track case progress.

**Collaboration**: Multi-user support allows analysts to work together on cases in real time, reducing investigation and remediation timelines.

**Observable analysis**: Observables like IPs, URLs, and file hashes can be enriched using threat intelligence integrations, giving analysts better context for decision-making.

**Alert management**: Alerts ingested from intrusion detection systems, firewalls, or SIEMs can be triaged and escalated into cases. This reduces manual effort when starting investigations.

**Integration with other tools**: TheHive integrates with platforms such as [MISP](https://www.misp-project.org/), enhancing observables with external intelligence and enabling broader threat context.

**Customizable templates**: Case and task templates standardize response workflows, ensuring analysts follow required steps and document actions consistently.

**RESTful API**: TheHive exposes an API that supports automation and orchestration (SOAR). For example, it can interact with firewalls to automatically block malicious IP addresses.

***

## Using TheHive - Cases

### Looking at a Case

When opening a case in TheHive, analysts see a structured view that consolidates all details of an investigation.

* **Header information**: Title, severity, description, tags, and case owner.
* **Tasks**: Organized investigation steps, each with notes and completion status.
* **Observables**: Indicators such as `192.168.10.5`, `malicious-domain.net`, or SHA256 hashes of suspicious files. Each can be enriched with threat intelligence services.
* **Alerts**: Security tool events (e.g., IDS or SIEM alerts) linked to the case to provide context.
* **Attachments**: Uploaded evidence like system logs, PCAPs, screenshots, or email samples.
* **Timeline view**: Chronological feed of every action taken—task progress, observable analysis, or analyst comments—ensuring full accountability.

This consolidated structure ensures that all information for the investigation is auditable and easily accessible.

***

### Create a Blank Case

1. **Navigate to “New Case.”**\
   Open TheHive dashboard and click **New Case**.
2. **Enter case details.**
   * Title: `Suspicious Email Investigation`
   * Severity: _High_
   * Description: _Phishing attempt targeting finance department_
   * Tags: `phishing`, `email`
3. **Add tasks.**
   * `Review email headers`
   * `Check malicious links in sandbox`
   * `Search SIEM for related activity`
   * `Contain affected account`
4. **Add observables.**
   * Sender: `fraud@SecureMail.net`
   * Domain: `fake-invoice.net`
   * IP: `203.0.113.45`
   * File hash: `44d88612fea8a8f36de82e1278abb02f`
5. **Upload attachments.**
   * Email `.eml` file
   * Extracted malicious PDF
6. **Save the case.**\
   The case is now ready for collaborative investigation.

***

### Creating a Case Template

1. Go to **Administration > Case Templates**.
2. Click **New Template** and name it `Phishing Investigation`.
3. Define **default fields**:
   * Severity: Medium
   * Tags: `phishing`, `email`
   * Custom fields: _Target department_, _Initial reporter_
4. Add **predefined tasks**:
   * `Analyze email headers`
   * `Check attachments for malware`
   * `Correlate indicators with threat intel`
   * `Contain compromised accounts`
   * `Notify affected users`
5. Save the template.

Now, any analyst can quickly create a standardized phishing case by selecting this template.

***

### Closing Cases

1. Open the case once all tasks are complete.
2. Click **Close Case**.
3. Choose a final status:
   * **Resolved** – _Malicious phishing email contained._
   * **False Positive** – _Legitimate business email flagged incorrectly._
   * **Duplicated** – _Case overlapped with existing investigation._
4. Add final notes summarizing findings and actions taken.
5. Confirm closure.

The case is now locked for historical reference, ensuring auditability and contributing to organizational reporting metrics.

***

## Using TheHive - Dashboards

### Creating a Dashboard

Dashboards in TheHive provide a centralized view of investigations, cases, alerts, and observables, helping analysts visualize data trends and quickly search for relevant information. They allow security teams to build custom views tailored to their workflows and priorities.

***

#### Step-by-Step: Creating a Dashboard

1. **Navigate to Dashboards.**\
   From the main menu, select **Dashboards**.
2. **Create a new dashboard.**\
   Click **New Dashboard**, then provide:
   * **Title**: `SOC Daily Overview`
   * **Description**: _Tracks open cases, recent alerts, and key observables._
3. **Add widgets.**\
   Dashboards consist of widgets that display specific data. Examples include:
   * **Case Status Widget**: Bar chart showing open, in-progress, and closed cases.
   * **Alerts by Source Widget**: Pie chart displaying alerts grouped by originating security tool (e.g., IDS, firewall, SIEM).
   * **Top Observables Widget**: Table listing the most frequently seen domains, IPs, or hashes.
   * **Recent Activity Feed**: Timeline of case updates and task completions.
4. **Configure search filters.**\
   Each widget can be filtered by:
   * Severity (high, medium, low)
   * Tags (e.g., `phishing`, `malware`, `ransomware`)
   * Date range (last 7 days, last 30 days, custom)
5. **Save and apply.**\
   Once widgets are configured, save the dashboard. Analysts can return to it for real-time monitoring and searching across all cases and alerts.

***

#### Example Use Cases of Dashboards

* **SOC Triage Dashboard**: Displays all new alerts, grouped by severity, helping Tier 1 analysts prioritize work.
* **Threat Hunting Dashboard**: Highlights recurring observables and correlations between cases to spot trends.
* **Executive Dashboard**: Summarizes total incidents, case closure rates, and response times for reporting to leadership.

***

## Using TheHive - Searching

### Searching in TheHive

TheHive includes a powerful search function that allows analysts to quickly locate relevant information across cases, tasks, alerts, and observables. This helps teams correlate investigations, identify recurring threats, and avoid duplicate work.

***

#### Step-by-Step: Searching in TheHive

1. **Access the search bar.**\
   From the top navigation menu, click the **Search** option.
2. **Choose a search type.**\
   TheHive allows searching across multiple entities:
   * **Cases** – Search by title, description, tags, or severity.
   * **Tasks** – Find specific tasks, notes, or assigned users.
   * **Observables** – Query indicators such as IPs, domains, email addresses, or hashes.
   * **Alerts** – Search by alert name, source, or severity.
3. **Apply filters.**\
   Narrow down results using filters such as:
   * **Date range** – Limit searches to recent days, weeks, or months.
   * **Tags** – Match specific investigation categories like `phishing`, `malware`, or `insider-threat`.
   * **Status** – Open, in-progress, or closed cases/tasks.
4. **Run the search.**\
   Enter your keyword or value (e.g., a suspicious IP or domain) and execute the search. Results are displayed in a list, grouped by type (cases, tasks, observables).
5. **Review and pivot.**\
   Analysts can click into results to view details or pivot directly from one entity to another (e.g., from an observable to related cases or alerts).

***

#### Example Searches

* Search for the observable `203.0.113.45` to find all cases where this IP was investigated.
* Search for the tag `phishing` to display all cases tagged as phishing-related.
* Search for a task note containing `containment` to locate investigations where containment actions were documented.

***
