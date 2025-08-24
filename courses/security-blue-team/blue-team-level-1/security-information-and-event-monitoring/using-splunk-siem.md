# Using Splunk SIEM

## Section Introduction

Covers how analysts use SIEM platforms to identify, analyze, and respond to security events.

***

## Splunk Crash Course - Navigating Splunk

Splunk provides a streamlined GUI, similar to other SIEMs, making navigation and skills transferable across platforms.

***

### Section 1 – Apps Panel

Lists installed applications available to the user. By default, the **Search & Reporting** app appears, but additional apps (such as those from BOTSv1) are also visible in this panel.

***

### Section 2 – Splunk Bar

Displayed on every page, this bar allows switching between apps, managing configurations, viewing system messages, and tracking search job progress.

***

### Section 3 – Explore Splunk Panel

Contains links to helpful resources including product tours, adding data, browsing apps, and documentation access.

***

### Section 4 – Home Dashboard

Dashboards can be set to display on the homepage, showing key information such as alert counts, attack types, and other important metrics.

***

## Splunk Crash Course - Search Queries

In this training environment we have imported a dataset called **AcmeTraining**, stored as an index (a searchable collection of logs). To search it, open the **Search & Reporting** app and run:

```bash
index="AcmeTraining" earliest=0
```

This command searches the AcmeTraining dataset starting from the earliest event. Alternatively, `index=*` can be used to query across all available indexes. Since this dataset contains hundreds of thousands of events, working with the raw results would be inefficient. That’s where focused search queries become essential.

We can combine filenames, process names, IP addresses, operators, and more to filter data. This section covers:

* Searching with Fields (Selected Fields, Interesting Fields)
* Field / Value Pairs (AND, OR, NOT operators)
* Wildcards
* Processes (Sysmon Image field)

***

### Searching With Fields

Let’s start with a basic query:

```bash
index="AcmeTraining" earliest=0
```

* `index="AcmeTraining"` — searches against our training dataset.
* `earliest=0` — includes all events from the very first log entry.

Because the dataset is large, we’ll apply **event sampling** (e.g., 1:100) so only 1 out of every 100 logs are displayed. This speeds up query refinement before switching back to full results.

On the left-hand panel, Splunk displays **Selected Fields** and **Interesting Fields**, which are properties extracted from the logs.

Examples:

* **ComputerName** shows systems such as `srv102.AcmeCorp.local`, with event counts for each.
* **host** highlights the busiest systems, e.g., `192.168.50.1`, `splunk-02.AcmeCorp.local`, or IDS sensors.
* **source** shows log origins such as Windows Security Logs, `udp:514` syslog, or Acme IDS.
* **sourcetype** indicates data format, such as `wineventlog` or `acme_firewall`.

Clicking a field value updates the search automatically. For example, selecting `acme_firewall` updates the query:

```bash
index="AcmeTraining" earliest=0 sourcetype=acme_firewall
```

From here, fields like `srcip`, `dstip`, `srcport`, and `dstport` let analysts quickly review network activity.

***

### Field / Value Pairs

Field/value queries are the simplest way to filter logs.

```bash
search src="10.25.30.50"
```

This finds logs where the source IP is `10.25.30.50`. To also include destination traffic:

```bash
search src="10.25.30.50" OR dst="10.25.30.50"
```

Scenario: Customers report slow responses on AcmeCorp’s web server (`10.25.50.5`). To investigate:

```bash
search dst="10.25.50.5"
```

This query shows all traffic directed to that server. Further filtering (e.g., by protocol) can isolate relevant logs.

***

### Wildcards

The `*` operator can match any string.

Example: Analysts suspect host `10.25.30.73` was compromised and scanning its subnet. To verify:

```bash
search src="10.25.30.73" dst="10.25.30.*"
```

Another use case is handling variations in keywords:

```bash
search pass* AND fail*
```

This could match:

* `password fail`
* `pass failure`
* `password failure`

***

### Searching For Processes

Sysmon logs (Event ID 1) include the **Image** field, which records executables that start new processes. To see where `cmd.exe` ran and what commands were issued:

```bash
index="AcmeTraining" earliest=0 Image="*\\cmd.exe" | stats values(CommandLine) by host
```

Example output:

```plaintext
host                        values(CommandLine)
----                        -------------------
workstation01.AcmeCorp.local   ["C:\Windows\System32\cmd.exe /c whoami",
                                "C:\Windows\System32\cmd.exe /c net user"]
server04.AcmeCorp.local        ["C:\Windows\System32\cmd.exe /c ipconfig /all"]
```

This helps identify suspicious command usage across systems.

***

### Additional Resources

* [Splunk Search Tutorial](https://docs.splunk.com/Documentation/Splunk/9.0.1/SearchTutorial/Startsearching)
* [Splunk Crash Course (YouTube)](https://www.youtube.com/watch?v=xtyH_6iMxwA)

***

## Splunk Crash Course - Search Commands

Search commands extend the power of queries by transforming results into something more structured and easier to analyze. In this lesson we’ll cover:

* **sort**
* **stats**
* **table**
* **uniq**
* **dedup**

***

### sort

The `sort` command arranges results based on field values. For instance, if Acme Firewall logs contain a `time` field that isn’t aligned with Splunk’s default timestamp, we can sort on that field directly.

```bash
... | sort time asc
```

This orders results so the earliest event is shown first. To reverse the order:

```bash
... | sort time desc
```

To limit the output, include a count:

```bash
... | sort limit=2 time asc
```

This displays only the first two results by `time`.

***

### stats

The `stats` command aggregates values to provide statistics. Example: counting how often an IP appears in the `srcip` field of Acme Firewall logs.

```bash
index="AcmeTraining" sourcetype=acme_firewall | stats count by srcip
```

To show the busiest IPs at the top, chain with `sort`:

```bash
index="AcmeTraining" sourcetype=acme_firewall | stats count by srcip | sort - count
```

***

### table

The `table` command allows analysts to present only the fields of interest in a clean view.

For example, if only `date`, `time`, `srcip`, `dstport`, `action`, and `msg` matter:

```bash
... | table date, time, srcip, dstport, action, msg
```

This strips away everything else and displays only the specified columns.

***

### uniq / dedup

The `uniq` command shows only unique values from a result set. For instance, to list distinct source IP addresses:

```bash
... | table srcip | uniq
```

If `uniq` doesn’t behave as expected, use `dedup`, which removes duplicates based on a field. Example: listing distinct `action`values from firewall logs:

```bash
... | table action | dedup action
```

***

## Splunk Crash Course - Creating Alerts

Alerts notify analysts when search results match defined conditions. They help detect activity such as repeated login failures or scanning from external IPs. Once triggered, alerts are triaged by SOC analysts and escalated if necessary. Senior analysts often refine or create new detection rules to improve accuracy and reduce noise.

***

### Alerting Process

The process of building alerts involves four steps.

#### 1 – Search Query

Define the activity to detect. Examples include:

* External IPs attempting SSH into servers.
* User accounts with excessive login failures.
* Use of local administrator accounts.

Each rule begins with a search query that identifies the activity.

#### 2 – Search Timing

Choose how often the query runs:

* **Real-time**: continuously runs to detect activity immediately.
* **Scheduled**: runs at defined intervals, often for baseline or behavioral detection.

#### 3 – Alert Trigger

Thresholds reduce noise by limiting when alerts fire. For example:

* Instead of alerting on every failed login, configure the rule to trigger after 6 failures per account within 5 minutes.
* This distinguishes normal mistakes from suspicious behavior.

#### 4 – Alert Action

Decide what occurs when the alert is generated:

* Send an email for high-priority events.
* Add to the list of triggered alerts for analyst triage.
* Log and index the alert to make it searchable.
* Execute custom actions via webhook, such as sending mobile notifications to SOC staff.

***

### Creating Your Own Rules

1. Run a search query.
2. Select **Save As → Alert**.
3. Provide a title and description.

**Permissions**

* _Private_: only the creator can view or edit.
* _Shared in App_: all app users can view, power users may edit.

**Alert Type**

* _Scheduled_: runs on a defined interval.
* _Real-time_: runs constantly and evaluates trigger conditions immediately.

**Trigger Actions**

* Add to alerts list.
* Log the event.
* Export to lookup files.
* Run scripts or forward results to an endpoint for analyst notification.

***

## Splunk Crash Course - Creating Dashboards

Dashboards are collections of panels that present different datasets in visual form, providing analysts with a consolidated view of activity. Security teams often display dashboards on large SOC screens to combine SIEM data with other tools like case management and endpoint detection.

Common dashboard elements include:

* Firewall traffic graphs showing denies versus allows, useful for spotting spikes.
* The number of active alerts under investigation.
* Alerts closed within the past 24 hours to measure analyst efficiency.
* Traffic flow into SIEM collectors to identify outages.
* An attack map plotting source IPs of alerts on a world map.
* Pie charts of event types over the past 24 hours.

***

### Creating Dashboards

Dashboards belong to specific Splunk Apps. For example, a dashboard created in the **Search & Reporting App** remains linked to that app. Each app can host different dashboards depending on its purpose. Dashboards can also be shared with or restricted from other users.

***

### Splunk Reports

Reports generate the data that powers dashboard panels. Any search can be saved as a report using **Save As → Report**.

Example: to track non-200 HTTP responses on a web application:

```splunk-spl
index="AcmeTraining" sourcetype=acme_web status!=200 | stats count by status
```

**Output:**

| status | count |
| ------ | ----- |
| 404    | 1542  |
| 500    | 267   |
| 302    | 105   |

**Naming convention (recommended):**

```
<group>_<object>_<description>
```

* _group_: department using it (e.g., finance, IT).
* _object_: report, dashboard, macro, etc.
* _description_: WeeklySales, FailedLogins, etc.

***

### Splunk Dashboards

To use a report in a dashboard:

1. Open the saved report.
2. Click **Add to dashboard**.
3. Configure the following:
   * **Dashboard Title**: name for the dashboard.
   * **Dashboard ID**: identifier string.
   * **Dashboard Description**: optional purpose.
   * **Dashboard Permissions**: typically _Private_ until tested.
   * **Panel Title**: name of the panel.
   * **Panel Powered By**: either an inline search or a saved report.

A dashboard can also be set as the home view by choosing it in the app’s settings.

***

### Example Panels

#### Login Failures Line Chart

```splunk-spl
index="AcmeTraining" sourcetype=wineventlog EventCode=4625 | timechart count by ComputerName
```

**Output:**

| \_time | workstation01.AcmeCorp.local | server02.AcmeCorp.local |
| ------ | ---------------------------- | ----------------------- |
| 10:00  | 3                            | 5                       |
| 10:05  | 2                            | 12                      |
| 10:10  | 1                            | 7                       |

This highlights spikes in failed logins, often a sign of brute-force attempts.

***

#### HTTP Response Codes Line Chart

```splunk-spl
index="AcmeTraining" sourcetype=acme_web | timechart count by status
```

**Output:**

| \_time | 200  | 404 | 500 |
| ------ | ---- | --- | --- |
| 10:00  | 1250 | 100 | 5   |
| 10:05  | 1375 | 220 | 15  |
| 10:10  | 1490 | 300 | 20  |

This panel helps detect spikes in website errors, which may indicate service outages or attacks.

***
