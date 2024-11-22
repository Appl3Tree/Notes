# Module 2: Fundamentals of Incident Response

## Incident Response Frameworks

### Incident Response in IT and Cybersecurity

<figure><img src="../../../.gitbook/assets/image (3).png" alt=""><figcaption><p>ITIL Frameworks for Incident Management</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1) (1).png" alt=""><figcaption><p>Information Security Management Framework</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (2) (1).png" alt=""><figcaption><p>Frameworks Hierarchy</p></figcaption></figure>

### CREST Model of Incident Management

<figure><img src="../../../.gitbook/assets/image (3) (1).png" alt=""><figcaption><p>The CREST model of Incident Management</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (4).png" alt=""><figcaption><p>ISO 27035 Incident Management Model</p></figcaption></figure>

### NIST Special Publication 800-61

<figure><img src="../../../.gitbook/assets/image (5).png" alt=""><figcaption><p>NIST Inicdent Response Lifecycle</p></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (6).png" alt=""><figcaption><p>Information Sharing Relationships</p></figcaption></figure>

### SANS Model of Incident Response

<figure><img src="../../../.gitbook/assets/image (7).png" alt=""><figcaption><p>Incident Management Model Mapping</p></figcaption></figure>

## Roles and Responsibilities of Incident Response Teams

### The SOC Role in Incident Response

Typically a SOC is organized into three teams (or levels) with various responsibilities.

#### SOC Level 1

Staffed by _Cyber Defense Analysts_ who monitor the organization 24x7. Tasked with checking logs and alerts for events which require attention, triaging those events to identify potential incidents and assigning initial priorities.

{% hint style="info" %}
The NICE work role for a Cyber Defense Analyst is: "_Uses Data collected from a variety of cyber defense tools (e.g. IDS alerts, firewalls, network traffic logs) to analyze events that occur within their environment for the purposes of mitigating threats_".
{% endhint %}

#### SOC Level 2

Staffed by _Cyber Defense Incident Responders._ Tasked with investigating event escalations (from SOC Level 1).&#x20;

{% hint style="info" %}
The NICE work role for a Cyber Defense Incident Responder is: _Investigates, analyzes, and responds to cyber incidents within the network environment or enclave._
{% endhint %}

#### SOC Level 3

Staffed by _Cyber Defense Incident Responders_ and _Cyber Defense Forensics Analysts_. Tasked with providing deeper technical incident investigation expertise and managing incidents that might require significant time or external resourcing to resolve.

{% hint style="info" %}
The NICE work role for Cyber Defense Forensics Analysts is: "_Analyzes digital evidence and investigates computer security incidents to derive useful information in support of system/network vulnerability mitigation_".
{% endhint %}

### Structure of an Incident Response Team

Most common structures of an incident response team:

* **Part-Time**. While an Incident Response Team will need to be available 24x7 to respond to incidents, it does not need to be a full time role for team members. Specific staff may be designated as _Incident Handlers_ as and when an incident occurs, and remain on call outside normal business hours. For example, a Windows System Administrator may be the business-as-usual _Incident Handler_ for routine Windows events that require investigation, while the Help Desk acts as the initial point of contact for incidents. In this case, the senior _Incident Handler_ would be appointed as the _Incident Response Team Manager_ in the event of a major incident.
* **Full-Time (SOC)**. When full-time staff are employed as _Cyber Defense Analysts_ and _Cyber Defense Incident Responders_, they typically operate as a Security Operations Center (SOC) for the organization. This is commonly observed in medium and large enterprises. The _Incident Response Team Manager_ act as the SOC Manager, and the staff serve as _Incident Handlers_.
* **Distributed**. In larger organizations, a central SOC may be supported by multiple regional teams of _Cyber Defense Incident Responders_, or multiple regional SOCs may engage with their own _Cyber Defense Analysts_ and _Cyber Defense Incident Responders_.
* **Outsource**. In addition to using its own staffing, an organization may outsource some aspects of its incident response. In particular, _Security Monitoring_ is a common third-party service offering which relieves an organization of the cost of setting up its own team of _Cyber Defense Analysts_. An organization may also retain a third party to handle major incidents through an _Incident Response_ service. Typically, with full outsourcing, a member of staff would be responsible for coordinating all internal actions in support of the _Incident Response Team Manager_.

### Responsibilities of the Incident Response Team

_NICE Cyber Defense Incident Responder Skills_

| NICE Code | Description                                                     |
| --------- | --------------------------------------------------------------- |
| S0003     | Identify, capture, contain and report malware                   |
| S0047     | Preserve evidence integrity                                     |
| S0077     | Secure network communications                                   |
| S0078     | Recognize and categorize vulnerabilities and associated attacks |
| S0079     | Protect a network against malware                               |
| S0080     | Perform damage assessments                                      |
| S0173     | Use security event correlation tools                            |
| S0365     | Design incident response for cloud service models               |

_NICE Cyber Defense Incident Responder Responsibilities_

| NICE Code | Description                                         |
| --------- | --------------------------------------------------- |
| T0041     | Technical assistance in resolving incidents         |
| T0047     | Recommend remediation actions                       |
| T0161     | Analyze log files to identify threats               |
| T0163     | Triage to determine scope, urgency and impact       |
| T0164     | Perform cyber defense trend analysis and reporting  |
| T0170     | Perform forensically-sound evidence collection      |
| T0175     | Perform real-time cyber defense incident handing    |
| T0214     | Analyze network alerts                              |
| T0233     | Track and document incidents through to closure     |
| T0246     | Develop cyber defense guidance and incident reports |
| T0262     | Employ approved defense-in-depth practices          |
| T0278     | Collect intrusion artifacts                         |
| T0279     | Liaise with law enforcement when required           |
| T0312     | Coordinate with threat intelligence analysts        |
| T0395     | Write post-incident reports                         |
| T0503     | Monitor and assess external threat sources          |
| T0510     | Coordinate incident response functions              |

### The Role of Forensics in Incident Response

Typically done by a _Cyber Defense Forensics Analyst_.&#x20;
