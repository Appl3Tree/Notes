# Module 13: Professional Red Teaming Methodology

### Introduction - From Techniques to Practice

AI red teaming engagements differ from traditional penetration tests in four structural ways:

| Dimension                 | Traditional Pentest                          | AI Red Team Engagement                                                  |
| ------------------------- | -------------------------------------------- | ----------------------------------------------------------------------- |
| Finding reliability       | Binary (works or doesn't)                    | Probabilistic; attacks succeed at rates requiring statistical reporting |
| Attack surface            | Discrete enumerable endpoints                | Conversational input space; infinite and exploratory                    |
| Business impact           | Often quantifiable (data loss, breach costs) | Frequently qualitative (reputational, regulatory)                       |
| Client knowledge baseline | Generally understands network/app risk       | Often limited AI threat awareness; education is part of the engagement  |

A fifth structural condition: no widely accepted standards exist for AI red teaming scope, methodology, or reporting. More latitude than traditional pentesting, less established precedent.

#### Engagement Lifecycle

Covered in this module:

1. Scoping and planning: defining boundaries and setting client expectations
2. Methodology: systematic coverage across a probabilistic attack surface
3. Documentation: evidence capture sufficient for reproducibility and defensibility
4. Reporting: findings written to drive executive action
5. Ethics and legal: authorization, liability, and disclosure considerations
6. Client communication: expectation management and relationship continuity
7. Practice development: career paths and business structure

***

### Engagement Scoping and Planning

Poor scoping produces authorization gaps, scope creep, mismatched deliverables, and findings that don't map to business risk. The scoping process has five sequential steps.

#### Step 1: Understand Business Context

Establish why the client is engaging before discussing technical scope. Required answers:

* What AI systems are in scope?
* What business functions do they support?
* Who are the users (internal, customers, public)?
* What data does the system access?
* What actions can the system take?
* Has there been a prior incident or concern driving this engagement?
* Are there regulatory or compliance requirements?
* What is the organization's risk tolerance?

#### Step 2: Identify System Architecture

Collect technical details per system component:

| Component   | Questions to Resolve                                      |
| ----------- | --------------------------------------------------------- |
| Model       | Base model identity, custom training, fine-tuning applied |
| Deployment  | Cloud provider, self-hosted, API vs direct access         |
| Integration | Connected systems and data flows                          |
| Data access | Databases, documents, and APIs reachable by the model     |
| Actions     | What the system can execute (critical for agents)         |
| Users       | Who interacts with it; authentication requirements        |
| Monitoring  | Logging coverage and alerting in place                    |

#### Step 3: Define Testing Boundaries

Produce an explicit in-scope / out-of-scope boundary document. Typical structure:

| Status       | Examples                                                                                                                                                 |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| In scope     | Customer-facing chatbot, RAG system over product docs, prompt injection, jailbreaking, system prompt extraction, cross-tenant access                     |
| Out of scope | Internal employee systems, production databases (use staging), DoS/availability testing, social engineering, physical security, third-party integrations |

#### Step 4: Establish Rules of Engagement

| Parameter           | Define                                                             |
| ------------------- | ------------------------------------------------------------------ |
| Testing window      | Permitted hours and days                                           |
| Notification        | Who is informed before testing begins                              |
| Escalation contacts | Named contacts for critical findings during testing                |
| Data handling       | How captured evidence is stored and transmitted                    |
| Evidence retention  | Retention period and destruction procedure                         |
| Environment         | Production vs staging; which systems can be actively tested        |
| Rate limits         | Request volume constraints to avoid triggering availability issues |
| Test accounts       | Provisioning process for dedicated test credentials                |

#### Step 5: Define Success Criteria

* Vulnerability types explicitly targeted
* Coverage framework: OWASP LLM Top 10, MITRE ATLAS, or custom
* Required deliverables: executive summary, technical report, remediation roadmap
* Whether retesting is included in scope

#### Statement of Work Structure

| SOW Section         | Contents                                                               |
| ------------------- | ---------------------------------------------------------------------- |
| Engagement Overview | Purpose, timeline, named team members                                  |
| Scope Definition    | In-scope and out-of-scope systems with explicit boundaries             |
| Methodology         | Testing approach, frameworks, attack categories                        |
| Rules of Engagement | Testing windows, communication protocol, escalation, data handling     |
| Deliverables        | Report format, delivery timeline, presentation, retesting terms        |
| Authorization       | Written authorization statement, liability allocation, indemnification |
| Confidentiality     | NDA reference, data handling commitments, distribution restrictions    |

{% hint style="warning" %}
Verbal scope expansions are not authorization. If a client mentions additional systems during testing ("you can also look at our other chatbot"), pause testing on those systems until the SOW is updated in writing.
{% endhint %}

#### Engagement Type Comparison

| Type                     | Scope                                 | Depth               | Duration  | Primary Deliverable                                      |
| ------------------------ | ------------------------------------- | ------------------- | --------- | -------------------------------------------------------- |
| Vulnerability Assessment | Broad, across OWASP/ATLAS categories  | Moderate            | 1-2 weeks | Prioritized vulnerability list with remediation guidance |
| Focused Penetration Test | Narrow, specific systems or scenarios | Maximum             | 1-3 weeks | Detailed exploitation paths with business impact         |
| Red Team Exercise        | Objective-based adversary simulation  | End-to-end          | 2-4 weeks | Attack narrative with timeline and detection gaps        |
| Compliance Assessment    | Mapped to regulatory requirements     | Evidence-collection | Variable  | Compliance status with gap analysis                      |
| Continuous Testing       | Evolving system coverage              | Ongoing             | Retainer  | Periodic reports and trend analysis                      |

***

### The AI Red Team Methodology

#### Six-Phase Engagement Flow

```
Phase 1: RECONNAISSANCE
         ↓
Phase 2: ENUMERATION
         ↓
Phase 3: VULNERABILITY DISCOVERY
         ↓
Phase 4: EXPLOITATION
         ↓
Phase 5: POST-EXPLOITATION
         ↓
Phase 6: REPORTING
```

#### Phase 1: Reconnaissance

Objective: characterize the target before active testing begins.

| Activity      | Techniques                                                                                                                                           |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| Passive recon | Public docs, API references, technology identification, prior security disclosures, LinkedIn for tech stack signals, GitHub for related repositories |
| Active recon  | Normal usage to establish behavioral baseline, error message analysis, response timing, feature discovery                                            |

Deliverable: notes covering system purpose, suspected technology stack, identified entry points, and initial attack surface assessment.

{% hint style="info" %}
Establish a normal-use baseline before attempting attacks. Anomalous behavior is easier to identify when you know what normal looks like, and baseline interaction produces more effective targeted payloads.
{% endhint %}

#### Phase 2: Enumeration

Objective: map the full attack surface.

| Target       | What to Enumerate                                                                                                                       |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------- |
| Model        | Base model identity, custom fine-tuning presence, knowledge cutoff (confirms version), capability set                                   |
| Context      | System prompt extraction, persona and instruction set, capability restrictions, output format constraints                               |
| Integrations | RAG document sources and retrieval behavior; agent tool inventory and permissions; API endpoints and parameters; connected data sources |
| Defenses     | Input filter detection, output filter detection, rate limiting behavior, monitoring and alerting presence                               |

Deliverable: attack surface map covering confirmed model and configuration, extracted or inferred system prompts, available tools and integrations, and identified defensive controls.

#### Phase 3: Vulnerability Discovery

Objective: systematically identify candidate vulnerabilities before confirming them.

Work through [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/):

| ID    | Category                         | Primary Test Focus                        |
| ----- | -------------------------------- | ----------------------------------------- |
| LLM01 | Prompt Injection                 | Direct and indirect injection paths       |
| LLM02 | Insecure Output Handling         | XSS, SQL injection via model output       |
| LLM03 | Training Data Poisoning          | Bias probing, backdoor detection          |
| LLM04 | Model DoS                        | Long inputs, recursive or looping prompts |
| LLM05 | Supply Chain                     | Plugin security, dependency integrity     |
| LLM06 | Sensitive Information Disclosure | PII extraction, system prompt leakage     |
| LLM07 | Insecure Plugin Design           | Input validation, permission scope        |
| LLM08 | Excessive Agency                 | Unauthorized action chains                |
| LLM09 | Overreliance                     | Confident misinformation generation       |
| LLM10 | Model Theft                      | Query-based extraction feasibility        |

Also map findings to [MITRE ATLAS](https://atlas.mitre.org/) tactics, and based on business context test for compliance violations, brand risk, competitive intelligence leakage, and client-specific threat scenarios.

Deliverable: vulnerability log with potential finding, initial evidence, severity estimate, and exploitation priority.

#### Phase 4: Exploitation

Objective: confirm vulnerabilities and demonstrate concrete business impact.

**Exploitation protocol (per finding):**

1. Develop proof-of-concept payload
2. Run the exploit a minimum of 10 times to establish reliability
3. Calculate success rate
4. Document exact reproduction steps
5. Capture evidence: screenshots, logs, API responses
6. Assess business impact of successful execution
7. Explore payload variations

**Success rate tracking:**

```python
attempts = [
    {"timestamp": "2024-01-15T10:30:00", "payload": "...", "success": True},
    {"timestamp": "2024-01-15T10:31:00", "payload": "...", "success": False},
]

success_count = sum(1 for a in attempts if a["success"])
total_attempts = len(attempts)
success_rate = success_count / total_attempts

print(f"Success Rate: {success_rate:.1%} ({success_count}/{total_attempts})")
# Example output: "Success Rate: 40.0% (4/10)"
```

For each confirmed finding, extend the demonstration beyond technical confirmation to show what an attacker achieves: extracted system prompts should be accompanied by analysis of the operational advantage gained; jailbreaks should show the actual harmful content producible; injections should show the downstream action taken.

{% hint style="warning" %}
Never exploit in a way that affects real users or live data. Use staging environments. If you discover a vulnerability that shows signs of active exploitation, escalate immediately per the rules of engagement.
{% endhint %}

#### Phase 5: Post-Exploitation

Objective: determine the full impact radius of each confirmed exploit.

| Vulnerability Class | Post-Exploitation Questions                                                                                                                                                     |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Prompt injection    | Can you pivot to other functionality? Access other users' data? Persist the injection across sessions? Chain with other vulnerabilities?                                        |
| Agent exploitation  | What is the full tool access scope? Can you escalate to more privileged tools? Can you affect other users through agent actions? What is the blast radius of full compromise?   |
| Data extraction     | What data categories are reachable? Can you enumerate other users or tenants? Is sensitive data present in training or retrieval context? What is the total exposure potential? |

Deliverable: per-vulnerability impact assessment covering maximum demonstrated impact, theoretical maximum impact, attack chain opportunities, and affected users, data, and systems.

***

### Documentation and Evidence Collection

Undocumented findings cannot be reproduced, cannot be defended if disputed, and cannot be used as a retesting baseline. Document in real time, not from memory after the session.

#### Session Logging Fields

Each interaction with the target requires:

| Field      | Content                                     |
| ---------- | ------------------------------------------- |
| Session ID | Unique identifier for the testing session   |
| Timestamp  | Date and time of the interaction            |
| Tester     | Name of the person conducting the test      |
| Target URL | Exact endpoint tested                       |
| Objective  | What this session was attempting to confirm |
| Input      | Exact payload or prompt submitted           |
| Output     | Exact response received                     |
| Result     | Success or failure                          |
| Notes      | Observations about behavior                 |

#### Evidence Capture Requirements

For confirmed exploitation:

* Full request and response content
* Screenshots showing the vulnerability in context
* Timestamps for all actions
* Network captures where relevant
* Video recording for multi-step or complex exploits

For multi-step attack chains: document each step in sequence, prerequisites per step, success or failure at each stage, and alternative paths attempted.

#### File Naming and Organization

**Screenshot naming convention:** `[EngagementID]-[FindingID]-[Sequence]-[Description].png`

Example sequence for a single finding:

```
ENG-2024-001-F003-01-initial-prompt.png
ENG-2024-001-F003-02-injection-attempt.png
ENG-2024-001-F003-03-successful-extraction.png
```

**Folder structure:**

```
engagement-root/
├── scope/          # SOW, authorization, pre-engagement notes
├── reconnaissance/ # Documentation review, architecture notes
├── testing/        # Session logs, raw captures
├── findings/       # Subdirectory per finding ID; evidence and analysis
├── reports/        # Drafts and final deliverables
└── communication/  # Client correspondence
```

#### Sensitive Data Handling

Testing against live systems may surface credentials, PII, or confidential documents. Required handling:

| Principle             | Application                                                                                                    |
| --------------------- | -------------------------------------------------------------------------------------------------------------- |
| Minimize capture      | Record enough to prove the vulnerability; do not extract beyond that                                           |
| Redact where possible | Mask personal identifiers in screenshots before storing or sharing                                             |
| Secure storage        | Encrypt all testing artifacts at rest; use secure transfer for client delivery                                 |
| Describe, don't dump  | Reports describe what could be accessed and show representative examples; never include complete data extracts |
| Retention enforcement | Delete artifacts per the retention policy defined in the SOW                                                   |

***

### Writing Professional Reports

#### Report Audiences

| Audience           | Required Content                                                       |
| ------------------ | ---------------------------------------------------------------------- |
| Executives         | Business impact, overall risk level, remediation investment estimate   |
| Security teams     | Technical details, exact reproduction steps, defensive recommendations |
| Development teams  | Root cause analysis, actionable remediation guidance, testing support  |
| Compliance / Legal | Regulatory implications, audit documentation                           |

#### Report Structure

| Section             | Length      | Contents                                                                                                                      |
| ------------------- | ----------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Executive Summary   | 1-2 pages   | Engagement purpose, highest-severity findings, overall risk assessment, critical recommendations, remediation effort estimate |
| Engagement Overview | 1-2 pages   | Scope definition, methodology summary, testing timeline, team composition, limitations and constraints                        |
| Findings Summary    | Table       | Finding ID, title, severity, status, ATLAS/OWASP mapping for all findings                                                     |
| Detailed Findings   | Per finding | See fields below                                                                                                              |
| Remediation Roadmap | Prioritized | Immediate (critical/high), short-term (medium), long-term (strategic hardening), resource estimates per phase                 |
| Appendices          | As needed   | Methodology detail, tool list, full evidence catalog, AI security glossary                                                    |

**Required fields per detailed finding:**

* Finding ID and title
* Severity rating
* ATLAS and OWASP mapping
* Summary
* Technical details
* Reproduction steps (exact, numbered)
* Success rate with attempt count
* Evidence (screenshots, transcripts)
* Business impact (specific and quantified)
* Remediation (actionable steps)
* References to applicable standards

#### Severity Scale

| Rating        | Criteria                                                                                         |
| ------------- | ------------------------------------------------------------------------------------------------ |
| Critical      | Immediate exploitation likely; severe business impact; data breach or system compromise possible |
| High          | Readily exploitable; significant business impact; requires prompt remediation                    |
| Medium        | Exploitable with effort; moderate business impact; should be addressed in normal cycle           |
| Low           | Limited exploitability or impact; address when convenient                                        |
| Informational | Best practice improvement; no immediate security risk                                            |

Calibrate severity consistently across findings. A medium finding in one section must be comparable to mediums elsewhere in the same report.

#### Writing Quality Standards

**Impact articulation:** connect findings to concrete business consequences.

| Quality | Example                                                                                                                                                                                                                                                  |
| ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Weak    | "The system prompt can be extracted."                                                                                                                                                                                                                    |
| Strong  | "The system prompt can be extracted, revealing a direct SQL connection to the customer database. This allows attackers to craft targeted injection attempts against that connection, potentially exposing PII for approximately 50,000 active accounts." |

**Success rate reporting:** quantify probabilistic findings.

| Quality | Example                                                                                                                                                                                      |
| ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Weak    | "The jailbreak sometimes works."                                                                                                                                                             |
| Strong  | "The jailbreak succeeded in 7 of 20 attempts (35%; 95% CI: 15%-59%). At approximately 10,000 daily production queries, this represents roughly 3,500 potential successful exploits per day." |

#### Common Mistakes

| Mistake                       | Impact                                              | Correction                                                                           |
| ----------------------------- | --------------------------------------------------- | ------------------------------------------------------------------------------------ |
| No business context           | Technical findings are deprioritized or ignored     | Every finding connects to a specific business risk                                   |
| Incomplete reproduction steps | Client cannot reproduce, fix, or verify remediation | Steps are exact, numbered, and tested by a second reviewer                           |
| Unannotated screenshots       | Evidence is ambiguous without context               | All screenshots include annotations, captions, and narrative placement               |
| Vague recommendations         | Remediation stalls without specific guidance        | Specify the control, the implementation approach, and the patterns to block          |
| Inconsistent severity ratings | Stakeholders lose trust in the rating system        | Apply the severity scale definitions uniformly across all findings before finalizing |

{% file src="../../../.gitbook/assets/AI_RedTeam_Report_Template.pdf" %}
Report Template Generated by AI with the above recommendations enforced
{% endfile %}

***

### Ethics, Legal Considerations, and Responsible Disclosure

#### Ethical Principles

AI red teaming occupies a more ambiguous ethical space than traditional security testing because AI systems can generate harmful content, affect real people's lives, and behave unpredictably. Ethical obligations go beyond legal compliance.

| Principle               | Requirement                                                                                                                                             |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Minimize Harm           | Use staging environments; stop testing if unintended impact occurs; escalate actively exploited vulnerabilities immediately                             |
| Respect Privacy         | Extract only what is needed to confirm a finding; protect any personal data encountered; avoid systems with real user data unless explicitly authorized |
| Proportionality         | Match technique destructiveness to risk being assessed; consider blast radius before acting                                                             |
| Transparency            | Report findings accurately; do not exaggerate severity or omit findings that reflect poorly on the assessment                                           |
| Professional Boundaries | Stay within agreed scope; do not use access gained through testing for any unauthorized purpose                                                         |

#### Legal Frameworks

| Framework                                 | Jurisdiction | Key Implication for AI Testing                                                                                                         |
| ----------------------------------------- | ------------ | -------------------------------------------------------------------------------------------------------------------------------------- |
| Computer Fraud and Abuse Act (CFAA)       | US           | Written authorization is required; "exceeding authorized access" creates liability; AI-specific applications are still being litigated |
| General Data Protection Regulation (GDPR) | EU           | Personal data encountered during testing is still regulated; document all data handling                                                |
| EU AI Act                                 | EU           | Creates security obligations for AI systems; sector-specific rules (healthcare, finance) may add requirements                          |
| Contract / Statement of Work              | All          | Exceeding scope creates liability; document everything                                                                                 |

{% hint style="info" %}
AI security law is evolving rapidly. This is general orientation, not legal advice. For any significant engagement, involve legal counsel with experience in computer security law across the relevant jurisdictions.
{% endhint %}

#### Authorization Requirements

Written authorization must be signed by someone with actual authority to authorize testing and must include:

* Explicit identification of in-scope systems (URLs, IPs, APIs)
* Explicit identification of out-of-scope systems
* Permitted testing methodologies
* Testing window dates and times
* Emergency contact information
* Data handling requirements
* Liability, indemnification, and confidentiality terms

Retain a signed copy before any testing begins.

#### Responsible Disclosure (Unauthorized Discovery)

When a vulnerability is found outside an authorized engagement:

1. Capture enough evidence to confirm the issue without exploiting further than necessary.
2. Contact the organization's security team via published channels (security contact page, bug bounty program).
3. Allow 90 days for remediation; extend for complex fixes, compress for actively exploited issues.
4. Coordinate public disclosure timing with the organization; include actionable guidance for users.

**AI-specific factors:** Fixing AI vulnerabilities may require model retraining, taking months rather than days. Some categories (such as jailbreaks) may have no complete fix. Before disclosing publicly, weigh whether the disclosure provides more value to attackers than to defenders.

#### Difficult Scenarios

| Scenario                                             | Response                                                                                                                                           |
| ---------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| System is actively being exploited during assessment | Escalate immediately per rules of engagement; shift to incident response mode; document discovery carefully                                        |
| Vulnerability is too dangerous to fully demonstrate  | Document the attack chain up to the point of harm; provide evidence without triggering the impact; explain the risk clearly                        |
| Client pressures tester to minimize findings         | Refuse to alter findings for non-technical reasons; context and mitigating factors may be added, but the technical assessment must remain accurate |

***

### Client Communication and Stakeholder Management

#### Scoping Calls

Scoping calls establish realistic expectations before testing begins. Listen more than you speak; the goal is to understand what the client is actually worried about, not to sell.

Questions that surface real concerns:

* What prompted the request for AI security testing?
* What keeps you up at night about your AI systems?
* Have there been any prior incidents or near-misses?
* What does a successful engagement look like to you?
* Who are the stakeholders, and what is driving the timeline?

Set expectations explicitly: testing is a point-in-time snapshot, not continuous monitoring; AI vulnerabilities are probabilistic, not deterministic; and some issues found during testing may not be fully fixable.

#### During-Engagement Communication

**Status updates** for longer engagements should be sent weekly and include: work completed, work in progress, remaining tasks, preliminary high-level finding descriptions (no exploitation detail until the report), blockers, next steps, and open questions for the client.

**Escalation triggers** requiring immediate contact rather than waiting for a scheduled update:

| Trigger                                             | Reason                                         |
| --------------------------------------------------- | ---------------------------------------------- |
| Critical finding with active exploitation potential | Client needs time to begin response planning   |
| Evidence of existing compromise                     | Shifts engagement posture to incident response |
| Issue affecting user safety                         | Legal and ethical obligation                   |
| Scope boundary ambiguity                            | Unauthorized testing creates liability         |

#### Delivering Negative Findings

Never deliver a critical finding for the first time in the final report. Escalate significant issues as soon as they are confirmed.

Escalation conversation structure:

> "During testing this week, we found a vulnerability I wanted to flag before the report. We confirmed that \[brief description]. This is a \[severity] issue because \[impact]. It is fixable, and I will include detailed remediation guidance in the report. I wanted to give you advance notice so you can begin thinking about remediation planning. Would you like me to brief anyone else on your team?"

Frame findings as improvement opportunities. Provide context on how common the issue type is. Bring proposed solutions alongside the problem.

#### Readout Presentations

Tailor depth to audience:

| Audience         | What They Need                                   |
| ---------------- | ------------------------------------------------ |
| Executives       | Business impact, remediation investment required |
| Security team    | Technical reproduction steps, detection guidance |
| Development team | Root cause, fix complexity, testing support      |

Suggested time allocation: engagement overview (2 min), findings summary (5 min), critical findings deep dive (15 min), remediation roadmap (5 min), Q\&A (open).

**Handling common pushback:**

| Objection                            | Response                                                                                                            |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------- |
| "That's not exploitable in practice" | Walk through the concrete attack scenario step by step                                                              |
| "We're already planning to fix that" | Acknowledge and note it as a known issue with planned remediation                                                   |
| "That's a feature, not a bug"        | Clarify the security implication; if the client accepts the risk knowingly, document the risk acceptance in writing |
| "Your testing was too aggressive"    | Reference the SOW; if testing was in scope, explain why; if scope was exceeded, acknowledge it                      |

***

### Client Communication and Stakeholder Management

#### Scoping Calls

Scoping calls establish realistic expectations before testing begins. Listen more than you speak; the goal is to understand what the client is actually worried about, not to sell.

Questions that surface real concerns:

* What prompted the request for AI security testing?
* What keeps you up at night about your AI systems?
* Have there been any prior incidents or near-misses?
* What does a successful engagement look like to you?
* Who are the stakeholders, and what is driving the timeline?

Set expectations explicitly: testing is a point-in-time snapshot, not continuous monitoring; AI vulnerabilities are probabilistic, not deterministic; and some issues found during testing may not be fully fixable.

#### During-Engagement Communication

**Status updates** for longer engagements should be sent weekly and include: work completed, work in progress, remaining tasks, preliminary high-level finding descriptions (no exploitation detail until the report), blockers, next steps, and open questions for the client.

**Escalation triggers** requiring immediate contact rather than waiting for a scheduled update:

| Trigger                                             | Reason                                         |
| --------------------------------------------------- | ---------------------------------------------- |
| Critical finding with active exploitation potential | Client needs time to begin response planning   |
| Evidence of existing compromise                     | Shifts engagement posture to incident response |
| Issue affecting user safety                         | Legal and ethical obligation                   |
| Scope boundary ambiguity                            | Unauthorized testing creates liability         |

#### Delivering Negative Findings

Never deliver a critical finding for the first time in the final report. Escalate significant issues as soon as they are confirmed.

Escalation conversation structure:

> "During testing this week, we found a vulnerability I wanted to flag before the report. We confirmed that \[brief description]. This is a \[severity] issue because \[impact]. It is fixable, and I will include detailed remediation guidance in the report. I wanted to give you advance notice so you can begin thinking about remediation planning. Would you like me to brief anyone else on your team?"

Frame findings as improvement opportunities. Provide context on how common the issue type is. Bring proposed solutions alongside the problem.

#### Readout Presentations

Tailor depth to audience:

| Audience         | What They Need                                   |
| ---------------- | ------------------------------------------------ |
| Executives       | Business impact, remediation investment required |
| Security team    | Technical reproduction steps, detection guidance |
| Development team | Root cause, fix complexity, testing support      |

Suggested time allocation: engagement overview (2 min), findings summary (5 min), critical findings deep dive (15 min), remediation roadmap (5 min), Q\&A (open).

**Handling common pushback:**

| Objection                            | Response                                                                                                            |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------- |
| "That's not exploitable in practice" | Walk through the concrete attack scenario step by step                                                              |
| "We're already planning to fix that" | Acknowledge and note it as a known issue with planned remediation                                                   |
| "That's a feature, not a bug"        | Clarify the security implication; if the client accepts the risk knowingly, document the risk acceptance in writing |
| "Your testing was too aggressive"    | Reference the SOW; if testing was in scope, explain why; if scope was exceeded, acknowledge it                      |

***

### Building an AI Red Team Practice

#### Career Paths

| Track                   | Characteristics                                                                                 |
| ----------------------- | ----------------------------------------------------------------------------------------------- |
| Corporate security team | Continuous assessment of internal AI systems; deep system-specific knowledge; stable employment |
| Consulting              | Varied client exposure; premium billing; requires business development                          |
| Product security        | Embedded with an AI product company; influences product direction; focused scope                |
| Research                | Academic or industry lab; publish findings; less applied                                        |

#### Staying Current

AI security moves fast. Useful inputs by category:

* **Technical:** arXiv preprints, conference proceedings (IEEE S\&P, USENIX, CCS); CTF challenges; hands-on experimentation with new model releases
* **Frameworks and standards:** [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/), [MITRE ATLAS](https://atlas.mitre.org/) updates; regulatory developments; relevant certifications
* **Soft skills:** Technical writing, client management, project management, business development

#### Building Reputation

Reputation compounds through demonstrated work, not credentials alone.

* Responsible disclosure: find real issues, write them up (with permission), build relationships with vendor security teams
* Knowledge sharing: blog posts, conference talks, open-source tooling, mentoring
* Community presence: AI security forums, working groups, standards bodies

#### Consulting Fundamentals

| Topic          | Notes                                                                                                                  |
| -------------- | ---------------------------------------------------------------------------------------------------------------------- |
| Day rate       | $1,500 to $5,000+ depending on expertise and market                                                                    |
| Fixed project  | Scope estimate plus margin; define deliverables explicitly                                                             |
| Retainer       | Monthly fee for ongoing availability                                                                                   |
| Scope creep    | Build change control into contracts; unauthorized extras are refused, not absorbed                                     |
| Infrastructure | Testing environments, documentation and reporting tools, secure client communication, professional liability insurance |

{% hint style="info" %}
Pro-bono or reduced-rate work for nonprofits or early-stage startups builds both experience and references before a full commercial practice is established.
{% endhint %}

***
