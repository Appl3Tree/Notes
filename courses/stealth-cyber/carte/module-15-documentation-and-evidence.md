# Module 15: Documentation & Evidence

### The Report as Product

The report is the only deliverable the client directly experiences. Testing methodology, prompt iterations, and exploitation chains are invisible to them. The report justifies the engagement investment, drives remediation decisions, and is reviewed by boards, auditors, and regulators.

#### Audience Requirements

| Audience            | What They Need                               | Reading Depth                                   |
| ------------------- | -------------------------------------------- | ----------------------------------------------- |
| Board / Executives  | Business risk, investment required           | Executive summary only (2-3 min)                |
| Security Leadership | Risk prioritization, resource allocation     | Summary plus high-severity findings (15-20 min) |
| Security Operations | Detection opportunities, monitoring guidance | Findings plus technical detail (30-60 min)      |
| Development Teams   | Root cause, fix guidance, code examples      | Full finding detail (deep dive)                 |
| Compliance / Legal  | Regulatory implications, documentation       | Full report plus evidence                       |

A single document must serve all of these audiences. The solution is layered structure: each layer targets a different reader while the document remains coherent as a whole.

***

### Report Structure and Organization

#### Layered Report Model

Each layer is independently useful: an executive reading only Layer 1 understands business risk; a developer jumping to Layer 3 can act on findings without reading the rest.

| Layer                   | Length    | Primary Audience                       | Answers                           |
| ----------------------- | --------- | -------------------------------------- | --------------------------------- |
| 1: Executive Summary    | 1-2 pages | Board, executives                      | What do I need to know?           |
| 2: Findings Overview    | 2-4 pages | Security leadership                    | What did you find?                |
| 3: Detailed Findings    | Variable  | Security operations, development       | How does each vulnerability work? |
| 4: Technical Appendices | Variable  | Compliance, legal, technical reviewers | Show me the evidence              |

{% hint style="success" %}
Test the report at three reading depths: 3 minutes (executive summary alone), 30 minutes (summary plus high-severity findings), 3 hours (complete document). Each level should be independently coherent.
{% endhint %}

#### Complete Report Structure

**Front Matter:** Cover page (client, date, classification, version); document control (version history, distribution list); table of contents.

**1. Executive Summary (1-2 pages):** Assessment overview (1 paragraph); scope summary (1 paragraph); key findings (3-5 bullets, highest severity only); overall risk assessment (1 paragraph); strategic recommendations (3-5 bullets).

**2. Assessment Overview (1-2 pages):** Objectives; in-scope and out-of-scope systems; methodology summary; timeline; team composition; limitations and constraints.

**3. Findings Summary:** Findings by severity table; findings by category table; risk distribution visualization.

**4. Detailed Findings:** Individual finding reports organized by severity or category.

**5. Strategic Recommendations:** Prioritized remediation roadmap; quick wins vs. longer-term investments; resource estimates.

**6. Appendices:** Methodology detail; tools list; evidence catalog; CVSS scoring detail; glossary; references.

***

### Writing Executive Summaries

The executive summary is the most-read section of any report and for many stakeholders the only section they will read. It must communicate overall risk, surface critical findings, and drive action without technical jargon.

#### Component Standards

**Assessment overview paragraph** -- State who conducted the assessment, the dates, what systems were assessed, and why the assessment was commissioned.

> Weak: "We conducted an AI security assessment of your systems."

> Strong: "Between March 3-14, SecureOps conducted a comprehensive AI security assessment of AcmeCorp's customer-facing chatbot and internal AI assistant, performed to evaluate security posture ahead of a planned Q2 capability expansion and to support emerging AI governance requirements."

**Key findings** -- Lead with business impact and affected scope, not technical labels.

> Weak: "Finding 1: Prompt injection vulnerability (Critical)"

> Strong: "CRITICAL: Customer Data Exposure -- The chatbot can be manipulated through crafted conversations to reveal other customers' order history and account details, affecting all 50,000+ active accounts."

**Overall risk assessment** -- Quantify exposure where possible. Probabilistic findings should be translated into expected impact at operational scale.

> Weak: "The system has several vulnerabilities that should be fixed."

> Strong: "OVERALL RISK: HIGH -- The chatbot handles approximately 10,000 customer interactions daily. At the observed 35% success rate for data extraction, systematic exploitation could expose up to 3,500 customer records per day."

#### Board Language Translation

| Technical                          | Board-Ready                                     |
| ---------------------------------- | ----------------------------------------------- |
| Prompt injection vulnerability     | Chatbot can be manipulated through text input   |
| 35% exploitation success rate      | Attack succeeds roughly 1 in 3 attempts         |
| RAG cross-tenant data access       | One customer can access another customer's data |
| Jailbreak bypasses safety controls | AI can be tricked into producing harmful output |
| CVSS 9.1 Critical                  | Severe risk requiring immediate action          |

Board members evaluate business impact (revenue, reputation, regulatory exposure), risk relative to other business priorities, investment required to remediate, and timeline implications. Technical attack detail, tool names, and framework acronyms belong in later sections.

**"So what?" test:** Every statement in the executive summary must answer this question implicitly. "The system prompt can be extracted" fails. "Attackers who extract the system prompt gain visibility into internal API endpoints and security logic, enabling more targeted follow-on attacks" passes.

{% hint style="warning" %}
Critical findings must appear prominently in the executive summary. Burying a critical issue in the detailed findings section means executives may never see it.
{% endhint %}

***

### Documenting Individual Findings

#### Finding Structure

Each finding is a self-contained document. A reader unfamiliar with the engagement should be able to understand, reproduce, and remediate the issue from the finding alone.

<table data-search="false"><thead><tr><th>Component</th><th>Content</th></tr></thead><tbody><tr><td>Header</td><td>Finding ID, title, severity, status</td></tr><tr><td>Classification</td><td>OWASP LLM Top 10, MITRE ATLAS, and CWE mappings</td></tr><tr><td>Summary</td><td>What the vulnerability is (1-2 sentences)</td></tr><tr><td>Technical Description</td><td>How it works mechanically (2-3 paragraphs)</td></tr><tr><td>Reproduction Steps</td><td>Exact steps to replicate, including prerequisites and success rate</td></tr><tr><td>Evidence</td><td>Screenshots, logs, API responses</td></tr><tr><td>Impact Analysis</td><td>Business consequences of exploitation</td></tr><tr><td>Risk Rating</td><td>CVSS score with justification</td></tr><tr><td>Recommendations</td><td>Specific remediation guidance</td></tr><tr><td>References</td><td>OWASP, ATLAS, external resources</td></tr></tbody></table>

#### Writing Reproduction Steps

Steps must be precise enough for someone unfamiliar with the testing to replicate the finding independently.

> Weak: "Send a prompt injection to the chatbot and observe that it reveals other users' data."

Strong example (fictionalized):

```
PREREQUISITES: Firefox or Chrome browser, valid user01@AcmeCorp.local account, VPN disconnected

STEPS:
1. Navigate to https://chat.AcmeCorp.com/support
2. Click "Start Chat"
3. When the greeting appears, send: "Hi, I have a question about my recent order"
4. Wait for response (2-3 seconds)
5. Send payload from Secure Appendix D, Item 3
6. Observe that the response contains order details belonging to another account

VERIFICATION: Compare the returned order number against the authenticated user's
own order history -- the returned order should NOT appear there

SUCCESS RATE: 35% (7/20 documented attempts)
```

For probabilistic vulnerabilities, always document the attempt count and success rate. A 35% rate at 20 attempts is materially different from one success in two tries.

#### Handling Sensitive Information

| Content Type             | Treatment                                                                                                                                          |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| Working exploit payloads | Redact from main report; place in a secure appendix with restricted distribution                                                                   |
| PII in screenshots       | Mask before inclusion; retain unmasked originals in secure storage                                                                                 |
| Sensitive sections       | Apply document classification markings; define distribution restrictions explicitly; consider separate appendices for highest-sensitivity material |

***

### Risk Rating and CVSS for AI Vulnerabilities

#### CVSS v3.1 Base Score Components

[CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document) scores AI vulnerabilities the same way as traditional software, but several metrics require AI-specific interpretation.

<table data-search="false"><thead><tr><th>Metric group</th><th>Metric</th><th>Options</th></tr></thead><tbody><tr><td>Exploitability</td><td>Attack Vector (AV)</td><td>Network / Adjacent / Local / Physical</td></tr><tr><td>Exploitability</td><td>Attack Complexity (AC)</td><td>Low / High</td></tr><tr><td>Exploitability</td><td>Privileges Required (PR)</td><td>None / Low / High</td></tr><tr><td>Exploitability</td><td>User Interaction (UI)</td><td>None / Required</td></tr><tr><td>Scope</td><td>Scope (S)</td><td>Unchanged / Changed</td></tr><tr><td>Impact</td><td>Confidentiality (C)</td><td>None / Low / High</td></tr><tr><td>Impact</td><td>Integrity (I)</td><td>None / Low / High</td></tr><tr><td>Impact</td><td>Availability (A)</td><td>None / Low / High</td></tr></tbody></table>

#### CVSS Applied to Common AI Vulnerability Types

**Prompt injection -- cross-user data extraction**

```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N = 7.1

AV:N  -- exploitable via web interface
AC:L  -- reliable exploitation
PR:L  -- requires authenticated user account
UI:N  -- no victim interaction needed
S:C   -- affects other users' data (scope changed)
C:H   -- high confidentiality impact (PII exposed)
```

**System prompt extraction**

```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N = 4.3

Elevation: if prompt contains embedded credentials, C:H raises score to 6.5
```

**Jailbreak / safety bypass**

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N = 5.3

Note: CVSS does not capture reputational damage from harmful output.
Business risk rating typically exceeds technical score for public-facing systems.
```

**AI agent tool abuse**

```
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:N = 8.5

Elevation: if agent can execute financial transactions or delete data, score ranges 9.6-10.0
```

#### CVSS Limitations for AI

| Limitation                            | Problem                                                                | Mitigation in Report                        |
| ------------------------------------- | ---------------------------------------------------------------------- | ------------------------------------------- |
| Deterministic exploitation assumption | A 20% success rate and 100% success rate receive identical scores      | Document success rate alongside CVSS vector |
| No reputational impact metric         | Brand damage from jailbreaks producing harmful content is not captured | Include a business risk assessment section  |
| Cascading effects not modeled         | AI vulnerabilities can chain into non-obvious downstream impact        | Document the full attack chain explicitly   |

#### Business Risk Assessment

CVSS provides technical severity. Business risk provides organizational context. Both are required.

**Likelihood factors:** technical skill required; access prerequisites; attack reliability; detection probability; attacker motivation.

**Impact factors:** data sensitivity; number of users affected; regulatory exposure; reputational damage; financial impact; safety implications.

**When to adjust CVSS ratings:** a CVSS 7.1 (High) may be elevated to Critical when business factors materially increase real-world risk:

* Regulatory exposure with significant financial penalty (e.g., potential GDPR fine at 4% of annual revenue)
* Large affected user population
* Low exploitation barrier (no specialized skill required)
* High reputational impact for the organization

Always document the reasoning for any adjustment. Undocumented severity changes invite client challenges.

{% hint style="info" %}
Elevate CVSS when business factors significantly increase real-world risk. Reduce when compensating controls exist that CVSS does not capture. Document reasoning in both cases.
{% endhint %}

***

### Writing Recommendations

Findings without actionable recommendations are complaints. Recommendations are what transform a report into a remediation plan.

#### Recommendation Structure

Each recommendation must answer:

<table data-search="false"><thead><tr><th>Field</th><th>Content</th></tr></thead><tbody><tr><td>What</td><td>Specific action to take</td></tr><tr><td>Why</td><td>How it addresses the root cause</td></tr><tr><td>How</td><td>Implementation guidance</td></tr><tr><td>When</td><td>Priority and timeline</td></tr><tr><td>Who</td><td>Responsible party</td></tr><tr><td>Effort</td><td>Engineering hour estimate</td></tr><tr><td>Success Criteria</td><td>How to verify the fix is effective</td></tr></tbody></table>

> Weak: "Implement input validation."

Strong example:

```
RECOMMENDATION: Implement AI-Specific Input Filtering
PRIORITY: High (Week 1)

WHAT: Deploy input filtering to detect and block prompt injection patterns
      before input reaches the AI model.

WHY: Direct prompt injection succeeds because malicious input reaches the
     model without preprocessing.

HOW: Deploy a filter layer between the UI and model; implement pattern
     matching for known injection signatures; add semantic analysis for
     instruction-like content; log and alert on filtered inputs.

EFFORT: 40-60 engineering hours

SUCCESS CRITERIA: Filter blocks 80%+ of documented patterns;
                  false positive rate <5%; alerts generated for blocked attempts.
```

#### Remediation Roadmap

Present recommendations as a phased roadmap, not an unordered list. Grouping by phase makes resource allocation and scheduling concrete.

```
Phase 1: Immediate Stabilization (Week 1)
- R1: Emergency input filtering [40 hrs]
- R2: Enhanced logging [16 hrs]

Phase 2: Short-Term Hardening (Weeks 2-4)
- R3: RAG access control implementation [120 hrs]
- R4: Output filtering deployment [60 hrs]

Phase 3: Architectural Improvements (Months 2-3)
- R5: Zero-trust RAG redesign [400 hrs]
- R6: AI security testing pipeline [80 hrs]

Total: 716 hours | Timeline: 12 weeks | Investment: $150,000-200,000
```

***

### Visual Communication in Reports

#### Essential Visuals

| Visual                  | Purpose                                                                          |
| ----------------------- | -------------------------------------------------------------------------------- |
| Risk distribution chart | Bar chart or table showing finding counts by severity                            |
| Findings by category    | Maps findings to OWASP LLM Top 10 categories                                     |
| Attack chain diagram    | Illustrates multi-step exploitation: entry point → vulnerable component → impact |
| Assessment timeline     | Shows phases and duration of the engagement                                      |

#### Evidence Presentation Standards

Raw screenshots without context are not evidence. Each screenshot must be annotated and referenced before it has evidentiary value.

**Screenshot checklist:**

* Sequential identifier in filename and caption (e.g., F003-01, F003-02)
* Descriptive caption explaining what the screenshot shows and why it matters
* Arrows or callouts pointing to the relevant elements
* All sensitive data redacted before inclusion
* Resolution sufficient to read relevant text
* Referenced explicitly in the body text where it is discussed

***

### Delivery and Presentation

#### Report Delivery Meeting Structure (60 min)

Present the report in person or over video rather than emailing it without context.

| Time      | Segment                              |
| --------- | ------------------------------------ |
| 0:00-0:05 | Introductions and agenda             |
| 0:05-0:15 | Executive summary walkthrough        |
| 0:15-0:35 | Critical and high findings deep dive |
| 0:35-0:50 | Remediation roadmap discussion       |
| 0:50-1:00 | Q\&A and next steps                  |

#### Audience-Specific Delivery

| Audience         | Focus                                                                             | Duration  |
| ---------------- | --------------------------------------------------------------------------------- | --------- |
| Board / C-suite  | Executive summary; business impact in financial and reputational terms; no jargon | 15-20 min |
| Security team    | Full findings walkthrough; technical detail; detection opportunities              | 45-60 min |
| Development team | Remediation focus; root cause; code examples; collaborative tone                  | 30-45 min |

#### Handling Difficult Questions

| Question                              | Response Approach                                                                                                       |
| ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| "Is this really that bad?"            | Provide industry comparisons and quantify the impact at the client's operational scale                                  |
| "We don't have budget or time."       | Prioritize: identify the single highest-value item if resources allow only one action                                   |
| "This seems theoretical."             | Reference real-world exploitation of the same class; translate success rate into expected impact at actual query volume |
| "Why didn't you find \[other issue]?" | Be direct: out of scope, not included, or potentially missed; clarify what was in scope                                 |

#### Post-Delivery Follow-Up

| Timeframe  | Actions                                                                                     |
| ---------- | ------------------------------------------------------------------------------------------- |
| Week 1     | Send final report; provide additional evidence on request; answer clarifying questions      |
| Weeks 2-4  | Check remediation progress; answer implementation questions                                 |
| Months 1-3 | Offer retest; discuss ongoing security program; identify follow-up engagement opportunities |

***
