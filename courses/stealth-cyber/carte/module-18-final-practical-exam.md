# Module 18: Final Practical Exam

### CARTE Practical Exam Structure

| Attribute      | Detail                                       |
| -------------- | -------------------------------------------- |
| Duration       | 7 days (168 hours) from activation           |
| Targets        | 5 vulnerable AI systems, 3 flags each        |
| Total flags    | 15                                           |
| Pass threshold | 12 flags (80%) with valid evidence           |
| Deliverable    | Professional report with documented findings |

Assessment criteria: vulnerability discovery; practical technique application; systematic methodology; documentation and evidence quality; report writing; ethical conduct.

***

### Exam Rules and Academic Integrity

#### Prohibited Conduct

| Category                   | Prohibited Actions                                                                                                                                                                                                   |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Collaboration              | Discussing the exam with anyone while active; posting questions about targets in any forum, Discord, Slack, or community; working with other candidates or individuals; hiring or paying anyone for assistance       |
| Sharing exam content       | Sharing flags, solutions, or approaches; sharing screenshots of exam targets; discussing specific vulnerabilities or techniques that worked; posting writeups before explicit permission; sharing access credentials |
| Unauthorized resources     | Using solutions or writeups from prior candidates; using AI assistants to solve exam challenges; using automated tools designed to solve exam targets; using purchased exam answers                                  |
| Circumventing exam systems | Attacking exam infrastructure; accessing other candidates' environments; exploiting the exam platform; attempting to extend exam time                                                                                |
| Misrepresenting work       | Submitting work that is not entirely your own; fabricating evidence or screenshots; claiming flags not legitimately captured; manipulating timestamps or evidence                                                    |

{% hint style="danger" %}
Any violation results in immediate disqualification, forfeiture of exam fees, and permanent ban from CARTE certification. Support is available at the exam support contact but exam answers will not be provided.
{% endhint %}

#### Permitted Resources

* Course materials from all modules and your own course notes
* Public reference documentation: OWASP LLM Top 10, MITRE ATLAS
* Standard security testing tools
* Search engines for general technique research (not exam-specific queries)
* Your own scripts and tools developed independently

The governing principle: all work must be your own, using your own knowledge and skills.

***

### Exam Monitoring and Detection

#### What Is Logged

All activity within the exam environment is recorded: every interaction with exam targets, all inputs submitted to AI systems, timestamps of all actions, session patterns and behavior, and evidence submission metadata.

#### Detection Methods

| Method                    | What It Catches                                                                                |
| ------------------------- | ---------------------------------------------------------------------------------------------- |
| Behavioral analysis       | Unusual activity patterns, impossible timelines, behavior inconsistent with legitimate testing |
| Similarity detection      | Copied content across candidate submissions                                                    |
| Technical fingerprinting  | Unauthorized tool usage or anomalous access patterns                                           |
| Community monitoring      | Leaked exam content posted to public forums                                                    |
| Post-certification audits | Random audits of passed candidates after certification                                         |

#### Consequences of Violations

Detected or suspected violations result in: immediate exam termination; submission disqualification; forfeiture of exam fees; permanent ban from CARTE certification; revocation of certification if already awarded; and potential reporting to employers or the security community for serious violations.

If unusual activity in your session has a legitimate explanation, document it proactively in your report.

***

### Exam Requirements

#### Technical Requirements

* Stable internet connection for the full 7-day window
* Modern browser (Chrome, Firefox, or Edge)
* Screenshot capture tool
* Text editor for notes and payload drafting
* PDF creation capability for report submission

#### Time Commitment

Recommended active working time is 40-60 hours across the 7 days. Do not activate the exam if significant conflicts exist during the window.

#### Flag Format

Flags follow this exact format:

```
FLAG{xxxxxxxxxxxxxxxxxx}
```

Capture the flag exactly as displayed. Do not paraphrase or transcribe from memory.

#### Per-Flag Evidence Requirements

1. **Screenshot:** Clear, unedited image showing the flag with enough surrounding context to verify authenticity.
2. **Reproduction steps:** Numbered sequential steps with exact copy-paste ready payloads and any prerequisites noted.
3. **Brief explanation:** What vulnerability was exploited and how.

{% hint style="danger" %}
No screenshot means no credit. This is absolute and has no exceptions.
{% endhint %}

***

### Exam Report Requirements

#### Required Sections

| Section           | Content                                                                                                                                                                                  |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Executive Summary | Assessment overview; findings summary; overall security posture of targets                                                                                                               |
| Methodology       | Approach taken; tools and techniques used; time allocation                                                                                                                               |
| Findings          | One entry per flag: target ID, vulnerability description, technical details, reproduction steps, screenshot evidence, risk rating (Critical/High/Medium/Low), remediation recommendation |
| Conclusion        | Summary of work performed; key recommendations                                                                                                                                           |

#### Format and Submission

* Submit as PDF with all screenshots embedded and legible.
* Professional formatting, clear organization, correct grammar and spelling.
* Submit via the exam portal before the 7-day window expires.
* Late submissions are not accepted under any circumstances.
* Confirm the upload completes successfully; a confirmation will be issued.

***

### Exam Logistics

#### Starting

Click "Begin Exam" only when fully ready. The 7-day timer starts immediately and cannot be paused for any reason.

#### During the Exam

Breaks, sleep, and leaving and returning to the environment are all permitted. Progress saves automatically and access remains active for the full window.

#### Technical Issues

| Issue Type                                    | Response                                                                                                                                                                |
| --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Platform issue                                | Screenshot the problem; contact support via the exam portal immediately; continue on unaffected targets; time extensions considered for verified platform failures only |
| Personal technical issue (internet, hardware) | Not grounds for extension                                                                                                                                               |

#### Ending the Exam

The exam ends on submission or when the timer expires, whichever comes first. Submitting early closes testing access permanently. If the timer expires before submission, submit whatever is complete immediately.

***

### Results and Certification

#### Grading Weights

| Component                            | Weight |
| ------------------------------------ | ------ |
| Flags captured (with valid evidence) | 60%    |
| Report quality                       | 30%    |
| Methodology and professionalism      | 10%    |

**Minimum requirements to pass:** 12 flags (80%) with valid screenshots and reproduction steps; report meets professional standards; no integrity violations.

#### Results

Provided within 10 business days. Includes pass/fail determination, verified flag count, and brief feedback. Detailed feedback is not provided.

#### Pass Outcomes

Digital certificate; employer verification credentials; permission to use the CARTE designation; optional listing in the certified professional directory.

#### Retake Policy

| Condition        | Detail                        |
| ---------------- | ----------------------------- |
| Waiting period   | 30 days minimum before retake |
| Retake fee       | Full exam fee required        |
| Maximum attempts | 3 total                       |

***

### Exam Terms and Conditions

By activating the exam, you agree to:

* All submitted work is entirely your own, completed without assistance from any person or AI system.
* No exam content, flags, solutions, techniques, or screenshots will be shared with anyone during or after the exam.
* Comprehensive logging and monitoring of all exam activity is consented to.
* Any integrity violation results in disqualification and permanent ban.
* Exam fees are non-refundable once the exam is activated.
* The 7-day time limit is absolute; extensions are granted only for verified platform issues.
* Flags without valid screenshots and reproduction steps will not be credited.
* Ethical conduct is maintained throughout; exam infrastructure and other candidates will not be targeted.
* If certified, professional standards expected of CARTE-certified practitioners will be upheld.
* Certification may be revoked if violations are discovered after the fact.

***

### Pre-Exam Final Checklist

**Readiness:**

* [ ] All course modules (1-17) completed and quizzes passed
* [ ] Practice labs completed
* [ ] Exam rules read and understood
* [ ] 7 days available with no major conflicts

**Environment:**

* [ ] Stable internet connection confirmed
* [ ] Screenshot tool ready
* [ ] Note-taking system prepared
* [ ] Report template created
* [ ] Evidence folder structure set up

**Understanding:**

* [ ] Pass requirement: 12 flags minimum (80%)
* [ ] Screenshots are mandatory for every finding; no screenshot means no credit
* [ ] Time limit is absolute; no pausing
* [ ] Report submission process confirmed
* [ ] Consequences of integrity violations understood

{% hint style="warning" %}
Clicking "Begin Exam" starts the 7-day timer immediately. It cannot be paused. Do not activate until fully prepared.
{% endhint %}

***
