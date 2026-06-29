# Module 17: Exam Preparation

### CARTE Practical Exam Overview

#### Exam Structure

| Attribute      | Detail                                             |
| -------------- | -------------------------------------------------- |
| Duration       | 7 days from activation                             |
| Format         | Practical lab environment with multiple AI targets |
| Pass threshold | Minimum 80% of flags captured                      |
| Deliverables   | Flags captured + professional report               |

#### Assessment Criteria

| Criterion          | Requirement                                    |
| ------------------ | ---------------------------------------------- |
| Flags              | Quantity and difficulty weighting              |
| Report quality     | Professional standard matching course guidance |
| Reproduction steps | Must be verifiable by examiner                 |
| Evidence           | Screenshots mandatory for every finding        |
| Conduct            | Ethical behavior throughout the exam window    |

***

### CARTE Exam Preparation

#### Knowledge Prerequisites

| Area                  | What to Know                                                                                                                |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Core concepts         | AI vs. traditional security fundamentals; why prompt injection exists; OWASP LLM Top 10; MITRE ATLAS tactics and techniques |
| Attack techniques     | Multiple approaches per vulnerability class; when to use each; how to adapt when initial attempts fail                      |
| System understanding  | How different AI architectures work; what attack surface each presents; how to identify system type through interaction     |
| Professional practice | Structured assessment methodology; documentation standards; report writing                                                  |

#### Skills to Build Before Starting

* Practice against intentionally vulnerable AI systems until enumeration feels systematic, not exploratory.
* Develop a documentation workflow that runs in parallel with testing, not after.
* Write at least one complete practice report before the exam window opens.

#### Environment Checklist

Verify everything before activating the exam. Technical problems during the exam consume time and create unnecessary pressure.

* Reliable internet connection
* Note-taking system you are already comfortable with
* Screenshot and evidence capture tools confirmed working
* Text editor set up for payload drafting and session notes
* Folder structure created for evidence organization by target
* Report template prepared and ready to populate
* Exam environment access confirmed

{% hint style="success" %}
Set up your folder structure and report template before day one. The exam tests finding and documenting vulnerabilities, not building infrastructure under pressure.
{% endhint %}

***

### Time Management

#### Allocation Guidelines

| Activity                        | Approximate Share |
| ------------------------------- | ----------------- |
| Reconnaissance and orientation  | 10-15%            |
| Active testing and exploitation | 50-60%            |
| Verification and gap analysis   | 10-15%            |
| Report writing                  | 15-20%            |

These are guidelines, not rules. Adapt based on progress and individual strengths. The report allocation is a floor, not a ceiling.

#### Daily Rhythm

Each effective day includes focused testing sessions (not marathon sessions), regular breaks, end-of-day documentation and next-day planning, and adequate sleep.

**Off-track warning signs:**

| Signal                                                   | Implication                                           |
| -------------------------------------------------------- | ----------------------------------------------------- |
| Day 3 with minimal findings                              | Methodology or approach needs adjustment              |
| No documentation of confirmed findings                   | Evidence will be incomplete or missing at report time |
| Day 5 with no report started                             | Reporting time is being consumed by testing time      |
| Repeatedly attempting the same technique without results | Time to change approach or move to another target     |

#### When to Move On

Getting stuck is normal. The decision tree when blocked:

1. Try a materially different approach on the same target (not a minor variation of what already failed).
2. Move to a different target and return later with fresh perspective.
3. Take a short break; fatigue degrades both creativity and judgment.
4. Accept that some targets carry harder flags and redirect effort to higher-yield areas.

***

### Exam Documentation Requirements

#### Per-Finding Evidence Checklist

| Required Element            | Standard                                                                   |
| --------------------------- | -------------------------------------------------------------------------- |
| Screenshot showing the flag | Mandatory; no screenshot means no credit regardless of written description |
| Exact payload or input      | Copy-paste ready; include special formatting and any encoding used         |
| Numbered reproduction steps | Sequential, specific, with expected results noted at each step             |
| Context screenshots         | Additional captures showing key intermediate steps                         |
| Success rate                | Required for probabilistic findings; include attempt count                 |
| Prerequisites               | Any setup or prior state required to reach the finding                     |

#### Screenshot Standards

* Must clearly show the flag text with enough surrounding context to verify authenticity.
* Must be legible; not blurry or cropped too tightly.
* Named systematically before filing (e.g., Target1-Flag1.png).
* Captured immediately upon discovery; do not rely on recreating the state later.
* Verify readability before moving on.
* Back up regularly throughout the exam window.

#### Reproduction Step Standards

Examiners follow steps exactly. Steps must produce the finding independently.

| Acceptable                                          | Insufficient                                  |
| --------------------------------------------------- | --------------------------------------------- |
| Numbered, sequential steps with exact URLs and text | "Use prompt injection to get the flag"        |
| Expected result stated after each key step          | "I tried various approaches until one worked" |
| Variability noted where it exists                   | General descriptions without specifics        |
| All intermediate steps included                     | Steps that skip setup or context              |

{% hint style="danger" %}
No screenshot means no credit. Perfect reproduction steps do not compensate for missing visual evidence. Capture screenshots immediately upon discovery.
{% endhint %}

{% hint style="warning" %}
The most common failure mode is finding enough flags but being unable to prove it. Document findings as they occur, not at the end of the exam window.
{% endhint %}

***

### Exam Report Expectations

#### Required Sections

| Section             | Content                                                                                                             |
| ------------------- | ------------------------------------------------------------------------------------------------------------------- |
| Executive Summary   | High-level assessment overview; summary of findings; overall security posture assessment                            |
| Methodology         | Approach taken; techniques and tools used; limitations or constraints encountered                                   |
| Findings            | Each vulnerability with technical description, exact reproduction steps, evidence, risk rating, and recommendations |
| Supporting Material | Full payloads if lengthy; additional evidence as needed                                                             |

#### Quality Standards

**What raises your score:** clear, organized structure; proper grammar and formatting; technical accuracy; actionable and specific recommendations; appropriate risk ratings.

**What hurts your score:** disorganized presentation; missing required sections; incomplete findings; absent reproduction steps; unprofessional tone or formatting.

#### Flag Count vs. Report Quality

Both are scored. A candidate with 12 flags and a poor report may score lower than one with 10 flags and an excellent report. In the final hours, do not sacrifice report quality chasing marginal additional flags.

***

### Common Exam Pitfalls

<table data-search="false"><thead><tr><th>Pitfall</th><th>Description</th><th>Prevention</th></tr></thead><tbody><tr><td>Poor time management</td><td>Spending too long on one area; leaving too little time for other targets or the report</td><td>Set per-target time limits; track daily progress; move on when stuck</td></tr><tr><td>Inadequate documentation</td><td>Finding issues but lacking enough evidence to prove or reproduce them</td><td>Document in real time; capture screenshots immediately; verify reproduction steps work before moving on</td></tr><tr><td>Tunnel vision</td><td>Fixating on one approach that is not producing results</td><td>Rotate techniques; change targets; take breaks to reset perspective</td></tr><tr><td>Skipping reconnaissance</td><td>Jumping into attacks without understanding the target</td><td>Spend initial time exploring and mapping each target before attempting exploitation</td></tr><tr><td>Report as afterthought</td><td>Treating documentation and writing as secondary to finding flags</td><td>Build report structure on day one; document continuously; reserve dedicated writing time</td></tr><tr><td>Testing while exhausted</td><td>Pushing through fatigue and missing obvious findings</td><td>Take regular breaks; maintain a normal sleep schedule; recognize when returns are diminishing</td></tr><tr><td>Not reading instructions</td><td>Missing submission requirements or rules</td><td>Read all instructions in full before activating the exam; re-read when uncertain</td></tr></tbody></table>

***

### Pre-Exam Checklist and Mindset

#### Readiness Checklists

**One week before:**

* [ ] All course modules and quizzes completed
* [ ] Practice labs completed
* [ ] Report template prepared
* [ ] Screenshot tool tested and confirmed working
* [ ] Testing tools and environment verified
* [ ] Schedule cleared for the full exam window

**Day before:**

* [ ] Exam environment access confirmed
* [ ] Workspace and tools ready
* [ ] First day schedule planned
* [ ] Adequate sleep prioritized

**At exam start:**

* [ ] Read all instructions completely before beginning
* [ ] Note any specific submission requirements
* [ ] Verify access to all targets and components
* [ ] Set up tracking and documentation structure
* [ ] Begin with systematic reconnaissance, not immediate exploitation

#### Mindset

Approach the exam as real client work. Systematic effort over the full seven days consistently outperforms frantic activity concentrated in a shorter window. When something is difficult, rotate approach rather than persisting with a technique that is not producing results.

#### After the Exam

Results are typically returned within 5-10 business days. If a retake is needed, identify the areas where progress stalled, strengthen them, and retake when ready. Feedback on individual attempts may or may not be provided.

***
