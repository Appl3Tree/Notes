# Module 14: Ethics and Responsible Disclosure

### Legal Frameworks for AI Security Testing

#### Computer Crime Laws by Jurisdiction

| Jurisdiction   | Law                                                   | Key Provisions                                                                                                                        | AI Testing Notes                                                                                                                                                                                                                                                 |
| -------------- | ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| United States  | Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030 | § 1030(a)(2): unauthorized access to obtain information; § 1030(a)(5): knowingly causing damage to a protected computer               | Valid API credentials = authorized access; extracting proprietary system prompts may exceed authorization; AI-specific applications not yet extensively litigated; _Van Buren_ (2021) narrowed "exceeding authorized access" but scope discipline still required |
| European Union | Computer Crime Directive 2013/40/EU                   | Illegal access (Art. 3), system interference (Art. 4), data interference (Art. 5), interception (Art. 6)                              | Member states implement with local variation; always verify local law                                                                                                                                                                                            |
| United Kingdom | Computer Misuse Act 1990                              | S.1: unauthorized access; S.2: unauthorized access with intent to commit further offenses; S.3: unauthorized acts to impair operation | No explicit safe harbor for security research; authorization documentation is the primary defense                                                                                                                                                                |
| Australia      | Criminal Code Act 1995                                | Div. 477.1: unauthorized access, modification, or impairment; Div. 478.1: unauthorized access to restricted data                      | Authorization and scope documentation are essential defenses                                                                                                                                                                                                     |

**CFAA safe harbor checklist:**

```
□ Written authorization from system owner
□ Scope explicitly defines permitted testing activities
□ Testing stays within defined scope
□ Any scope expansion is documented and re-authorized
□ No damage to systems or data
□ Copy of authorization retained
```

#### Data Protection: GDPR

GDPR applies when data subjects are located in the EU or when the data controller is an EU entity. Personal data encountered during AI testing remains regulated regardless of testing context.

| Requirement                       | Application to AI Red Teaming                                                                                                              |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Lawful basis (Art. 6(1)(f))       | Security testing typically relies on legitimate interests; requires a legitimate interests assessment before testing                       |
| Data minimization                 | Extract only what is necessary to demonstrate a vulnerability; do not retain excess data                                                   |
| Security measures                 | Implement appropriate controls for any personal data captured during testing                                                               |
| Breach notification (Arts. 33-34) | If testing reveals a breach, the client organization may have notification obligations; agree on protocol before testing                   |
| Data subject rights               | Extracting personal data from an AI system raises unresolved questions about whose responsibility it is to fulfill subject access requests |

```
Before Testing:
□ Document lawful basis (complete legitimate interests assessment)
□ Define data minimization approach
□ Establish secure data handling procedures
□ Agree with client on breach notification procedures

During Testing:
□ Minimize personal data capture
□ Anonymize or pseudonymize where possible
□ Secure all captured data
□ Log all data processing activities

After Testing:
□ Delete personal data per agreed retention schedule
□ Confirm deletion with client
□ Retain only anonymized evidence
```

#### Sector-Specific Regulations

| Sector                   | Regulation                    | Trigger Condition                                      | Key Requirement                                           |
| ------------------------ | ----------------------------- | ------------------------------------------------------ | --------------------------------------------------------- |
| Healthcare (US)          | HIPAA Security Rule           | AI system processes Protected Health Information (PHI) | Business Associate Agreement required with covered entity |
| Financial services (US)  | Gramm-Leach-Bliley Act (GLBA) | AI system handles consumer financial data              | Security safeguards program compliance                    |
| Payment cards            | PCI DSS                       | AI system touches cardholder data                      | Full PCI DSS compliance for data handling                 |
| Children's products (US) | COPPA                         | AI system interacts with users under 13                | Heightened caution; additional consent requirements       |

#### AI-Specific Regulatory Frameworks

| Framework                                                                                                      | Status               | Relevance to Red Teaming                                                                                                                                                 |
| -------------------------------------------------------------------------------------------------------------- | -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| EU AI Act (effective 2024-2026)                                                                                | Binding (EU)         | High-risk AI systems must implement risk management including cybersecurity; testing may surface prohibited practices or transparency violations that require disclosure |
| [NIST AI Risk Management Framework](https://www.nist.gov/system/files/documents/2023/01/26/AI%20RMF%201.0.pdf) | Non-binding guidance | Red teaming directly supports the Measure and Manage functions; increasingly referenced in contracts and procurement requirements                                        |

{% hint style="info" %}
This is general orientation, not legal advice. For any significant engagement, consult an attorney with experience in computer security law, data protection, and AI regulation across the relevant jurisdictions.
{% endhint %}

***

### Ethical Frameworks for AI Security

Three major ethical traditions apply to AI red team decision-making. When frameworks converge on the same answer, confidence is higher. When they conflict, the divergence itself is diagnostic.

#### Frameworks Compared

| Framework        | Judges Actions By             | Core Questions                                                                                                                                  | Strengths                                                              | Limitations                                                                                    |
| ---------------- | ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| Consequentialism | Outcomes produced             | What are all possible outcomes, who is affected, what is the probability and magnitude of each, which action produces the best expected result? | Focuses on real-world impact; flexible to context                      | Hard to predict all consequences; can justify harmful means; may underweight individual rights |
| Deontology       | Adherence to duties and rules | What duties apply here? Am I treating everyone with respect? Could I universalize this action? Am I being honest and keeping commitments?       | Clear rules; protects individual rights regardless of outcome          | Can produce poor outcomes in edge cases; rules may conflict                                    |
| Virtue ethics    | Character of the actor        | What would a person of integrity do? Would I be proud of this? Does this action build or erode the character I want to have?                    | Focuses on judgment, not just rule-following; handles novel situations | Less action-guiding in ambiguous cases                                                         |

#### Biomedical Ethics Adapted for AI Security

Four principles from biomedical ethics transfer directly to AI red teaming, where testing can affect users, data subjects, and third parties with no direct role in the engagement.

| Principle       | Meaning in Practice                                                                                                                                                                  |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Beneficence     | Testing should produce benefit: for the client (risk identification), for users (safer systems), and for the field broadly                                                           |
| Non-maleficence | The testing process itself must not create new risks; do not damage systems, expose users, or produce artifacts that could enable attackers                                          |
| Autonomy        | Respect informed decision-making by clients; protect the interests of users whose data or interactions you encounter; treat people as ends, not means                                |
| Justice         | Distribute testing burdens and benefits fairly; do not exploit vulnerable populations; AI systems used in healthcare, criminal justice, or child welfare warrant heightened scrutiny |

#### CARTE Decision Framework

Use when facing an ethically ambiguous situation during an engagement:

1. **IDENTIFY the ethical issue** — What decision is being made? What makes it ethically significant? Which values are in tension?
2. **STAKEHOLDERS analysis** — Who is affected? What does each party stand to gain or lose? Who is least able to protect themselves?
3. **OPTIONS enumeration** — What courses of action are available? Are there alternatives that avoid the core tradeoff? What constraints apply?
4. **ANALYSIS using multiple frameworks** — Consequentialist: which option produces the best expected outcome? Deontological: what duties or rules apply? Virtue: what would a person of integrity do? Note whether the frameworks converge or diverge.
5. **DECISION and justification** — What is the chosen course of action? What is the reasoning? How would this be explained to those affected?
6. **REVIEW and learn** — What actually happened? Would the same decision be made again? What does this case teach for future situations?

{% hint style="info" %}
When frameworks suggest different actions, identify which is most relevant to the specific situation, look for options that satisfy multiple frameworks simultaneously, and document your reasoning so it can be reviewed and defended.
{% endhint %}

***

### Responsible Disclosure: Principles and Process

Responsible disclosure maximizes the chance a vulnerability gets fixed while minimizing exploitation risk. AI systems add complexity: base model vulnerabilities affect every application built on that model; some issues cannot be fixed without full retraining; many AI vendors lack mature security response processes; and probabilistic vulnerabilities are harder to communicate clearly.

#### Disclosure Timelines

The 90-day standard was established by [Google Project Zero](https://googleprojectzero.blogspot.com/) and is now the de facto industry baseline.

| AI Vulnerability Type                | Typical Fix Time                  | Recommended Timeline                         |
| ------------------------------------ | --------------------------------- | -------------------------------------------- |
| System prompt / configuration issues | Days to weeks                     | Standard 90 days                             |
| Application-layer filters            | Weeks                             | Standard 90 days                             |
| Base model jailbreaks                | Months (requires retraining)      | 120-180 days                                 |
| Training data exposure               | Months to years; may be unfixable | Coordinate carefully; focus on mitigations   |
| Architectural flaws                  | Indefinite                        | Coordinate on mitigations; no fixed timeline |

Timeline modifiers: +14 days if a fix is imminent; +30 days for extraordinary complexity; compress to hours/days if active exploitation is confirmed.

#### Disclosure Process

1. **Document the vulnerability** -- Record a technical description, reproduction steps (including success rate for probabilistic issues), affected systems and versions, potential attack scenarios, any evidence of active exploitation, and suggested mitigations.
2. **Identify the right contact** -- Use this priority order: `security@vendor.com` or `security.txt`; bug bounty program if one exists; product security team; general security team; engineering leadership; coordinating body ([CERT/CC](https://www.kb.cert.org/vuls/report/) or AI-ISAC). Never use public channels, sales contacts, or general support.
3. **Send the initial report** -- Include: a subject line naming the system and vulnerability type; a summary paragraph; severity assessment with justification; affected systems; reproduction overview (detailed steps as an attachment); impact description; a responsible disclosure statement with your intended timeline; a request for acknowledgment; and your contact information.
4. **Coordinate with the vendor** -- Confirm they understood the report, answer technical questions, agree on a communication cadence, discuss the disclosure timeline, and offer to review proposed fixes.
5. **Track progress** -- Log all communications with dates. This record is your protection if the process breaks down.
6. **Public disclosure** -- Coordinate timing with the vendor where possible. Credit responsive handling. Provide enough detail to help defenders without enabling exploitation. Include remediation or mitigation guidance. Link to the vendor's own advisory if one exists.

#### When Vendors Are Unresponsive

| Stage                      | Days  | Actions                                                                                                                                 |
| -------------------------- | ----- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Persistence                | 1-14  | Resend report; try alternative contacts; document all attempts                                                                          |
| Escalation                 | 14-30 | Contact company leadership; engage CERT/CC; consider legal counsel                                                                      |
| Public interest evaluation | 30-90 | Assess public interest; consider partial disclosure (existence without exploitation detail); consult other researchers or legal counsel |
| Disclosure                 | 90+   | Disclose with or without vendor cooperation; prioritize user protection; provide mitigation guidance; document all vendor non-response  |

#### Active Exploitation: Compressed Timeline

If a vulnerability is being exploited in the wild:

1. Notify the vendor within hours.
2. Demand acknowledgment within 24-48 hours.
3. Request an emergency fix or mitigation within days.
4. Consider early public disclosure if the vendor is unresponsive, exploitation is widespread, or users can take protective action themselves.
5. Engage CERT/CC for issues affecting multiple parties.
6. Document everything for potential legal protection.

#### Additional Channels

Bug bounty platforms ([HackerOne](https://www.hackerone.com/), [Bugcrowd](https://www.bugcrowd.com/)) provide established process, legal safe harbor, financial rewards, and direct vendor communication. For vulnerabilities affecting multiple vendors or where direct contact fails, CERT/CC provides neutral coordination and has pre-existing vendor relationships.

For base model vulnerabilities, report to the model provider directly; a single flaw may affect thousands of downstream applications. For research intended for publication, complete the disclosure process before submitting to venues.

{% hint style="info" %}
Engaging with vendor security teams before finding vulnerabilities -- through conferences, bug bounty programs, and community participation -- makes the disclosure process faster and more cooperative when it matters.
{% endhint %}

***

### Professional Conduct Standards

#### Core Standards

| Standard        | Requirements                                                                                                                                                                                                        |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Integrity       | Report findings accurately; do not exaggerate severity or suppress unflattering results; acknowledge uncertainty; give credit appropriately                                                                         |
| Competence      | Only accept work within your qualifications; acknowledge limits; seek assistance in unfamiliar territory; do not misrepresent credentials                                                                           |
| Confidentiality | Honor NDAs; secure client data and findings; do not discuss engagements without permission; sanitize examples used for training or marketing; confidentiality persists after engagement ends                        |
| Authorization   | Obtain explicit written authorization before testing; stay within defined scope; document any scope changes; stop immediately if authorization is revoked; do not test adjacent systems without separate permission |
| Proportionality | Use the minimum necessary technique; prefer staging environments; avoid irreversible actions; confirm vulnerability existence without full exploitation where safe; consider impact on real users                   |
| Transparency    | Document methodology; explain what was and was not tested; disclose conflicts of interest; be honest about what testing can and cannot achieve                                                                      |

#### Conflict of Interest Management

Common conflict categories: financial (stock holdings, payment by an interested party); professional (prior employment, competitive relationships); personal (relationships with stakeholders, strong prior opinions about the client or industry).

1. **Identify** potential conflicts before the engagement begins.
2. **Disclose** any conflicts to relevant parties.
3. **Assess** whether objective work is still possible.
4. **Recuse** if the conflict is too significant to manage.
5. **Document** how each conflict was identified and handled.
6. **Maintain** independence throughout the engagement.

#### Relationship Boundaries

| Relationship | Standards                                                                                                        |
| ------------ | ---------------------------------------------------------------------------------------------------------------- |
| Clients      | Maintain professional distance; decline inappropriate gifts or benefits; document all significant communications |
| Colleagues   | Share credit appropriately; do not disparage competitors; maintain confidentiality about others' work            |
| Public       | Educate without enabling attackers; represent the profession accurately; be deliberate in public statements      |

#### Professional Development

Relevant certifications: OSCP/OSCE for penetration testing foundations; GIAC certifications for specialized domains; cloud certifications for cloud-hosted AI systems.

Community involvement: [AI Village](https://aivillage.org/) and DEF CON working groups for AI security; [ISSA](https://www.issa.org/) and [ISACA](https://www.isaca.org/) for general security practice; local security meetups; CTF participation; conference attendance.

***

### Navigating Ethical Dilemmas

#### Dilemma Scenarios and Resolutions

**Patient Safety vs. Confidentiality**

**Situation:** Authorized testing of a healthcare AI reveals a vulnerability requiring model retraining (6-month fix window). Client requests confidentiality during remediation while patients remain at risk.

| Stakeholder | Interest                                          |
| ----------- | ------------------------------------------------- |
| Patients    | Safety; informed decision-making about their care |
| Client      | Reputation, legal exposure, time to fix           |
| Tester      | Contractual confidentiality obligations           |

**Principles in tension:** Non-maleficence (patient safety) vs. confidentiality (contractual obligation) vs. autonomy (patients deserve to make informed care decisions).

**Resolution:** Push the client for accelerated interim mitigations that reduce risk during the fix window. If the client is unresponsive to patient safety concerns, escalate to the relevant regulator, who has both the authority and the responsibility to act. Public disclosure is a last resort when other channels have failed and harm is imminent.

***

**Unfixable Vulnerability vs. Public Transparency**

**Situation:** A jailbreak technique working at 40% success rate against all major large language models (LLMs) is discovered. The issue is architectural; no patch exists short of a fundamental alignment breakthrough. Publishing enables attackers; not publishing leaves users unaware.

**Principles in tension:** Transparency (users deserve to understand risks) vs. non-maleficence (publication may accelerate harmful use) vs. beneficence (research advances defensive capability).

**Resolution:** Coordinate with major model vendors on available mitigations before publication. Publish the vulnerability class and defensive guidance without including ready-to-use exploit scripts. Determined attackers can likely rediscover the technique independently, making responsible disclosure preferable to suppression.

***

**Findings Integrity Under Client Pressure**

**Situation:** A client facing acquisition pressures the tester to downgrade critical findings to medium or remove them entirely from the report, threatening to withhold payment.

| Stakeholder  | Interest                                  |
| ------------ | ----------------------------------------- |
| Client       | Favorable report for acquisition          |
| Acquirer     | Accurate risk information before purchase |
| Future users | Safe product                              |
| Tester       | Payment; professional reputation          |

**Resolution:** Refuse to alter findings for non-technical reasons. Adding context, noting mitigating factors, or documenting planned remediation is acceptable; changing severity ratings under financial pressure is not. If the client withholds payment, pursue it through appropriate channels. Never deliver a dishonest report.

***

**Accidental Discovery Without Authorization**

**Situation:** A serious vulnerability is found during normal personal use of a public AI service. No testing was intended; no authorization exists.

**Resolution:** If the vendor has a bug bounty or responsible disclosure program, report through it; these programs typically provide explicit legal safe harbor. If no program exists, consider anonymous disclosure or coordination through [CERT/CC](https://www.kb.cert.org/vuls/report/). Document everything to establish good faith. Consult legal counsel before acting if the vulnerability is serious and legal exposure is a concern.

***

**Dual-Use Research Publication**

**Situation:** A novel AI attack technique developed during legitimate research is useful for defenders but equally usable for harassment or fraud.

**Resolution:** Apply graduated disclosure: publish enough for defenders to understand and protect against the technique without including copy-paste exploit scripts. Coordinate with major vendors before any public release. Include concrete defensive recommendations alongside the research. Accept that determined attackers can likely develop the technique independently.

***

#### Deciding Under Uncertainty

When outcomes are unclear:

* Gather available information before committing to a course of action.
* Weight potential outcomes by probability rather than treating all scenarios as equally likely.
* Prefer reversible decisions where possible.
* Apply a precautionary standard when stakes are high and harm is hard to undo.
* Consult trusted colleagues, mentors, or legal counsel before acting unilaterally.

***

### Special Ethical Considerations for AI Systems

#### Training Data Extraction

Probing for memorization or extracting training data engages with underlying data collection practices: consent may have been absent, personal information may be present, and biases or copyrighted material may have been included.

| Guideline                              | Application                                                                                                                          |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| Minimize extraction                    | Extract only what is needed to demonstrate the vulnerability exists                                                                  |
| Handle as sensitive                    | Treat any extracted training data as confidential regardless of apparent content                                                     |
| Report the capability, not the content | Focus reporting on the risk and technique, not on reproducing the extracted data                                                     |
| Flag downstream obligations            | Extracted data containing personally identifiable information (PII) may trigger notification obligations for the client organization |

#### Bias and Discriminatory Behavior

Security testing may surface biased or discriminatory AI behavior even when fairness is not formally in scope.

* Include fairness testing in scope when the system operates in high-stakes domains (hiring, lending, healthcare, criminal justice).
* Report observed bias even when it falls outside the agreed scope; document it separately from security findings.
* Do not test for bias using interactions that could harm real users.
* Recognize that deep fairness auditing is a specialized discipline; recommend a dedicated audit when findings warrant it.

#### AI Agent Testing

Agents can execute real-world actions, which means manipulation during testing can produce real-world consequences.

* Test agents in sandboxed or staging environments whenever possible.
* Establish explicit boundaries before testing begins: identify what actions the agent can take and which are off-limits to trigger.
* If testing causes an unintended effect, work to reverse it immediately.
* Document agent behavior during testing carefully; real consequences require an accountability record.

#### User Interaction During Testing

Testing may expose real user conversations or inadvertently affect live user sessions.

* Avoid affecting real users; use synthetic sessions or isolated test accounts wherever possible.
* Treat any user conversations encountered as confidential.
* Apply heightened care when the system operates in sensitive contexts: mental health support, crisis intervention, child welfare.
* Do not deceive real users into believing they are in a legitimate interaction during testing.

#### Novel Capabilities Without Established Precedent

AI capabilities are advancing faster than ethical and legal frameworks can address. Situations without clear guidance will arise.

Apply the core principles from earlier sections (beneficence, non-maleficence, autonomy, justice) when no specific rule exists. Contribute findings and reasoning to professional discourse to help the field develop norms. Remain open to updating prior judgments as understanding improves.

***

### Building an Ethical Practice

#### Individual Practices

* **Ethics decision log:** Record each significant ethical decision with date, situation, decision made, reasoning, and outcome. Creates accountability and surfaces patterns over time.
* **Consultation network:** Maintain relationships with experienced mentors, peers facing similar challenges, and legal counsel for complex situations. Ethics decisions should rarely be made in isolation.
* **Continuing education:** Read ethics literature relevant to security research; engage with case studies at conferences; reflect on past decisions.

#### Organizational Structures

For teams and practice leads:

| Area           | Implementation                                                                                                |
| -------------- | ------------------------------------------------------------------------------------------------------------- |
| Policies       | Written code of conduct; conflict of interest policy; disclosure procedures; escalation paths                 |
| Review         | Pre-engagement ethics review of scope; post-engagement reflection; peer review for difficult decisions        |
| Training       | Ethics training for all team members; regular case study discussions; updates as norms evolve                 |
| Accountability | Clear ownership of ethical decisions; safe channels for raising concerns; defined consequences for violations |

#### Responsibilities by Seniority

| Level                | Ethical Responsibilities                                                                                                  |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| Junior practitioners | Learn frameworks; follow established guidelines; seek guidance for ambiguous situations; build consistent habits          |
| Senior practitioners | Model ethical behavior; mentor others; navigate ambiguity without escalating every decision; influence team culture       |
| Leaders              | Set standards; build structures that make ethical behavior the default; accept responsibility for organizational outcomes |

#### Community Contribution

The norms of AI security are still forming. Individual behavior shapes them.

* Model ethical reasoning publicly, not just ethical outcomes.
* Call out unethical behavior when observed; support colleagues facing pressure.
* Participate in standards development and framework discussions.
* Decline work that violates ethical principles; accept the short-term cost to protect long-term integrity.

***
