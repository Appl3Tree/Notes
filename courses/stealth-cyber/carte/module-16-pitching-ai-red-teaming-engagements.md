# Module 16: Pitching AI Red Teaming Engagements

### Understanding the AI Security Market

#### Buyer Segments

| Segment                         | Budget / Maturity                                                | Primary Motivators                                                          |
| ------------------------------- | ---------------------------------------------------------------- | --------------------------------------------------------------------------- |
| Enterprise technology companies | Highest budgets; often have internal security teams              | Product security, customer trust, competitive differentiation               |
| Financial services              | Large budgets; compliance-driven; risk-averse culture            | Regulatory compliance, fraud prevention, risk management                    |
| Healthcare organizations        | Moderate budgets; growing AI adoption; limited security maturity | Patient safety, HIPAA compliance, liability reduction                       |
| Retail and e-commerce           | Variable maturity; large user bases                              | Customer trust, fraud prevention, brand protection                          |
| Government and defense          | Long procurement cycles; clearance requirements may apply        | National security, compliance, public trust                                 |
| AI startups                     | Limited budgets; high motivation                                 | Enterprise sales readiness, investor due diligence, competitive positioning |

#### Buyer Personas

| Persona                       | Cares About                                                   | Fears                                           | Budget Authority                                        |
| ----------------------------- | ------------------------------------------------------------- | ----------------------------------------------- | ------------------------------------------------------- |
| CISO                          | Risk reduction, compliance, budget efficiency                 | Breaches on their watch, regulatory penalties   | Usually final authority on security spend               |
| CTO / VP Engineering          | Product security, development velocity, technical credibility | Security incidents affecting product reputation | Influences decisions; may control AI-specific budget    |
| Chief AI Officer / Head of AI | AI performance, responsible AI, competitive advantage         | AI failures, bias incidents, safety events      | Controls AI initiatives; may not own security budget    |
| Compliance / Risk Officer     | Regulatory compliance, audit readiness, documented controls   | Regulatory penalties, audit failures            | Can mandate assessments; influences security priorities |
| Procurement / Vendor Manager  | Cost, vendor qualifications, contract terms                   | Overpaying, vendor failures                     | Manages process; rarely final selection authority       |

Tailor pitch language to the persona: risk and compliance framing for CISOs and compliance officers; technical architecture framing for CTOs; governance and safety framing for AI leads.

#### Buying Triggers

| Trigger Type                    | Examples                                                                                                 | Sales Implication                                             |
| ------------------------------- | -------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| Reactive (high urgency)         | AI security incident; failed audit; competitor breach in the news; board or investor inquiry             | Budget and urgency exist; timelines are compressed            |
| Proactive (planning cycle)      | New AI system launching; annual assessment planning; regulatory deadline approaching; M\&A due diligence | Longer sales cycle; more deliberate decision-making           |
| Strategic (relationship-driven) | AI governance program development; security maturity initiative; enterprise AI platform deployment       | Entry through advisory relationships; longer horizon to close |

{% hint style="success" %}
Reactive buyers move fast but demand immediate availability. Proactive and strategic buyers reward ongoing presence and relationship investment. A healthy pipeline includes both.
{% endhint %}

***

### Finding and Qualifying Opportunities

#### Lead Generation

| Channel              | Tactics                                                                                                                                                                          |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Inbound marketing    | Blog posts, research publications, conference talks, open-source tool contributions, LinkedIn engagement, SEO targeting "AI red team" and "LLM security assessment"              |
| Outbound prospecting | Identify AI-deploying companies via press releases and job postings; personalized outreach referencing specific AI initiatives; lead with insight, not pitch                     |
| Partnerships         | Traditional penetration testing firms needing AI capabilities; AI consulting firms needing security expertise; governance, risk, and compliance (GRC) platforms; cloud providers |
| Referrals            | Past client recommendations; professional network introductions; industry association connections                                                                                |

#### Qualifying with BANT

| Dimension | Qualification Questions                                                                                   |
| --------- | --------------------------------------------------------------------------------------------------------- |
| Budget    | "What budget range are you working with?" / "Has this been approved, or are we building a business case?" |
| Authority | "Who else is involved in this decision?" / "What's your role in the evaluation process?"                  |
| Need      | "What's driving this initiative right now?" / "What happens if you don't address this?"                   |
| Timeline  | "When are you looking to have this completed?" / "What's driving that timeline?"                          |

Disqualify early if budget is absent, the contact has no influence over the decision, or the need is speculative with no timeline.

#### Discovery Questions

Use discovery to understand risk exposure and position yourself as a specialist, not a vendor.

**About their AI systems:**

* Which systems are they most concerned about? Are they customer-facing, internal, or both?
* What data do these systems have access to?
* Can the systems take actions, or are they purely informational?

**About current security posture:**

* How have they approached AI security testing so far?
* Does existing penetration testing include AI-specific techniques?
* What visibility do they have into AI system behavior?

**About their concerns:**

* What would a successful attack against their AI look like?
* What is the business impact if those systems were compromised?
* Are there specific attack scenarios they are worried about?

**About buying drivers:**

* What is prompting this now?
* Are regulatory or compliance requirements involved?
* Has leadership or the board been asking about AI security?

***

### Crafting the Pitch

#### Core Value Propositions

| Value                 | Framing                                                                                                                                                        |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Risk discovery        | Traditional security testing does not cover AI-specific attack surfaces; prompt injection, jailbreaking, and agent manipulation require specialized techniques |
| Expertise access      | AI security expertise is rare and expensive to build internally                                                                                                |
| Business protection   | Avoid regulatory penalties, customer harm, and reputational damage from AI security failures                                                                   |
| Compliance support    | Produce documentation and evidence for AI governance frameworks and regulatory audits                                                                          |
| Competitive advantage | Demonstrated AI security builds customer trust and differentiates from competitors who have had incidents                                                      |

#### Pitch Framework: Problem / Agitation / Solution

**Problem:** AI systems have fundamentally different attack surfaces than traditional software, and standard penetration testing does not cover them.

**Agitation:** AI security failures produce severe consequences: customer data exposure, regulatory penalties, reputational damage, and direct user harm. Attack sophistication is increasing while most organizations remain unprotected.

**Solution:** A systematic AI red team assessment identifies vulnerabilities before attackers do and delivers actionable remediation guidance with compliance documentation.

#### Persona-Tailored Pitches

**CISO:** Frame as a gap in existing security program coverage. AI-specific techniques (prompt injection, jailbreaking, agent exploitation) fall outside standard penetration testing scope. Emphasize OWASP and MITRE ATLAS framework mapping for risk reporting.

**CTO / VP Engineering:** Frame as understanding exactly how attackers could exploit the product: extracting customer data, bypassing safety controls, manipulating agent actions. Emphasize that findings are technical enough for engineers to act on and business-contextualized for stakeholder communication.

**Compliance / Risk Officer:** Frame as regulatory evidence production. The EU AI Act and emerging AI regulations require documented security measures. Emphasize systematic testing against recognized frameworks, detailed findings documentation, and remediation verification suitable for audit.

**Chief AI Officer / Head of AI:** Frame as adversarial robustness. Responsible AI includes security; a system that can be manipulated to harm users is not responsible regardless of fairness or performance metrics. Emphasize testing that confirms the system behaves as intended under adversarial conditions.

#### Elevator Pitch (30 seconds)

> "We specialize in finding security vulnerabilities in AI systems -- chatbots, copilots, agents. These systems have attack surfaces that traditional penetration testing simply doesn't reach. In past engagements we've uncovered critical issues where customer data could be extracted or the AI could be forced into producing harmful output. Every engagement ends with detailed findings and concrete remediation steps. A typical assessment runs \[timeframe] at \[price range]."

{% hint style="warning" %}
Fear-based selling erodes trust. Lead with expertise and demonstrated value. Prospects who connect the dots to risk themselves are more committed buyers than those who were scared into a purchase.
{% endhint %}

***

### Proposal Writing

#### Proposal Structure

| Section                          | Content                                                                                                                               |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| 1. Executive Summary             | Their situation and needs (demonstrates you listened); proposed solution at high level; key outcomes; investment and timeline summary |
| 2. Understanding of Requirements | Restate their goals, concerns, and success criteria in their own language; scope as discussed; constraints                            |
| 3. Proposed Approach             | Methodology overview; phases and activities; explicit inclusions and exclusions                                                       |
| 4. Deliverables                  | Report contents and format; whether a readout presentation is included; retesting provisions                                          |
| 5. Team and Qualifications       | Who performs the work; relevant credentials; similar engagement experience                                                            |
| 6. Timeline                      | Project phases with dates; dependencies and assumptions; delivery schedule                                                            |
| 7. Investment                    | Pricing; payment terms; what is and is not included; options if applicable                                                            |
| 8. Terms and Conditions          | Engagement terms; confidentiality; authorization requirements; liability and insurance                                                |
| 9. Next Steps                    | How to proceed; open questions; proposal expiration date                                                                              |

#### Writing Principles

**Show you listened.** Reference specific systems, concerns, and goals the prospect mentioned. Use their terminology, not yours.

**Write to outcomes, not activities.**

> Activity framing: "We will perform prompt injection testing." Outcome framing: "You will understand exactly how attackers could manipulate your customer service chatbot and have specific steps to prevent it."

**Reduce perceived risk.** Buyers hiring a specialist for the first time carry uncertainty about quality and reliability. Address this directly: reference comparable prior work, offer references, describe your methodology, and explain what happens if issues arise during the engagement.

**Make it easy to say yes.** Clear pricing with no hidden costs; simple next steps; reasonable terms; defined scope and deliverables with no ambiguity.

**Make it easy to compare.** If the prospect is evaluating multiple vendors, use consistent structure, state your differentiators explicitly, and make your value proposition unambiguous rather than burying it in methodology prose.

***

### Pricing Models and Strategy

#### Pricing Model Comparison

| Model              | Structure                                     | Pros                                                 | Cons                                                        | Best For                                                     |
| ------------------ | --------------------------------------------- | ---------------------------------------------------- | ----------------------------------------------------------- | ------------------------------------------------------------ |
| Fixed price        | Set fee for defined scope                     | Client has cost certainty; you can optimize delivery | Scope creep risk; may under- or overprice                   | Well-defined assessments with clear boundaries               |
| Time and materials | Hourly or daily rate times hours worked       | Flexible; fair when scope is unclear                 | Client cost uncertainty; less delivery efficiency incentive | Exploratory work, ongoing advisory, ambiguous scope          |
| Retainer           | Monthly fee for ongoing access                | Predictable revenue; deeper client relationships     | Scope management complexity; capacity planning required     | Continuous testing, advisory relationships, embedded support |
| Value-based        | Price tied to value delivered, not time spent | Captures more value; aligns incentives               | Harder to justify without quantified value                  | High-stakes assessments where business impact is clear       |

#### Market Rates (Approximate)

| Service                                      | Range              |
| -------------------------------------------- | ------------------ |
| Single AI system assessment                  | $8,000 - $25,000   |
| AI red team assessment (1-2 weeks)           | $15,000 - $50,000  |
| Comprehensive AI security review (3-4 weeks) | $40,000 - $100,000 |
| Day rate (AI security consultant)            | $2,000 - $4,500    |
| Monthly advisory retainer                    | $5,000 - $15,000   |

AI security specialization commands a 30-50% premium over traditional penetration testing rates. Compete on expertise and outcomes, not price; discounting signals low value.

#### Pricing Principles

* Price to the value delivered, not cost incurred. An assessment that prevents a $10M breach is reasonably priced at $30K regardless of time invested.
* Build negotiation margin in, but do not inflate artificially; sophisticated buyers will notice.
* Offer tiered options (Basic / Standard / Comprehensive) to anchor expectations and let clients self-select.

#### Option Structure Example

```
Option A: Focused Assessment - $18,000
- Single AI system (customer chatbot)
- Prompt injection, jailbreaking, system prompt extraction
- 5-day testing window
- Written report with findings and remediation

Option B: Comprehensive Assessment - $32,000 [Recommended]
- All customer-facing AI systems (3 systems)
- Full OWASP LLM Top 10 coverage
- 10-day testing window
- Written report + executive presentation
- One retest cycle included

Option C: Enterprise Program - $55,000
- All AI systems (customer-facing + internal)
- Full OWASP LLM Top 10 + MITRE ATLAS coverage
- 15-day testing window
- Full report suite + board presentation
- Two retest cycles + 30-day support
```

{% hint style="success" %}
Label the middle option as recommended. This anchors expectations upward and makes the mid-tier feel like the rational choice. Most clients self-select to the middle option.
{% endhint %}

***

### Handling Objections

#### Common Objections and Responses

**"You're too expensive."**

First, diagnose: are they anchored to traditional penetration testing rates, working within a real budget constraint, or testing your pricing flexibility?

* "What are you comparing us to?" (surfaces their anchor)
* "Our rate reflects AI-specific expertise most security firms don't carry. What would an AI security incident cost your organization?"
* "We can adjust scope to fit budget constraints -- which systems are highest priority?"

**"We can do this internally."**

Diagnose: do they actually have the expertise, or is this a budget objection in disguise?

* "Does your current team have hands-on experience with prompt injection, jailbreaking, and RAG exploitation?"
* "Many organizations use external assessors to validate internal work or cover techniques their team doesn't specialize in."
* "We can work alongside your team to transfer knowledge and build internal capability."

**"We haven't had any AI security problems."**

Diagnose: false confidence, absence of detection capability, or low internal priority?

* "That's what most organizations say before their first incident. Would you rather find vulnerabilities now or learn about them from attackers?"
* "Many AI vulnerabilities don't surface in standard monitoring. Have you tested specifically for prompt injection or jailbreaking?"
* "No detected incidents often means no detection capability, not no vulnerabilities."

**"Our AI isn't mature enough yet."**

Diagnose: legitimate timing concern, avoiding spend, or unclear roadmap?

* "Security is easier to build in than retrofit after launch. Finding issues now is cheaper than redesigning post-deployment."
* "We can scope to your current state -- even a lightweight assessment catches major issues before they become architectural problems."
* "When do you expect to be ready? Let's schedule a follow-up conversation."

**"We need to think about it."**

Diagnose: insufficient urgency, need for internal alignment, or a competing proposal?

* "Of course. What information would help your decision?"
* "Is there someone else who should be part of this conversation?"
* "What would need to be true for you to move forward?"
* "To deliver before \[their deadline] we'd need to start by \[date] -- does that work?"

**"Can you provide references?"** -- This is a buying signal, not an objection. Connect them with a reference from a comparable engagement and ask what specific questions they want addressed.

#### Negotiation Principles

| Principle                        | Application                                                                                                        |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Don't negotiate against yourself | When price is challenged, ask what they want to remove from scope; don't drop price unilaterally                   |
| Trade, don't give                | If reducing price, get something in return: faster payment terms, case study rights, a referral commitment         |
| Know your walk-away              | Set a minimum acceptable price before negotiating; be willing to decline unprofitable work                         |
| Create genuine urgency           | "To hold these dates we need commitment by \[date]" / "Pricing is valid for 30 days; rates are reviewed quarterly" |

***

### Closing and Delivery

#### Recognizing and Acting on Buying Signals

Buying signals: asking about timeline and availability; discussing internal approval process; requesting references or credentials; negotiating terms; asking about next steps.

When signals appear, ask directly rather than waiting:

* "Are you ready to move forward?"
* "What do you need to make a decision?"
* "Should I send the agreement for signature?"

Reduce friction at signing: use electronic signature tools, keep terms clear and simple, offer easy payment options, and respond to questions quickly.

#### Contract to Kickoff

**Immediately after signing:** confirm receipt; introduce the delivery team; schedule a kickoff call; send any pre-work requirements.

**Kickoff call agenda:** introductions; scope and objectives confirmation; technical requirements and access; communication protocols; timeline confirmation; open questions.

#### Delivery as Business Development

Client satisfaction is the highest-leverage business development activity. Happy clients become repeat customers, referral sources, case study subjects, and references for future prospects.

| Phase             | Actions                                                                                                                                                     |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| During engagement | Communicate proactively; escalate significant findings early; meet deadlines; respond quickly to questions                                                  |
| At delivery       | Present findings professionally; provide actionable recommendations; answer questions thoroughly; discuss next steps                                        |
| After delivery    | Follow up on remediation progress; offer to validate fixes; request feedback; ask for referrals when appropriate; maintain contact for future opportunities |

***

### Building Long-Term Success

#### Account Expansion

Single engagements are expensive to sell relative to expanded relationships. Common expansion paths:

* Single AI system assessment → all AI systems → enterprise-wide program
* Assessment → remediation support → ongoing monitoring
* Project engagement → annual or quarterly recurring assessment as systems evolve
* Advisory retainer: reviewing new AI initiatives, advising on security architecture, supporting vendor assessments, training internal teams

#### Pipeline Management

Track opportunities across five stages: leads (unqualified); qualified opportunities (BANT confirmed); proposals submitted; negotiations in progress; closed won or lost.

Key metrics to maintain:

| Metric                               | Purpose                                 |
| ------------------------------------ | --------------------------------------- |
| Lead → qualified conversion rate     | Measures targeting and outreach quality |
| Qualified → proposal conversion rate | Measures discovery and fit assessment   |
| Proposal → close conversion rate     | Measures proposal quality and pricing   |
| Average deal size                    | Inputs revenue forecasting              |
| Average sales cycle length           | Inputs capacity and cash flow planning  |

Work backward from revenue targets to required pipeline volume at each stage. If close rate is 30% and average deal is $25K, closing $500K requires roughly $1.67M in submitted proposals.

Maintain business development activity even during full delivery periods: weekly content publishing, monthly networking, quarterly conference presence, ongoing relationship contact.

***
